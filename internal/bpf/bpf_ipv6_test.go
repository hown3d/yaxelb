//go:build linux

package bpf

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"yaxelb/internal/bpf/testutil"
	"yaxelb/internal/config"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	backendsV6 = map[netip.Addr]net.HardwareAddr{
		netip.MustParseAddr("fd00:db81:1::10"): must(testutil.GenerateRandMAC),
		netip.MustParseAddr("fd00:db81:1::11"): must(testutil.GenerateRandMAC),
	}
	clientIPv6 = netip.MustParseAddr("fd00:db81:1::42")
	lbIPv6     = netip.MustParseAddr("fd00:db81:1::2")
)

func TestIPv6(t *testing.T) {
	suite.Run(t, new(ipv6Suite))
}

type ipv6Suite struct {
	suite.Suite
	kernelTraceReader *testutil.KernelTracer
	lbMac             net.HardwareAddr
	lbLink            netlink.Link
}

func (s *ipv6Suite) SetupSuite() {
	t := s.T()
	var err error
	s.kernelTraceReader, err = testutil.KernelTraceReader()
	if err != nil {
		t.Errorf("creating kernel trace reader: %s", err)
		return
	}
	t.Cleanup(func() {
		s.kernelTraceReader.Close()
	})
	s.lbMac = must(testutil.GenerateRandMAC)
	s.lbLink = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "lb-v6",
			HardwareAddr: s.lbMac,
		},
		PeerName: "lb-v6-peer",
	}

	if err := setupTestLink(s.lbLink, lbIPv6); err != nil {
		t.Fatalf("setup test link: %v", err)
		return
	}
	t.Cleanup(func() {
		netlink.LinkDel(s.lbLink)
	})

}

func (s *ipv6Suite) TestLoadbalancer_Client() {
	t := s.T()
	var (
		udpPort uint16 = 8080
		tcpPort uint16 = 80
	)
	conf := config.Config{
		Algorithm: config.AlgorithmHash,
		Listeners: config.Listeners{
			{
				Protocol: config.TCP,
				Port:     tcpPort,
			},
			{
				Protocol: config.UDP,
				Port:     udpPort,
			},
		},
	}

	for ip := range backendsV6 {
		conf.Listeners[0].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
		conf.Listeners[1].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
	}

	// Without this entry fib_lookup returns BPF_FIB_LKUP_RET_NO_NEIGH because they kernel does not know about the mac of the backends yet.
	// Create this entry in the neighbor table directly to mock ARP resolution.
	for ip, mac := range backendsV6 {
		t.Logf("adding neighbor %s=>%s on link %d", ip, mac, s.lbLink.Attrs().Index)
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    s.lbLink.Attrs().Index,
			IP:           net.IP(ip.AsSlice()),
			HardwareAddr: mac,
			State:        unix.NUD_REACHABLE,
			Family:       netlink.FAMILY_V6,
		}); err != nil {
			t.Errorf("adding neighbor %s=>%s: %v", ip, mac, err)
			return
		}
	}

	var scenarios = []struct {
		name                 string
		srcInfo              packetInfo
		dstInfo              packetInfo
		proto                config.Protocol
		expectedRet          uint32
		additionalAssertions func(t *testing.T, retPacket gopacket.Packet)
	}{
		{
			name:        "client to loadbalancer on listener port",
			expectedRet: XDP_REDIRECT,
			srcInfo: packetInfo{
				ip:   clientIPv6,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv6,
				mac:  s.lbMac,
				port: tcpPort,
			},
			proto: config.TCP,
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				eth := retPacket.LinkLayer().(*layers.Ethernet)
				ipv6 := retPacket.NetworkLayer().(*layers.IPv6)
				assert.Equal(t, s.lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIPv6.String(), ipv6.SrcIP.String(), "src IP is not LB")

				mac, ok := backendsV6[netip.MustParseAddr(ipv6.DstIP.String())]
				assert.True(t, ok, "dst IP is a backend")
				assert.Equal(t, mac, eth.DstMAC)
			},
		},
		{
			name:        "client to loadbalancer udp",
			expectedRet: XDP_REDIRECT,
			srcInfo: packetInfo{
				ip:   clientIPv6,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv6,
				mac:  s.lbMac,
				port: udpPort,
			},
			proto: config.UDP,
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				eth := retPacket.LinkLayer().(*layers.Ethernet)
				ipv6 := retPacket.NetworkLayer().(*layers.IPv6)
				assert.Equal(t, s.lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIPv6.String(), ipv6.SrcIP.String(), "src IP is not LB")

				mac, ok := backendsV6[netip.MustParseAddr(ipv6.DstIP.String())]
				assert.True(t, ok, "dst IP is a backend")
				assert.Equal(t, mac, eth.DstMAC)
			},
		},
		{
			name:        "client to loadbalancer on port not listening",
			expectedRet: XDP_DROP,
			srcInfo: packetInfo{
				ip:   clientIPv6,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv6,
				mac:  s.lbMac,
				port: 12345,
			},
			proto: config.TCP,
		},
	}
	for _, tt := range scenarios {
		s.Run(tt.name, func() {
			t := s.T()
			inPacket, err := ipv6Packet(tt.srcInfo, tt.dstInfo, tt.proto)
			if err != nil {
				t.Fatalf("building packet: %s", err)
			}

			t.Cleanup(func() {
				traces, err := io.ReadAll(s.kernelTraceReader)
				if err != nil {
					t.Logf("WARNING: failed to read kernel traces: %s", err)
				} else {
					t.Logf("ebpf program traces:\n%s", traces)
				}
				if err := s.kernelTraceReader.Clear(); err != nil {
					t.Logf("WARNING: unable to clear kernel traces: %s", err)
				}
			})

			var (
				retPacket gopacket.Packet
				ret       uint32
			)
			// CAP_SYS_ADMIN is required for using xdp_ct_lookup kfunc as it is from a kernel module.
			testutil.WithCapabilities(t, []testutil.Capability{testutil.CAP_SYS_ADMIN}, func() {
				m, err := New(&conf, lbIPv6)
				if err != nil {
					t.Fatalf("setup ebpf manager: %s", err)
				}
				t.Cleanup(func() {
					m.Close()
				})

				ret, retPacket, err = testEbpf(m.objs.LoadBalance, inPacket.packet.Data(), uint32(s.lbLink.Attrs().Index))
				if err != nil {
					t.Fatalf("testing ebpf program: %s", err)
				}
			})

			if assert.Equal(t, tt.expectedRet, ret, "xdp return code") {
				assertChecksum(t, retPacket)
				if tt.additionalAssertions != nil {
					tt.additionalAssertions(t, retPacket)
				}
			}
		})
	}
}

func ipv6Packet(src, dst packetInfo, proto config.Protocol) (packet, error) {
	if src.mac == nil {
		mac, _ := testutil.GenerateRandMAC()
		src.mac = mac
	}
	eth := &layers.Ethernet{
		SrcMAC:       src.mac,
		DstMAC:       dst.mac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		SrcIP:      src.ip.AsSlice(),
		DstIP:      dst.ip.AsSlice(),
		Version:    6,
		NextHeader: layers.IPProtocol(proto.Unix()),
	}

	l4, err := transportLayer(ipv6, src, dst, proto)
	if err != nil {
		return packet{}, fmt.Errorf("building l4 layer: %w", err)
	}

	return buildPacket(eth, ipv6, l4)
}
