//go:build linux

package bpf

import (
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"syscall"
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
	backendsV4 = map[netip.Addr]net.HardwareAddr{
		netip.MustParseAddr("10.0.4.10"): must(testutil.GenerateRandMAC),
		netip.MustParseAddr("10.0.4.11"): must(testutil.GenerateRandMAC),
	}
	clientIPv4 = netip.MustParseAddr("10.0.4.42")
	lbIPv4     = netip.MustParseAddr("10.0.4.2")
)

func TestIPv4(t *testing.T) {
	suite.Run(t, new(ipv4Suite))
}

type ipv4Suite struct {
	suite.Suite
	kernelTraceReader *testutil.KernelTracer
	lbMac             net.HardwareAddr
	lbLink            netlink.Link
}

func (s *ipv4Suite) SetupSuite() {
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
			Name:         "lb-v4",
			HardwareAddr: s.lbMac,
		},
		PeerName: "lb-v4-peer",
	}

	if err := setupTestLink(s.lbLink, lbIPv4); err != nil {
		t.Errorf("setup test link: %v", err)
		return
	}
	t.Cleanup(func() {
		netlink.LinkDel(s.lbLink)
	})

	// add a source route to LB index to ensure our src mac is from lb device
	if err := netlink.RouteAdd(&netlink.Route{
		Src:       net.IP(lbIPv4.AsSlice()),
		LinkIndex: s.lbLink.Attrs().Index,
	}); err != nil {
		t.Errorf("adding source route: %s", err)
		return
	}
}

func (s *ipv4Suite) TestLoadbalancer_Client() {
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

	for ip := range backendsV4 {
		conf.Listeners[0].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
		conf.Listeners[1].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
	}

	// Without this entry fib_lookup returns BPF_FIB_LKUP_RET_NO_NEIGH because they kernel does not know about the mac of the backends yet.
	// Create this entry in the neighbor table directly to mock ARP resolution.
	for ip, mac := range backendsV4 {
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    s.lbLink.Attrs().Index,
			IP:           net.IP(ip.AsSlice()),
			HardwareAddr: mac,
			State:        unix.NUD_REACHABLE,
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
				ip:   netip.MustParseAddr("10.0.4.42"),
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv4,
				mac:  s.lbMac,
				port: tcpPort,
			},
			proto: config.TCP,
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				eth := retPacket.LinkLayer().(*layers.Ethernet)
				ipv4 := retPacket.NetworkLayer().(*layers.IPv4)
				assert.Equal(t, s.lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIPv4.String(), ipv4.SrcIP.String(), "src IP is not LB")

				mac, ok := backendsV4[netip.MustParseAddr(ipv4.DstIP.String())]
				assert.True(t, ok, "dst IP is a backend")
				assert.Equal(t, mac, eth.DstMAC)
			},
		},
		{
			name:        "client to loadbalancer udp",
			expectedRet: XDP_REDIRECT,
			srcInfo: packetInfo{
				ip:   clientIPv4,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv4,
				mac:  s.lbMac,
				port: udpPort,
			},
			proto: config.UDP,
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				eth := retPacket.LinkLayer().(*layers.Ethernet)
				ipv4 := retPacket.NetworkLayer().(*layers.IPv4)
				assert.Equal(t, s.lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIPv4.String(), ipv4.SrcIP.String(), "src IP is not LB")

				mac, ok := backendsV4[netip.MustParseAddr(ipv4.DstIP.String())]
				assert.True(t, ok, "dst IP is a backend")
				assert.Equal(t, mac, eth.DstMAC)
			},
		},
		{
			name:        "client to loadbalancer on port not listening",
			expectedRet: XDP_DROP,
			srcInfo: packetInfo{
				ip:   clientIPv4,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIPv4,
				mac:  s.lbMac,
				port: 12345,
			},
			proto: config.TCP,
		},
	}
	for _, tt := range scenarios {
		s.Run(tt.name, func() {
			t := s.T()
			inPacket, err := ipv4Packet(tt.srcInfo, tt.dstInfo, tt.proto)
			if err != nil {
				t.Fatalf("building ipv4 packet: %s", err)
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
				m, err := New(&conf, lbIPv4)
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

			assert.Equal(t, tt.expectedRet, ret, "xdp return code")
			assertChecksum(t, retPacket)
			if tt.additionalAssertions != nil {
				tt.additionalAssertions(t, retPacket)
			}
		})
	}
}

func (s *ipv4Suite) TestLoadbalancer_BackendReturn() {
	conf := config.Config{
		Algorithm: config.AlgorithmHash,
		Listeners: config.Listeners{
			{
				Protocol: config.TCP,
				Port:     80,
			},
		},
	}

	for ip := range backendsV4 {
		conf.Listeners[0].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
	}

	var (
		backendIP              = slices.Collect(maps.Keys(backendsV4))[0]
		backendPort     uint16 = 8080
		originalSrcPort uint16 = 32123
	)

	var scenarios = []struct {
		name                 string
		srcInfo              packetInfo
		dstInfo              packetInfo
		proto                config.Protocol
		expectedRet          uint32
		additionalSetup      func(t *testing.T, m *Manager)
		additionalAssertions func(t *testing.T, retPacket gopacket.Packet)
	}{
		{
			name:        "backend response to loadbalancer with ct present",
			expectedRet: XDP_PASS,
			srcInfo: packetInfo{
				ip:   backendIP,
				port: backendPort,
			},
			dstInfo: packetInfo{
				ip:   lbIPv4,
				mac:  s.lbMac,
				port: originalSrcPort,
			},
			proto: config.TCP,
			additionalSetup: func(t *testing.T, m *Manager) {
				// setup a conntrack entry in our map to simulate the loadbalancer already forwarded the packet
				conntrackEntry := lbConntrackEntry{
					SrcIp:   lbInAddrFromNetipAddr(clientIPv4),
					DstIp:   lbInAddrFromNetipAddr(lbIPv4),
					SrcPort: originalSrcPort,
					DstPort: 80,
				}
				fiveTuple := lbFiveTupleT{
					SrcIp:    lbInAddrFromNetipAddr(backendIP),
					DstIp:    lbInAddrFromNetipAddr(lbIPv4),
					SrcPort:  8080,
					DstPort:  originalSrcPort,
					Protocol: conf.Listeners[0].Protocol.Unix(),
				}
				assert.NoError(t, m.objs.Conntrack.Put(fiveTuple, conntrackEntry), "conntrack entry ebpf map")
			},
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				_ = retPacket.LinkLayer().(*layers.Ethernet)
				ipv4 := retPacket.NetworkLayer().(*layers.IPv4)
				// TODO: assert client MAC once we have a neigh for that
				// assert.Equal(t, lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIPv4.String(), ipv4.SrcIP.String(), "src IP is not LB")
				assert.Equal(t, clientIPv4.String(), ipv4.DstIP.String(), "dst IP is not client")
				tcp := retPacket.TransportLayer().(*layers.TCP)
				assert.EqualValues(t, 80, tcp.SrcPort)
				assert.EqualValues(t, originalSrcPort, tcp.DstPort)

			},
		},
	}
	for _, tt := range scenarios {
		s.Run(tt.name, func() {
			t := s.T()
			inPacket, err := ipv4Packet(tt.srcInfo, tt.dstInfo, tt.proto)
			if err != nil {
				t.Fatalf("building ipv4 packet: %s", err)
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
				m, err := New(&conf, lbIPv4)
				if err != nil {
					t.Fatalf("setup ebpf manager: %s", err)
				}
				t.Cleanup(func() {
					m.Close()
				})

				if tt.additionalSetup != nil {
					tt.additionalSetup(t, m)
				}

				ret, retPacket, err = testEbpf(m.objs.LoadBalance, inPacket.packet.Data(), uint32(s.lbLink.Attrs().Index))
				if err != nil {
					t.Fatalf("testing ebpf program: %s", err)
				}
			})

			assert.Equal(t, tt.expectedRet, ret, "xdp return code")
			assertChecksum(t, retPacket)
			if tt.additionalAssertions != nil {
				tt.additionalAssertions(t, retPacket)
			}
		})
	}

}

func ipv4Packet(src, dst packetInfo, proto config.Protocol) (packet, error) {
	if src.mac == nil {
		mac, _ := testutil.GenerateRandMAC()
		src.mac = mac
	}
	eth := &layers.Ethernet{
		SrcMAC:       src.mac,
		DstMAC:       dst.mac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP:   src.ip.AsSlice(),
		DstIP:   dst.ip.AsSlice(),
		Version: 4,
		// Don't fragment
		FragOffset: syscall.IP_DF,
		Protocol:   layers.IPProtocol(proto.Unix()),
	}

	l4, err := transportLayer(ipv4, src, dst, proto)
	if err != nil {
		return packet{}, fmt.Errorf("building l4 layer: %w", err)
	}

	return buildPacket(eth, ipv4, l4)
}
