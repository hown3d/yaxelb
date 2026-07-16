//go:build linux

package bpf

import (
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"

	"yaxelb/internal/bpf/testutil"
	"yaxelb/internal/config"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

var (
	backends = map[netip.Addr]net.HardwareAddr{
		netip.MustParseAddr("10.0.4.10"): must(testutil.GenerateRandMAC),
		netip.MustParseAddr("10.0.4.11"): must(testutil.GenerateRandMAC),
	}
	clientIP = netip.MustParseAddr("10.0.4.42")
	lbIP     = netip.MustParseAddr("10.0.4.2")
	lbMac    = must(testutil.GenerateRandMAC)
	lbLink   = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "lb",
			HardwareAddr: lbMac,
		},
		PeerName: "lb-peer",
	}
	kernelTraceReader *testutil.KernelTracer
)

func TestMain(m *testing.M) {
	os.Exit(runTest(m))
}

func runTest(m *testing.M) int {
	var err error
	kernelTraceReader, err = testutil.KernelTraceReader()
	if err != nil {
		log.Printf("creating kernel trace reader: %s", err)
		return -1
	}
	defer func() {
		kernelTraceReader.Close()
	}()

	if err := setupTestLink(lbLink, lbIP); err != nil {
		log.Printf("setup test link: %v", err)
		return -1
	}
	defer func() {
		netlink.LinkDel(lbLink)
	}()

	// add a source route to LB index to ensure our src mac is from lb device
	if err := netlink.RouteAdd(&netlink.Route{
		Src:       net.IP(lbIP.AsSlice()),
		LinkIndex: lbLink.Index,
	}); err != nil {
		log.Printf("adding source route: %s", err)
		return -1
	}
	return m.Run()
}

func TestLoadbalancer_Client(t *testing.T) {
	conf := config.Config{
		Algorithm: config.AlgorithmHash,
		Listeners: config.Listeners{
			{
				Protocol: config.TCP,
				Port:     80,
			},
		},
	}

	for ip := range backends {
		conf.Listeners[0].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
	}

	// Without this entry fib_lookup returns BPF_FIB_LKUP_RET_NO_NEIGH because they kernel does not know about the mac of the backends yet.
	// Create this entry in the neighbor table directly to mock ARP resolution.
	for ip, mac := range backends {
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    lbLink.Index,
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
				ip:   lbIP,
				mac:  lbMac,
				port: 80,
			},
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				eth := retPacket.LinkLayer().(*layers.Ethernet)
				ipv4 := retPacket.NetworkLayer().(*layers.IPv4)
				assert.Equal(t, lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIP.String(), ipv4.SrcIP.String(), "src IP is not LB")

				mac, ok := backends[netip.MustParseAddr(ipv4.DstIP.String())]
				assert.True(t, ok, "dst IP is a backend")
				assert.Equal(t, mac, eth.DstMAC)
			},
		},
		{
			name:        "client to loadbalancer on port not listening",
			expectedRet: XDP_DROP,
			srcInfo: packetInfo{
				ip:   clientIP,
				port: 32112,
			},
			dstInfo: packetInfo{
				ip:   lbIP,
				mac:  lbMac,
				port: 12345,
			},
		},
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			inPacket, err := ipv4Packet(tt.srcInfo, tt.dstInfo)
			if err != nil {
				t.Fatalf("building ipv4 packet: %s", err)
			}

			t.Cleanup(func() {
				traces, err := io.ReadAll(kernelTraceReader)
				if err != nil {
					t.Logf("WARNING: failed to read kernel traces: %s", err)
				} else {
					t.Logf("ebpf program traces:\n%s", traces)
				}
				if err := kernelTraceReader.Clear(); err != nil {
					t.Logf("WARNING: unable to clear kernel traces: %s", err)
				}
			})

			var (
				retPacket gopacket.Packet
				ret       uint32
			)
			// CAP_SYS_ADMIN is required for using xdp_ct_lookup kfunc as it is from a kernel module.
			testutil.WithCapabilities(t, []testutil.Capability{testutil.CAP_SYS_ADMIN}, func() {
				m, err := New(&conf, lbIP)
				if err != nil {
					t.Fatalf("setup ebpf manager: %s", err)
				}
				t.Cleanup(func() {
					m.Close()
				})

				ret, retPacket, err = testEbpf(m.objs.LoadBalance, inPacket.packet.Data(), uint32(lbLink.Attrs().Index))
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

func TestLoadbalancer_BackendReturn(t *testing.T) {
	conf := config.Config{
		Algorithm: config.AlgorithmHash,
		Listeners: config.Listeners{
			{
				Protocol: config.TCP,
				Port:     80,
			},
		},
	}

	for ip := range backends {
		conf.Listeners[0].Backends = append(conf.Listeners[0].Backends, config.Backend{
			Addr: netip.AddrPortFrom(ip, 80),
		})
	}

	var (
		backendIP              = slices.Collect(maps.Keys(backends))[0]
		backendPort     uint16 = 8080
		originalSrcPort uint16 = 32123
	)

	var scenarios = []struct {
		name                 string
		srcInfo              packetInfo
		dstInfo              packetInfo
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
				ip:   lbIP,
				mac:  lbMac,
				port: originalSrcPort,
			},
			additionalSetup: func(t *testing.T, m *Manager) {
				// setup a conntrack entry in our map to simulate the loadbalancer already forwarded the packet
				conntrackEntry := lbConntrackEntry{
					SrcIp:   lbInAddrFromNetipAddr(clientIP),
					DstIp:   lbInAddrFromNetipAddr(lbIP),
					SrcPort: originalSrcPort,
					DstPort: 80,
				}
				fiveTuple := lbFiveTupleT{
					SrcIp:    lbInAddrFromNetipAddr(backendIP),
					DstIp:    lbInAddrFromNetipAddr(lbIP),
					SrcPort:  8080,
					DstPort:  originalSrcPort,
					Protocol: conf.Listeners[0].Protocol.Unix(),
				}
				assert.NoError(t, m.objs.Conntrack.Put(fiveTuple, conntrackEntry), "conntrack entry ebpf map")
			},
			additionalAssertions: func(t *testing.T, retPacket gopacket.Packet) {
				_ = retPacket.LinkLayer().(*layers.Ethernet)
				ipv4 := retPacket.NetworkLayer().(*layers.IPv4)
				tcp := retPacket.TransportLayer().(*layers.TCP)
				// TODO: assert client MAC once we have a neigh for that
				// assert.Equal(t, lbMac, eth.SrcMAC, "src MAC is not from LB link")
				assert.Equal(t, lbIP.String(), ipv4.SrcIP.String(), "src IP is not LB")
				assert.Equal(t, clientIP.String(), ipv4.DstIP.String(), "dst IP is not client")
				assert.EqualValues(t, 80, tcp.SrcPort)
				assert.EqualValues(t, originalSrcPort, tcp.DstPort)

			},
		},
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			inPacket, err := ipv4Packet(tt.srcInfo, tt.dstInfo)
			if err != nil {
				t.Fatalf("building ipv4 packet: %s", err)
			}

			t.Cleanup(func() {
				traces, err := io.ReadAll(kernelTraceReader)
				if err != nil {
					t.Logf("WARNING: failed to read kernel traces: %s", err)
				} else {
					t.Logf("ebpf program traces:\n%s", traces)
				}
				if err := kernelTraceReader.Clear(); err != nil {
					t.Logf("WARNING: unable to clear kernel traces: %s", err)
				}
			})

			var (
				retPacket gopacket.Packet
				ret       uint32
			)
			// CAP_SYS_ADMIN is required for using xdp_ct_lookup kfunc as it is from a kernel module.
			testutil.WithCapabilities(t, []testutil.Capability{testutil.CAP_SYS_ADMIN}, func() {
				m, err := New(&conf, lbIP)
				if err != nil {
					t.Fatalf("setup ebpf manager: %s", err)
				}
				t.Cleanup(func() {
					m.Close()
				})

				if tt.additionalSetup != nil {
					tt.additionalSetup(t, m)
				}

				ret, retPacket, err = testEbpf(m.objs.LoadBalance, inPacket.packet.Data(), uint32(lbLink.Attrs().Index))
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

type packetInfo struct {
	mac  net.HardwareAddr
	ip   netip.Addr
	port uint16
}

type packet struct {
	packet gopacket.Packet
}

func assertChecksum(t *testing.T, packet gopacket.Packet) {
	err, mismatchs := packet.VerifyChecksums()
	assert.NoError(t, err, "checksum verification")
	if !assert.Len(t, mismatchs, 0, "checksum mismatchs") {
		for _, m := range mismatchs {
			t.Logf("checksum verification failed on layer %s, correct csum is %04x, got %04x", m.Layer.LayerType(), m.Correct, m.Actual)
		}
	}

}

func ipv4Packet(src, dst packetInfo) (packet, error) {
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
		SrcIP:    src.ip.AsSlice(),
		DstIP:    dst.ip.AsSlice(),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		// Don't fragment
		FragOffset: syscall.IP_DF,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.port),
		DstPort: layers.TCPPort(dst.port),
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		return packet{}, err
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, tcp); err != nil {
		return packet{}, err
	}
	return packet{
		packet: testutil.DecodePacket(buf.Bytes()),
	}, nil

}

func testEbpf(prog *ebpf.Program, in []byte, ifindex uint32) (uint32, gopacket.Packet, error) {
	out := make([]byte, len(in))
	xdpMd := testutil.XdpMd{
		IngressIfindex: ifindex,
		Data:           0,
		DataEnd:        uint32(len(out)),
	}

	opts := &ebpf.RunOptions{
		Data:    in,
		DataOut: out,
		Context: xdpMd,
	}

	ret, err := prog.Run(opts)
	if err != nil {
		return 0, nil, err
	}
	packet := testutil.DecodePacket(opts.DataOut)
	return ret, packet, nil
}

func setupTestLink(l netlink.Link, ip netip.Addr) error {
	if err := netlink.LinkAdd(l); err != nil {
		return fmt.Errorf("adding link: %w", err)
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	if err := netlink.AddrAdd(l, &netlink.Addr{
		IPNet: &net.IPNet{
			IP: net.IP(ip.AsSlice()), Mask: net.CIDRMask(32, 32),
		},
	}); err != nil {
		return fmt.Errorf("adding address to link: %w", err)
	}
	return nil
}

func must[T any](f func() (T, error)) T {
	obj, err := f()
	if err != nil {
		panic(err)
	}
	return obj
}
