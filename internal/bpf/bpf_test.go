//go:build linux

package bpf

import (
	"fmt"
	"io"
	"net"
	"net/netip"
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

func TestManager_Loadbalance(t *testing.T) {
	kernelTraceReader, err := testutil.KernelTraceReader()
	if err != nil {
		t.Fatalf("creating kernel trace reader: %s", err)
	}

	backend1IP := netip.MustParseAddr("10.0.4.10")
	backend1Mac := must(t, testutil.GenerateRandMAC)
	backend2IP := netip.MustParseAddr("10.0.4.11")
	backend2Mac := must(t, testutil.GenerateRandMAC)

	backends := map[netip.Addr]net.HardwareAddr{
		backend1IP: backend1Mac,
		backend2IP: backend2Mac,
	}

	lbIP := netip.MustParseAddr("10.0.4.2")
	lbMac := must(t, testutil.GenerateRandMAC)
	lbLink := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "lb",
			HardwareAddr: lbMac,
		},
		PeerName: "lb-peer",
	}
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
			Addr: netip.AddrPortFrom(ip, 8080),
		})
	}

	srcInfo := packetInfo{
		ip:   netip.MustParseAddr("10.0.4.42"),
		port: 32112,
	}
	dstInfo := packetInfo{
		ip:   lbIP,
		mac:  lbMac,
		port: 80,
	}

	in, err := ipv4Packet(srcInfo, dstInfo)
	if err != nil {
		t.Fatalf("building ipv4 packet: %s", err)
	}

	if err := setupTestLink(lbLink, lbIP); err != nil {
		t.Errorf("setup test link: %v", err)
		return
	}

	// add a source route to LB index to ensure our src mac is from lb device
	if err := netlink.RouteAdd(&netlink.Route{
		Src:       net.IP(lbIP.AsSlice()),
		LinkIndex: lbLink.Index,
	}); err != nil {
		t.Errorf("adding source route: %s", err)
		return
	}

	// TODO: at the moment fib_lookup returns BPF_FIB_LKUP_RET_NO_NEIGH because they kernel does not know about the Mac of expectedNewDst yet.
	// Create this entry in the neighbor table directly using netlink.NeighAdd.
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
		kernelTraceReader.Close()
		netlink.LinkDel(lbLink)
	})

	var (
		packet gopacket.Packet
		ret    uint32
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

		ret, packet, err = testEbpf(m.objs.LoadBalance, in, uint32(lbLink.Attrs().Index))
		if err != nil {
			t.Fatalf("testing ebpf program: %s", err)
		}
	})

	assert.Equal(t, XDP_REDIRECT, ret, "xdp return code")
	eth := packet.LinkLayer().(*layers.Ethernet)
	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	assert.Equal(t, lbMac, eth.SrcMAC, "src MAC is not from LB link")
	assert.Equal(t, lbIP.String(), ipv4.SrcIP.String(), "src IP is not LB")

	mac, ok := backends[netip.MustParseAddr(ipv4.DstIP.String())]
	assert.True(t, ok, "dst IP is a backend")
	assert.Equal(t, mac, eth.DstMAC)
}

type packetInfo struct {
	mac  net.HardwareAddr
	ip   netip.Addr
	port uint16
}

func ipv4Packet(src, dst packetInfo) ([]byte, error) {
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
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

func must[T any](t *testing.T, f func() (T, error)) T {
	obj, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return obj
}
