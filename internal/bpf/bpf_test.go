//go:build linux

package bpf

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"yaxelb/internal/bpf/testutil"
	"yaxelb/internal/config"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

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

type checksummableLayer interface {
	gopacket.SerializableLayer
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func transportLayer(networkLayer gopacket.NetworkLayer, src, dst packetInfo, proto config.Protocol) (gopacket.SerializableLayer, error) {
	var l4 checksummableLayer
	switch proto {
	case config.TCP:
		l4 = &layers.TCP{
			SrcPort: layers.TCPPort(src.port),
			DstPort: layers.TCPPort(dst.port),
		}
	case config.UDP:
		l4 = &layers.UDP{
			SrcPort: layers.UDPPort(src.port),
			DstPort: layers.UDPPort(dst.port),
		}
	default:
		return nil, fmt.Errorf("unknown proto %s", proto)
	}
	if err := l4.SetNetworkLayerForChecksum(networkLayer); err != nil {
		return nil, err
	}
	return l4, nil
}

func buildPacket(layers ...gopacket.SerializableLayer) (packet, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
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

	var mask net.IPMask
	if ip.Is4() {
		mask = net.CIDRMask(32, 32)
	}
	if ip.Is6() {
		mask = net.CIDRMask(96, 128)
	}
	if err := netlink.AddrAdd(l, &netlink.Addr{
		IPNet: &net.IPNet{
			IP: net.IP(ip.AsSlice()), Mask: mask,
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
