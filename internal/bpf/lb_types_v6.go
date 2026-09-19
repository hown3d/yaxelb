package bpf

import (
	"fmt"
	"net/netip"
	"unsafe"

	"yaxelb/internal/config"
	"yaxelb/pkg/byteorder"
)

func lbV6FiveTupleFromBpf(l lbV6FiveTupleT) LBFiveTuple {
	return LBFiveTuple{
		SrcIP:    netip.AddrFrom16(l.SrcIp.Addr),
		DstIP:    netip.AddrFrom16(l.DstIp.Addr),
		SrcPort:  l.SrcPort,
		DstPort:  l.DstPort,
		Protocol: (new(config.Protocol)).FromUnix(l.Protocol),
	}
}

func lbV6ConntrackEntryFromBpf(l lbV6ConntrackEntry) LBConntrackEntry {
	return LBConntrackEntry{
		SrcIP:   netip.AddrFrom16(l.SrcIp.Addr),
		DstIP:   netip.AddrFrom16(l.DstIp.Addr),
		SrcPort: l.SrcPort,
		DstPort: l.DstPort,
	}
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (l *lbV6ListenerEntry) UnmarshalBinary(data []byte) error {
	var ip6 [16]byte
	copy(ip6[:], data[0:16])
	l.Ip.Addr = ip6
	l.Port = NetworkOrder.Uint16(data[16:18])
	l.Protocol = data[18]
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l lbV6ListenerEntry) MarshalBinary() (data []byte, err error) {
	data = make([]byte, unsafe.Sizeof(l))
	copy(data[0:16], l.Ip.Addr[:])
	NetworkOrder.PutUint16(data[16:18], l.Port)
	data[18] = l.Protocol
	return data, nil
}

func (l lbV6ListenerEntry) FromConfig(lis config.Listener, addr netip.Addr) lbV6ListenerEntry {
	l = lbV6ListenerEntry{
		Port:     lis.Port,
		Protocol: lis.Protocol.Unix(),
	}
	l.Ip.Addr = addr.As16()
	return l
}

func (l *lbV6ConntrackEntry) UnmarshalBinary(data []byte) (err error) {
	copy(l.SrcIp.Addr[:], data[0:16])
	copy(l.DstIp.Addr[:], data[16:32])
	l.SrcPort = NetworkOrder.Uint16(data[32:34])
	l.DstPort = NetworkOrder.Uint16(data[34:36])
	return nil
}

func (l *lbV6FiveTupleT) UnmarshalBinary(data []byte) (err error) {
	copy(l.SrcIp.Addr[:], data[0:16])
	copy(l.DstIp.Addr[:], data[16:32])
	l.SrcPort = NetworkOrder.Uint16(data[32:34])
	l.DstPort = NetworkOrder.Uint16(data[34:36])
	l.Protocol = data[36]
	return nil
}

func (l lbV6Backend) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 20)
	copy(data[0:16], l.Ip.Addr[:])
	NetworkOrder.PutUint16(data[16:18], l.Port)
	return data, nil
}

func (l *lbV6Backend) UnmarshalBinary(data []byte) (err error) {
	var ip6 [16]byte
	copy(ip6[:], data[0:16])
	l.Ip.Addr = ip6
	l.Port = byteorder.NetworkToHost16(NetworkOrder.Uint16(data[16:18]))
	return nil
}

func (l lbV6Backend) String() string {
	return fmt.Sprintf("%s:%d", netip.AddrFrom16(l.Ip.Addr), byteorder.NetworkToHost16(l.Port))
}

func (l lbV6Backend) IsEmpty() bool {
	return netip.AddrFrom16(l.Ip.Addr) == netip.IPv6Unspecified()
}
