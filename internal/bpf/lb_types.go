package bpf

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"yaxelb/internal/config"
	"yaxelb/pkg/byteorder"
)

type LBFiveTuple struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol config.Protocol
}

func lbFiveTupleFromBpf(l lbFiveTupleT) LBFiveTuple {
	return LBFiveTuple{
		SrcIP:    l.SrcIp.toNetipAddr(),
		DstIP:    l.DstIp.toNetipAddr(),
		SrcPort:  l.SrcPort,
		DstPort:  l.DstPort,
		Protocol: (new(config.Protocol)).FromUnix(l.Protocol),
	}
}

type LBConntrackEntry struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
}

func lbConntrackEntryFromBpf(l lbConntrackEntry) LBConntrackEntry {
	return LBConntrackEntry{
		SrcIP:   l.SrcIp.toNetipAddr(),
		DstIP:   l.DstIp.toNetipAddr(),
		SrcPort: l.SrcPort,
		DstPort: l.DstPort,
	}
}

var (
	_ encoding.BinaryUnmarshaler = (*lbInAddr)(nil)
	_ encoding.BinaryMarshaler   = lbInAddr{}
)

var NetworkOrder = binary.BigEndian

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (l *lbInAddr) UnmarshalBinary(data []byte) error {
	var v4 [4]byte
	copy(v4[:], data[:])
	ip := netip.AddrFrom4(v4)
	l.S_addr = saddrFromNetipAddr(ip)
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l lbInAddr) MarshalBinary() (data []byte, err error) {
	// s_addr is already in network order
	b := *(*[4]byte)(unsafe.Pointer(&l.S_addr))
	return b[:], nil
}

func (l lbInAddr) toNetipAddr() netip.Addr {
	// s_addr is already in network order
	buf := *(*[4]byte)(unsafe.Pointer(&l.S_addr))
	return netip.AddrFrom4(buf)
}

func (l lbInAddr) String() string {
	raw, _ := l.MarshalBinary()
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "NA"
	}
	return ip.String()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (l *lbListenerEntry) UnmarshalBinary(data []byte) error {
	ip := new(lbInAddr)
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	l.Ip = *ip
	l.Port = NetworkOrder.Uint16(data[4:6])
	l.Protocol = data[6]
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l lbListenerEntry) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	ipRaw, err := l.Ip.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[0] = ipRaw[0]
	data[1] = ipRaw[1]
	data[2] = ipRaw[2]
	data[3] = ipRaw[3]
	NetworkOrder.PutUint16(data[4:6], l.Port)
	data[6] = l.Protocol
	return data, nil
}

func (l lbListenerEntry) FromConfig(lis config.Listener, addr netip.Addr) lbListenerEntry {
	l = lbListenerEntry{
		Port:     lis.Port,
		Ip:       lbInAddrFromNetipAddr(addr),
		Protocol: lis.Protocol.Unix(),
	}
	return l
}

func (l lbConntrackEntry) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 12)
	srcIPRaw, err := l.SrcIp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[0] = srcIPRaw[0]
	data[1] = srcIPRaw[1]
	data[2] = srcIPRaw[2]
	data[3] = srcIPRaw[3]

	dstIPRaw, err := l.DstIp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[4] = dstIPRaw[0]
	data[5] = dstIPRaw[1]
	data[6] = dstIPRaw[2]
	data[7] = dstIPRaw[3]
	NetworkOrder.PutUint16(data[8:10], l.SrcPort)
	NetworkOrder.PutUint16(data[10:12], l.DstPort)
	return data, nil
}

func (l *lbConntrackEntry) UnmarshalBinary(data []byte) (err error) {
	if err := l.SrcIp.UnmarshalBinary(data[0:4]); err != nil {
		return err
	}
	if err := l.DstIp.UnmarshalBinary(data[4:8]); err != nil {
		return err
	}
	l.SrcPort = NetworkOrder.Uint16(data[8:10])
	l.DstPort = NetworkOrder.Uint16(data[10:12])
	return nil
}

func (l lbFiveTupleT) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	srcIPRaw, err := l.SrcIp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[0] = srcIPRaw[0]
	data[1] = srcIPRaw[1]
	data[2] = srcIPRaw[2]
	data[3] = srcIPRaw[3]

	dstIPRaw, err := l.DstIp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[4] = dstIPRaw[0]
	data[5] = dstIPRaw[1]
	data[6] = dstIPRaw[2]
	data[7] = dstIPRaw[3]
	NetworkOrder.PutUint16(data[8:10], l.SrcPort)
	NetworkOrder.PutUint16(data[10:12], l.DstPort)
	data[12] = l.Protocol
	return data, nil
}

func (l *lbFiveTupleT) UnmarshalBinary(data []byte) (err error) {
	if err := l.SrcIp.UnmarshalBinary(data[0:4]); err != nil {
		return err
	}
	if err := l.DstIp.UnmarshalBinary(data[4:8]); err != nil {
		return err
	}
	l.SrcPort = NetworkOrder.Uint16(data[8:10])
	l.DstPort = NetworkOrder.Uint16(data[10:12])
	l.Protocol = data[12]
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l lbBackend) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	ipRaw, err := l.Ip.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ip: %w", err)
	}
	data[0] = ipRaw[0]
	data[1] = ipRaw[1]
	data[2] = ipRaw[2]
	data[3] = ipRaw[3]
	NetworkOrder.PutUint16(data[4:6], l.Port)
	return data, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l *lbBackend) UnmarshalBinary(data []byte) (err error) {
	ip := new(lbInAddr)
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	l.Ip = *ip
	l.Port = byteorder.NetworkToHost16(NetworkOrder.Uint16(data[4:6]))
	return nil
}

func (l lbBackend) String() string {
	return fmt.Sprintf("%s:%d", l.Ip, byteorder.NetworkToHost16(l.Port))
}

func (l lbLbAlgorithm) FromConfig(algo config.Algorithm) lbLbAlgorithm {
	switch algo {
	case config.AlgorithmRandom:
		l = lbLbAlgorithmRANDOM
	case config.AlgorithmHash:
		l = lbLbAlgorithmHASH
	default:
		l = lbLbAlgorithmRANDOM
	}
	return l
}

func lbInAddrFromNetipAddr(a netip.Addr) lbInAddr {
	return lbInAddr{
		S_addr: saddrFromNetipAddr(a),
	}
}

func saddrFromNetipAddr(a netip.Addr) uint32 {
	b := a.As4()
	// we already know that netip.Addr stores in networkOrder
	return *(*uint32)(unsafe.Pointer(&b))
}
