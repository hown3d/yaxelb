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

func (l lbListenerEntry) FromConfig(lis config.Listener) lbListenerEntry {
	l = lbListenerEntry{
		Port:     lis.Addr.Port(),
		Ip:       lbInAddrFromNetipAddr(lis.Addr.Addr()),
		Protocol: lis.Protocol.Unix(),
	}
	return l
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
