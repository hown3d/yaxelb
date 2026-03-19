package bpf

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"net/netip"

	"yaxelb/internal/config"
)

var (
	_ encoding.BinaryUnmarshaler = (*lbInAddr)(nil)
	_ encoding.BinaryMarshaler   = lbInAddr{}
)

var NetworkOrder = binary.BigEndian

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (l *lbInAddr) UnmarshalBinary(data []byte) error {
	_, err := binary.Decode(data, NetworkOrder, &l.S_addr)
	return err
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (l lbInAddr) MarshalBinary() (data []byte, err error) {
	data = NetworkOrder.AppendUint32(data, l.S_addr)
	return
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (l *lbListenerEntry) UnmarshalBinary(data []byte) error {
	ip := new(lbInAddr)
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	l.Ip = *ip
	l.Port = NetworkOrder.Uint16(data[3:5])
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
func (l lbBackend) UnmarshalBinary(data []byte) (err error) {
	ip := new(lbInAddr)
	if err := ip.UnmarshalBinary(data); err != nil {
		return err
	}
	l.Ip = *ip
	l.Port = NetworkOrder.Uint16(data[3:5])
	return nil
}

func lbInAddrFromNetipAddr(a netip.Addr) lbInAddr {
	b := a.As4()

	return lbInAddr{
		S_addr: uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24,
	}
}

func (l lbListenerEntry) FromConfig(lis config.Listener) lbListenerEntry {
	l = lbListenerEntry{
		Port:     lis.Addr.Port(),
		Ip:       lbInAddrFromNetipAddr(lis.Addr.Addr()),
		Protocol: lis.Protocol.Unix(),
	}
	return l
}
