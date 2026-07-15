package testutil

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func DecodePacket(b []byte) gopacket.Packet {
	return gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
}
