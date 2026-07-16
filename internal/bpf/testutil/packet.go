package testutil

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type networkLayerChecksummer interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func DecodePacket(b []byte) gopacket.Packet {
	p := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	checksummer, ok := p.TransportLayer().(networkLayerChecksummer)
	if ok {
		if err := checksummer.SetNetworkLayerForChecksum(p.NetworkLayer()); err != nil {
			panic(err)
		}
	}
	return p
}
