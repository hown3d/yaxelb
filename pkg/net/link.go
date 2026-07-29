package net

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
)

func AddressOfInterface(iface netlink.Link) (netip.Addr, error) {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		// fallback to ipv6
		addrs, err = netlink.AddrList(iface, netlink.FAMILY_V6)
		if err != nil {
			return netip.Addr{}, err
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("link %s has no IPs", iface.Attrs().Name)
	}
	addr := addrs[0]
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return ip, fmt.Errorf("can't parse IP %s", addr.IP)
	}
	return ip, nil
}
