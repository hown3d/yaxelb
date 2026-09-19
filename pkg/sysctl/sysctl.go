package sysctl

import (
	"fmt"

	"github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
)

func EnableForwarding(link netlink.Link, ipv6 bool) error {
	var (
		linkName string
		family   string
	)

	if link != nil {
		linkName = link.Attrs().Name
	} else {
		linkName = "all"
	}
	if ipv6 {
		family = "ipv6"
	} else {
		family = "ipv4"
	}
	key := fmt.Sprintf("net.%s.conf.%s.forwarding", family, linkName)
	return sysctl.Set(key, "1")
}
