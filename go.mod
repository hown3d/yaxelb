module yaxelb

go 1.26.1

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.21.0
	github.com/goccy/go-yaml v1.19.2
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.37.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
