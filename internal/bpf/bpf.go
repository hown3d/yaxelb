package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"yaxelb/internal/config"
	"yaxelb/internal/healthcheck"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const pinPath = "/sys/fs/bpf/yaxelb"

type Manager struct {
	log             *slog.Logger
	backendUpdaters []BackendHealthProber
	objs            *lbObjects
	xdpLink         link.Link
}

func New(conf *config.Config, addr netip.Addr) (*Manager, error) {
	objs, spec, err := LoadObjects()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		objs: objs,
		log:  slog.Default().WithGroup("bpf"),
	}

	var lbAlgo lbLbAlgorithm
	if err := objs.LbAlgo.Set(lbAlgo.FromConfig(conf.Algorithm)); err != nil {
		m.Close()
		return nil, fmt.Errorf("setting lb algorithm: %w", err)
	}

	p := newMapPopulator(addr, objs, spec)
	for _, l := range conf.Listeners {
		if err := p.Populate(l, addr); err != nil {
			m.Close()
			return nil, fmt.Errorf("popluating map for listener %+v: %w", l, err)
		}
		if conf.HealthchecksEnabled() {
			healthManager := healthcheck.NewManager(m.log, l.Backends, l.Protocol)
			updater, err := m.newBackendHealthUpdater(l, addr, healthManager)
			if err != nil {
				return nil, fmt.Errorf("creating backend health updater: %w", err)
			}

			m.backendUpdaters = append(m.backendUpdaters, updater)
		}
	}

	return m, nil
}

func (p *Manager) Attach(iface netlink.Link, mode config.XDPMode) error {
	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   p.objs.LoadBalance,
		Interface: iface.Attrs().Index,
		Flags:     mode.ToBPFFlags(),
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	p.xdpLink = xdpLink
	return nil
}

func (p *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, u := range p.backendUpdaters {
		wg.Go(func() {
			u.Probe(ctx)
		})
	}
	wg.Wait()
}

func (p *Manager) Close() error {
	var err error
	if p.xdpLink != nil {
		err = errors.Join(err, p.xdpLink.Close())
	}
	err = errors.Join(err, p.objs.Close())
	for _, u := range p.backendUpdaters {
		err = errors.Join(err, u.Close())
	}
	return err
}

type mapPopulator interface {
	Populate(config.Listener, netip.Addr) error
}

func newMapPopulator(addr netip.Addr, objs *lbObjects, spec *ebpf.CollectionSpec) mapPopulator {
	if addr.Is4() {
		return &genericMapPopulator[lbListenerEntry, lbBackend]{
			backendFunc: func(b config.Backend) lbBackend {
				return lbBackend{
					Port: b.Addr.Port(),
					Ip:   lbInAddrFromNetipAddr(b.Addr.Addr()),
				}
			},
			listenerFunc: func(lis config.Listener, addr netip.Addr) lbListenerEntry {
				return (lbListenerEntry{}).FromConfig(lis, addr)
			},
			numBackendMap: objs.NumBackends,
			listenerMap:   objs.ListenerMap,
			backendMapFunc: func() (*ebpf.Map, error) {
				return newBackendMap(spec.Maps[lbMapListenerMap])
			},
		}
	}
	if addr.Is6() {
		return &genericMapPopulator[lbV6ListenerEntry, lbV6Backend]{
			numBackendMap: objs.V6NumBackends,
			listenerMap:   objs.V6ListenerMap,
			listenerFunc: func(lis config.Listener, addr netip.Addr) lbV6ListenerEntry {
				return (lbV6ListenerEntry{}).FromConfig(lis, addr)
			},
			backendFunc: func(b config.Backend) lbV6Backend {
				var backend lbV6Backend
				backend.Ip.Addr = b.Addr.Addr().As16()
				backend.Port = b.Addr.Port()
				return backend
			},
			backendMapFunc: func() (*ebpf.Map, error) {
				return newBackendMap(spec.Maps[lbMapV6ListenerMap])
			},
		}
	}
	panic("ip is neither ipv4 nor ipv6")
}

type genericMapPopulator[LISTENER, BACKEND any] struct {
	numBackendMap  *ebpf.Map
	listenerMap    *ebpf.Map
	listenerFunc   func(lis config.Listener, addr netip.Addr) LISTENER
	backendFunc    func(config.Backend) BACKEND
	backendMapFunc func() (*ebpf.Map, error)
}

func (p *genericMapPopulator[LISTENER, BACKEND]) Populate(lis config.Listener, addr netip.Addr) error {
	if err := p.populateListenerMap(lis, addr); err != nil {
		return err
	}

	if err := p.populateNumBackendMap(lis, addr); err != nil {
		return err
	}
	return nil
}

func (p *genericMapPopulator[LISTENER, BACKEND]) populateListenerMap(lis config.Listener, addr netip.Addr) error {
	backendMap, err := p.backendMapFunc()
	if err != nil {
		return err
	}

	for i, b := range lis.Backends {
		backend := p.backendFunc(b)
		if err := backendMap.Put(uint32(i), backend); err != nil {
			return fmt.Errorf("put backend %+v into map: %w", b, err)
		}
	}

	key := p.listenerFunc(lis, addr)
	if err := p.listenerMap.Put(key, uint32(backendMap.FD())); err != nil {
		return fmt.Errorf("store backend map for listener %+v: %w", lis, err)
	}
	return nil
}

func (p *genericMapPopulator[LISTENER, BACKEND]) populateNumBackendMap(lis config.Listener, addr netip.Addr) error {
	key := p.listenerFunc(lis, addr)
	return p.numBackendMap.Put(key, uint16(len(lis.Backends)))
}

func newBackendMap(outer *ebpf.MapSpec) (*ebpf.Map, error) {
	if outer.InnerMap == nil {
		return nil, errors.New("outer map spec does not contain innermap")
	}
	return ebpf.NewMap(outer.InnerMap)
}

func LoadObjects() (*lbObjects, *ebpf.CollectionSpec, error) {
	spec, err := loadLb()
	if err != nil {
		return nil, nil, err
	}

	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return nil, nil, err
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs lbObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			if err := writeVerifierLog(verifierErr); err != nil {
				slog.Default().Error("writing verifier error", "error", err)
			}
			// print as %+v to get the full error log
			return nil, nil, fmt.Errorf("verifier error from kernel: %+v", verifierErr)
		}
		return nil, nil, fmt.Errorf("loading eBPF objects: %w", err)
	}
	return &objs, spec, nil
}
