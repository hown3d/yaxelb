package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"yaxelb/internal/config"
	"yaxelb/internal/healthcheck"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	log             *slog.Logger
	backendUpdaters []*backendHealthUpdater
	objs            *lbObjects
	xdpLink         link.Link
}

func New(conf *config.Config) (*Manager, error) {
	spec, err := loadLb()
	if err != nil {
		return nil, err
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs lbObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			// print as %+v to get the full error log
			return nil, fmt.Errorf("verifier error from kernel: %+v", verifierErr)
		}
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}
	m := &Manager{
		objs: &objs,
		log:  slog.Default().WithGroup("bpf"),
	}

	var lbAlgo lbLbAlgorithm
	if err := objs.LbAlgo.Set(lbAlgo.FromConfig(conf.Algorithm)); err != nil {
		m.Close()
		return nil, fmt.Errorf("setting lb algorithm: %w", err)
	}

	for _, l := range conf.Listeners {
		if err := m.populateListenerMap(l, func() (*ebpf.Map, error) {
			return newBackendMap(spec.Maps["listener_map"])
		}); err != nil {
			m.Close()
			return nil, err
		}

		if err := m.populateNumBackendMap(l); err != nil {
			m.Close()
			return nil, err
		}

		healthManager := healthcheck.NewManager(m.log, l.Backends, l.Protocol)
		updater, err := m.newBackendHealthUpdater(l, healthManager)
		if err != nil {
			return nil, fmt.Errorf("creating backend health updater: %w", err)
		}

		m.backendUpdaters = append(m.backendUpdaters, updater)
	}

	return m, nil
}

func (m *Manager) Attach(iface netlink.Link) error {
	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.LoadBalance,
		Interface: iface.Attrs().Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	m.xdpLink = xdpLink
	return nil
}

func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, u := range m.backendUpdaters {
		wg.Go(func() {
			u.Run(ctx)
		})
	}
	wg.Wait()
}

func (m *Manager) Close() error {
	var err error
	if m.xdpLink != nil {
		err = errors.Join(err, m.xdpLink.Close())
	}
	err = errors.Join(err, m.objs.Close())
	for _, u := range m.backendUpdaters {
		err = errors.Join(err, u.Close())
	}
	return err
}

func (m *Manager) populateListenerMap(lis config.Listener, backendMapFunc func() (*ebpf.Map, error)) error {
	backendMap, err := backendMapFunc()
	if err != nil {
		return err
	}

	for i, b := range lis.Backends {
		if err := backendMap.Put(uint32(i), lbBackend{
			Port: b.Addr.Port(),
			Ip:   lbInAddrFromNetipAddr(b.Addr.Addr()),
		}); err != nil {
			return fmt.Errorf("put backend %+v into map: %w", b, err)
		}
	}

	key := (lbListenerEntry{}).FromConfig(lis)
	if err := m.objs.ListenerMap.Put(key, uint32(backendMap.FD())); err != nil {
		return fmt.Errorf("store backend map for listener %+v: %w", lis, err)
	}
	return nil
}

func (m *Manager) populateNumBackendMap(lis config.Listener) error {
	key := (lbListenerEntry{}).FromConfig(lis)
	return m.objs.NumBackends.Put(key, uint16(len(lis.Backends)))
}

func newBackendMap(outer *ebpf.MapSpec) (*ebpf.Map, error) {
	if outer.InnerMap == nil {
		return nil, errors.New("outer map spec does not contain innermap")
	}
	return ebpf.NewMap(outer.InnerMap)
}
