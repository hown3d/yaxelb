package bpf

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"yaxelb/internal/config"
	"yaxelb/internal/healthcheck"
	"yaxelb/pkg/byteorder"

	"github.com/cilium/ebpf"
)

type BackendHealthProber interface {
	Probe(ctx context.Context)
	Close() error
}

func (p *Manager) newBackendHealthUpdater(listener config.Listener, addr netip.Addr, healthManager *healthcheck.Manager) (BackendHealthProber, error) {
	var (
		backendMap *ebpf.Map
	)
	log := p.log.
		WithGroup("healthcheck").
		With("listener", fmt.Sprintf("%s://%s:%d", listener.Protocol.GoNetwork(), addr, listener.Port))

	switch addr.BitLen() {
	case 32:
		listenerKey := v4ListenerKey(listener, addr)
		if err := p.objs.ListenerMap.Lookup(listenerKey, &backendMap); err != nil {
			return nil, err
		}
		log.Debug("retrieved backend map", "map", backendMap.String())
		return &backendHealthProber[lbBackend]{
			healthManager: healthManager,
			backendMap:    backendMap,
			updateNumBackendFunc: func(num int) error {
				return p.objs.NumBackends.Put(listenerKey, uint16(num))
			},
			log: log,
			backendFromResultFunc: func(res *healthcheck.Result) lbBackend {
				// since we are loading the backend from the kernel, we must store port here in network order
				return lbBackend{
					Port: byteorder.HostToNetwork16(res.Target.Addr.Port()),
					Ip:   lbInAddrFromNetipAddr(res.Target.Addr.Addr()),
				}
			},
		}, nil
	case 128:
		listenerKey := v6ListenerKey(listener, addr)
		if err := p.objs.V6ListenerMap.Lookup(listenerKey, &backendMap); err != nil {
			return nil, err
		}
		log.Debug("retrieved backend map", "map", backendMap.String())
		return &backendHealthProber[lbV6Backend]{
			healthManager: healthManager,
			backendMap:    backendMap,
			updateNumBackendFunc: func(num int) error {
				return p.objs.V6NumBackends.Put(listenerKey, uint16(num))
			},
			log: log,
			backendFromResultFunc: func(res *healthcheck.Result) lbV6Backend {
				b := lbV6Backend{
					Port: byteorder.HostToNetwork16(res.Target.Addr.Port()),
				}
				b.Ip.Addr = res.Target.Addr.Addr().As16()
				return b
			},
		}, nil
	default:
		return nil, fmt.Errorf("ip type is neither ipv4 nor ipv6, got len %d", addr.BitLen())
	}
}

type backend interface {
	lbBackend | lbV6Backend
	IsEmpty() bool
}

type backendHealthProber[BACKENDTYPE backend] struct {
	healthManager         *healthcheck.Manager
	backendMap            *ebpf.Map
	updateNumBackendFunc  func(num int) error
	backendFromResultFunc func(*healthcheck.Result) BACKENDTYPE
	log                   *slog.Logger
}

func v4ListenerKey(listener config.Listener, addr netip.Addr) lbListenerEntry {
	return (lbListenerEntry{}).FromConfig(listener, addr)
}

func v6ListenerKey(listener config.Listener, addr netip.Addr) lbV6ListenerEntry {
	return (lbV6ListenerEntry{}).FromConfig(listener, addr)
}

func (u *backendHealthProber[BACKENDTYPE]) Probe(ctx context.Context) {
	resultChan := u.runHealthManager(ctx)
	for {
		select {
		case <-ctx.Done():
			u.log.Debug("context done", "err", ctx.Err())
			return
		case res := <-resultChan:
			{
				err := u.updateBackendHealth(u.backendFromResultFunc(res), res.Healthy())
				if err != nil {
					u.log.Error("updating backend health", "error", err)
				}
			}
		}
	}
}

func (u *backendHealthProber[BACKENDTYPE]) Close() error {
	return u.healthManager.Close()
}

func (u *backendHealthProber[BACKENDTYPE]) runHealthManager(ctx context.Context) <-chan *healthcheck.Result {
	go func() {
		u.healthManager.Run(ctx)
	}()
	return u.healthManager.ResultChan()
}

func (u *backendHealthProber[BACKENDTYPE]) updateBackendHealth(b BACKENDTYPE, healthy bool) error {
	current, err := u.currentBackends()
	if err != nil {
		return fmt.Errorf("retrieving current backends: %w", err)
	}
	u.log.Debug("current backends", "backends", current)

	if !healthy {
		u.log.Debug("backend is not healthy", "backend", b)
		delete(current, b)
	} else {
		// if backend was previouly not healthy, readd it to the new backends
		_, ok := current[b]
		if ok {
			// backend is healthy and included in current backends
			return nil
		}
		u.log.Debug("backend healthy again", "backend", b)
		current[b] = uint32(len(current) - 1)
	}

	keys, backends := current.toKernelMap()
	u.log.Debug("updating backends", "keys", keys, "backends", backends)
	_, err = u.backendMap.BatchUpdate(keys, backends, &ebpf.BatchOptions{})
	if err != nil {
		return err
	}

	if err := u.updateNumBackendFunc(len(backends)); err != nil {
		return err
	}
	return nil
}

type backendMap[BACKENDTYPE backend] map[BACKENDTYPE]uint32

func (b backendMap[BACKENDTYPE]) String() string {
	sb := new(strings.Builder)
	for backend, index := range b {
		fmt.Fprintf(sb, "{%d: %s}", index, backend)
	}
	return sb.String()
}

func (b backendMap[BACKENDTYPE]) toKernelMap() ([]uint32, []BACKENDTYPE) {
	keys := make([]uint32, 0, len(b))
	backends := make([]BACKENDTYPE, 0, len(b))
	var index uint32
	for backend := range b {
		keys = append(keys, index)
		backends = append(backends, backend)
		index++
	}
	return keys, backends
}

func (u *backendHealthProber[BACKENDTYPE]) currentBackends() (backendMap[BACKENDTYPE], error) {
	backends := backendMap[BACKENDTYPE]{}
	iter := u.backendMap.Iterate()
	var (
		index   uint32
		backend BACKENDTYPE
	)
	for iter.Next(&index, &backend) {
		if backend.IsEmpty() {
			break
		}
		backends[backend] = index
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return backends, nil
}
