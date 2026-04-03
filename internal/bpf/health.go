package bpf

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"yaxelb/internal/config"
	"yaxelb/internal/healthcheck"
	"yaxelb/pkg/byteorder"

	"github.com/cilium/ebpf"
)

func (m *Manager) newBackendHealthUpdater(listener config.Listener, healthManager *healthcheck.Manager) (*backendHealthUpdater, error) {
	listenerKey := (lbListenerEntry{}).FromConfig(listener)
	var backendMap *ebpf.Map
	if err := m.objs.ListenerMap.Lookup(listenerKey, &backendMap); err != nil {
		return nil, err
	}
	log := m.log.
		WithGroup("healthcheck").
		With("listener", fmt.Sprintf("%s://%s", listener.Protocol.GoNetwork(), listener.Addr))
	log.Debug("retrieved backend map", "map", backendMap.String())
	return &backendHealthUpdater{
		healthManager: healthManager,
		backendMap:    backendMap,
		updateNumBackendFunc: func(num int) error {
			return m.objs.NumBackends.Put(listenerKey, uint16(num))
		},
		log: log,
	}, nil
}

type backendHealthUpdater struct {
	healthManager        *healthcheck.Manager
	backendMap           *ebpf.Map
	updateNumBackendFunc func(num int) error
	log                  *slog.Logger
}

func (u *backendHealthUpdater) Run(ctx context.Context) {
	resultChan := u.runHealthManager(ctx)
	for {
		select {
		case <-ctx.Done():
			u.log.Debug("context done", "err", ctx.Err())
			return
		case res := <-resultChan:
			{
				err := u.updateBackendHealth(
					lbBackend{
						// since we are loading the backend from the kernel, we must store port here in network order
						Port: byteorder.HostToNetwork16(res.Target.Addr.Port()),
						Ip:   lbInAddrFromNetipAddr(res.Target.Addr.Addr()),
					}, res.Healthy())
				if err != nil {
					u.log.Error("updating backend health", "error", err)
				}
			}
		}
	}
}

func (u *backendHealthUpdater) Close() error {
	return u.healthManager.Close()
}

func (u *backendHealthUpdater) runHealthManager(ctx context.Context) <-chan *healthcheck.Result {
	go func() {
		u.healthManager.Run(ctx)
	}()
	return u.healthManager.ResultChan()
}

func (u *backendHealthUpdater) updateBackendHealth(b lbBackend, healthy bool) error {
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

type backendMap map[lbBackend]uint32

func (b backendMap) String() string {
	sb := new(strings.Builder)
	for backend, index := range b {
		fmt.Fprintf(sb, "{%d: %s}", index, backend)
	}
	return sb.String()
}

func (b backendMap) toKernelMap() ([]uint32, []lbBackend) {
	keys := make([]uint32, 0, len(b))
	backends := make([]lbBackend, 0, len(b))
	var index uint32
	for backend := range b {
		keys = append(keys, index)
		backends = append(backends, backend)
		index++
	}
	return keys, backends
}

func (u *backendHealthUpdater) currentBackends() (backendMap, error) {
	backends := backendMap{}
	iter := u.backendMap.Iterate()
	var (
		index   uint32
		backend lbBackend
	)
	for iter.Next(&index, &backend) {
		if backend.Ip.S_addr == 0 {
			break
		}
		backends[backend] = index
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return backends, nil
}
