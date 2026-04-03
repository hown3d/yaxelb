package healthcheck

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"yaxelb/internal/config"
)

var checkInterval = 10 * time.Second

type Manager struct {
	checkChan    chan *Result
	checkers     []*checker
	targetHealth map[target]bool
	log          *slog.Logger
}

func NewManager(log *slog.Logger, targets []config.Backend, protocol config.Protocol) *Manager {
	checkers := make([]*checker, 0, len(targets))
	for _, t := range targets {
		checkers = append(checkers, &checker{
			dialer: &net.Dialer{},
			targt:  target{proto: protocol, addr: t.Addr},
		})
	}
	return &Manager{
		checkChan:    make(chan *Result),
		checkers:     checkers,
		log:          log,
		targetHealth: make(map[target]bool, len(targets)),
	}
}

func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() {
		m.performChecks(ctx)
	})
	wg.Go(m.updateTargetHealth)
	wg.Wait()
}

func (m *Manager) Close() error {
	close(m.checkChan)
	return nil
}

func (m *Manager) updateTargetHealth() {
	for res := range m.checkChan {
		log := m.log.With("target", res.Target)
		if res.err != nil {
			log.Error("performing healthcheck failed", "error", res.err)
		}
		log.Debug("healthcheck performed", "healthy", res.Healthy)
		m.targetHealth[res.Target] = res.Healthy
	}
}

func (m *Manager) performChecks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.Tick(checkInterval):
			m.runChecks(ctx)
		}
	}
}

func (m *Manager) runChecks(ctx context.Context) {
	var wg sync.WaitGroup
	for _, c := range m.checkers {
		m.log.Debug("performing healthcheck", "target", c.targt)
		wg.Go(func() {
			m.checkChan <- c.Check(ctx)
		})
	}
	wg.Wait()
}
