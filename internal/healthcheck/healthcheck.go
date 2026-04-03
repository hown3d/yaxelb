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
	checkChan chan *Result
	checkers  []*checker
	log       *slog.Logger
}

func NewManager(log *slog.Logger, targets []config.Backend, protocol config.Protocol) *Manager {
	checkers := make([]*checker, 0, len(targets))
	for _, t := range targets {
		checkers = append(checkers, &checker{
			dialer: &net.Dialer{},
			targt:  Target{Proto: protocol, Addr: t.Addr},
		})
	}
	return &Manager{
		checkChan: make(chan *Result),
		checkers:  checkers,
		log:       log,
	}
}

func (m *Manager) Run(ctx context.Context) {
	m.log.Info("running healthcheck manager")
	m.performChecks(ctx)
}

func (m *Manager) Close() error {
	close(m.checkChan)
	return nil
}

func (m *Manager) ResultChan() <-chan *Result {
	return m.checkChan
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
