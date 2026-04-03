package healthcheck

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"yaxelb/internal/config"
)

const failedTreshhold = 3

var checkInterval = 10 * time.Second

type Manager struct {
	checkChan chan *Result
	checkers  []*checker
	log       *slog.Logger
}

func NewManager(log *slog.Logger, targets []config.Backend, protocol config.Protocol) *Manager {
	checkers := make([]*checker, 0, len(targets))
	for _, t := range targets {
		t := Target{Proto: protocol, Addr: t.Addr}
		checkers = append(checkers, &checker{
			Dialer:          &net.Dialer{},
			Targt:           t,
			FailedTreshhold: failedTreshhold,
			log:             log.With("target", t),
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
		wg.Go(func() {
			m.checkChan <- c.Check(ctx)
		})
	}
	wg.Wait()
}
