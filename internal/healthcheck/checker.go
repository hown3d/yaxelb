package healthcheck

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"yaxelb/internal/config"
)

type Target struct {
	Addr  netip.AddrPort
	Proto config.Protocol
}

func (t Target) String() string {
	return fmt.Sprintf("%s://%s", t.Proto.GoNetwork(), t.Addr)
}

type Result struct {
	Target Target
	Err    error
}

func (r Result) Healthy() bool {
	return r.Err == nil
}

type checker struct {
	Dialer          netDialer
	Targt           Target
	FailedTreshhold uint

	log           *slog.Logger
	failedCounter uint
	lastError     error
}

type netDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

var timeout = time.Second * 5

func (c *checker) Check(ctx context.Context) *Result {
	c.log.Debug("performing healthcheck")

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.Dialer.DialContext(ctx, c.Targt.Proto.GoNetwork(), c.Targt.Addr.String())
	if err != nil {
		c.failedCounter++
		c.lastError = err
		c.log.Debug("healthcheck failed", "err", err.Error(), "failed", c.failedCounter)
		return c.calculateResult()
	}
	defer conn.Close()
	c.failedCounter = 0
	c.lastError = nil
	return c.calculateResult()
}

func (c *checker) calculateResult() *Result {
	r := &Result{Target: c.Targt}
	if c.failedCounter >= c.FailedTreshhold {
		r.Err = c.lastError
	}
	return r
}
