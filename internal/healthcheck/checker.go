package healthcheck

import (
	"context"
	"fmt"
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
	Healthy bool
	Target  Target
	err     error
}

type checker struct {
	dialer netDialer
	targt  Target
}

type netDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

var timeout = time.Second * 5

func (c *checker) Check(ctx context.Context) *Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dialer.DialContext(ctx, c.targt.Proto.GoNetwork(), c.targt.Addr.String())
	if err != nil {
		return &Result{Healthy: false, Target: c.targt, err: err}
	}
	defer conn.Close()
	return &Result{Healthy: true, Target: c.targt}
}
