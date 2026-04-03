package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"yaxelb/internal/config"
)

type target struct {
	addr  netip.AddrPort
	proto config.Protocol
}

func (t target) String() string {
	return fmt.Sprintf("%s://%s", t.proto.GoNetwork(), t.addr)
}

type Result struct {
	Healthy bool
	Target  target
	err     error
}

type checker struct {
	dialer netDialer
	targt  target
}

type netDialer interface {
	DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
}

var timeout = time.Second * 10

func (c *checker) Check(ctx context.Context) *Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dialer.DialContext(ctx, c.targt.proto.GoNetwork(), c.targt.addr.String())
	if err != nil {
		return &Result{Healthy: false, Target: c.targt, err: err}
	}
	defer conn.Close()
	return &Result{Healthy: true, Target: c.targt}
}
