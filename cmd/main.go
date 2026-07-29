package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"yaxelb/internal/bpf"
	"yaxelb/internal/config"
	"yaxelb/pkg/net"

	"github.com/cilium/ebpf/rlimit"
	"github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
)

var (
	configFile string
	ifname     string
	logLevel   slog.Level
)

func init() {
	flag.TextVar(&logLevel, "log-level", slog.LevelInfo, "log level")
	flag.StringVar(&ifname, "interface", "eth0", "interface to bind ebpf program to")
	flag.StringVar(&configFile, "config-file", "/loadbalancer/config.yaml", "config file")
}

func main() {
	config.AddToFlags(flag.CommandLine)
	flag.Parse()
	slog.SetLogLoggerLevel(logLevel)
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("Removing memlock: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	c, err := config.FromFile(configFile)
	if err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	slog.Debug("parsed config", "config", c)

	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", ifname, err)
	}

	addr, err := net.AddressOfInterface(iface)
	if err != nil {
		return fmt.Errorf("getting address of interface %s: %w", ifname, err)
	}
	if addr.Is6() {
		if err := enableIPV6Forwarding(); err != nil {
			return fmt.Errorf("enabling ipv6 forwarding: %w", err)
		}
	}

	bpfManager, err := bpf.New(c, addr)
	if err != nil {
		return fmt.Errorf("loading program: %w", err)
	}
	defer bpfManager.Close()

	if err := bpfManager.Attach(iface, c.XdpMode); err != nil {
		return fmt.Errorf("attaching program to interface %s: %s", ifname, err)
	}

	bpfManager.Run(ctx)

	slog.Info("successfully attached program, waiting for signals...", "ifname", ifname, "address", addr)
	<-ctx.Done()
	return nil
}

func enableIPV6Forwarding() error {
	return sysctl.Set("net.ipv6.conf.all.forwarding", "1")
}
