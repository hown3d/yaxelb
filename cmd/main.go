package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"

	"yaxelb/internal/bpf"
	"yaxelb/internal/config"
	"yaxelb/internal/healthcheck"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

var (
	configFile = flag.String("config-file", "/loadbalancer/config.yaml", "config file")
	logLevel   slog.Level
)

func main() {
	flag.TextVar(&logLevel, "log-level", slog.LevelInfo, "log level")
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

	ifname := "eth0" // Change this to an interface on your machine.
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("Getting interface %s: %w", ifname, err)
	}

	c, err := config.FromFile(*configFile)
	if err != nil {
		return fmt.Errorf("parsing config: %W", err)
	}

	slog.Debug("parsed config", "config", c)
	bpfManager, err := bpf.New(c)
	if err != nil {
		return fmt.Errorf("loading program: %w", err)
	}
	defer bpfManager.Close()

	var healthcheckWg sync.WaitGroup
	for _, lis := range c.Listeners {
		log := slog.With("listener", fmt.Sprintf("%s://%s", lis.Protocol.GoNetwork(), lis.Addr))
		healthManager := healthcheck.NewManager(log, lis.Backends, lis.Protocol)
		defer healthManager.Close()
		healthcheckWg.Go(func() {
			log.Info("running healthcheck manager")
			healthManager.Run(ctx)
		})
	}

	if err := bpfManager.Attach(iface); err != nil {
		return fmt.Errorf("attaching program to interface %s: %s", ifname, err)
	}

	slog.Info("successfully attached program, waiting for signals...")
	<-ctx.Done()
	return nil
}
