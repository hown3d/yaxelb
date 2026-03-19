package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"yaxelb/internal/bpf"
	"yaxelb/internal/config"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

var configFile = flag.String("config-file", "/loadbalancer/config.yaml", "config file")

func main() {
	flag.Parse()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	ifname := "eth0" // Change this to an interface on your machine.
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	c, err := config.FromFile(*configFile)
	if err != nil {
		log.Fatal("parsing config:", err)
	}

	log.Printf("%+v", c)
	manager, err := bpf.New(c)
	if err != nil {
		log.Fatalf("loading program: %s", err)
	}
	defer manager.Close()

	if err := manager.Attach(iface); err != nil {
		log.Fatalf("attaching program to interface %s: %s", ifname, err)
	}

	log.Printf("successfully attached program, waiting for signals...")

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, os.Kill)
	<-stop
}
