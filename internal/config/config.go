package config

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"golang.org/x/sys/unix"
)

type Config struct {
	Algorithm Algorithm  `yaml:"algorithm"`
	Listeners []Listener `yaml:"listeners"`

	healthcheck healthcheck
}

var flagConfig Config

func AddToFlags(fs *flag.FlagSet) {
	fs.BoolVar(&flagConfig.healthcheck.Enabled, "enable-healthcheck", true, "Wether to enable backend healthchecks")
}

func (c *Config) HealthchecksEnabled() bool {
	return c.healthcheck.Enabled
}

type healthcheck struct {
	Enabled bool
}

type Algorithm string

const (
	AlgorithmRandom Algorithm = "random"
	AlgorithmHash   Algorithm = "hash"
)

type Listener struct {
	Addr     netip.AddrPort `yaml:"address"`
	Protocol Protocol       `yaml:"protocol"`
	Backends []Backend      `yaml:"backends"`
}

// Protocol is a network protocol.
type Protocol string

// Constants for valid protocols:
const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

func (p *Protocol) UnmarshalYAML(data []byte) error {
	switch strings.TrimSpace(strings.ToUpper(string(data))) {
	case string(TCP):
		*p = TCP
	case string(UDP):
		*p = UDP
	default:
		return fmt.Errorf("unknown protocol: %s", data)
	}
	return nil
}

func (p Protocol) Unix() uint8 {
	switch p {
	case TCP:
		return unix.IPPROTO_TCP
	case UDP:
		return unix.IPPROTO_UDP
	}
	return 0
}

func (p Protocol) GoNetwork() string {
	return strings.ToLower(string(p))
}

type Backend struct {
	Addr netip.AddrPort `yaml:"address"`
}

func FromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// use flags as default
	c := flagConfig
	if err := yaml.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
