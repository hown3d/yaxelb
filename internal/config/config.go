package config

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-yaml"
	"golang.org/x/sys/unix"
)

var validate = validator.New()

type Config struct {
	// Algorithm defaults to random if unspecified
	Algorithm Algorithm `yaml:"algorithm" validate:"oneof=hash random"`
	Listeners Listeners `yaml:"listeners" validate:"validateFn"`

	healthcheck healthcheck
	XdpMode     XDPMode `validate:"oneof=generic driver"`
}

type Listeners []Listener

func (l Listeners) Validate() error {
	type key struct {
		port  uint16
		proto string
	}
	var errs error
	uniqueMap := map[key]int{}
	for i, lis := range l {
		errs = errors.Join(errs, validate.Struct(lis))
		k := key{
			port:  lis.Port,
			proto: string(lis.Protocol),
		}
		idx, ok := uniqueMap[k]
		if ok {
			errs = errors.Join(errs, fmt.Errorf("duplicate port + protocol found on Listener %d and %d", i, idx))
			continue
		}
		uniqueMap[k] = idx
	}
	return errs
}

var flagConfig Config

func AddToFlags(fs *flag.FlagSet) {
	fs.BoolVar(&flagConfig.healthcheck.Enabled, "enable-healthcheck", true, "Wether to enable backend healthchecks")
	fs.Var(&flagConfig.XdpMode, "xdp-mode", "XDP Mode to use for attaching xdp program")
}

func (c *Config) HealthchecksEnabled() bool {
	return c.healthcheck.Enabled
}

type healthcheck struct {
	Enabled bool
}

type XDPMode string

// Set implements [flag.Value].
func (x *XDPMode) Set(v string) error {
	switch XDPMode(v) {
	case "", XDPModeGeneric, XDPModeDriver:
		*x = XDPMode(v)
		return nil
	}
	return fmt.Errorf("unsupported xdp-mode: %s", v)
}

// String implements [flag.Value].
func (x *XDPMode) String() string {
	return string(*x)
}

func (x XDPMode) ToBPFFlags() link.XDPAttachFlags {
	switch x {
	case XDPModeGeneric:
		return link.XDPGenericMode
	case XDPModeDriver:
		return link.XDPDriverMode
	}

	return 0
}

const (
	XDPModeGeneric XDPMode = "generic"
	XDPModeDriver  XDPMode = "driver"
)

type Algorithm string

const (
	AlgorithmRandom Algorithm = "random"
	AlgorithmHash   Algorithm = "hash"
)

type Listener struct {
	Port uint16 `yaml:"port" validate:"required"`
	// Protocol is TCP if unspecified
	Protocol Protocol  `yaml:"protocol" validate:"oneof=TCP UDP"`
	Backends []Backend `yaml:"backends"`
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
	case string(TCP), "":
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
	Addr netip.AddrPort `yaml:"address" validate:"required"`
}

func FromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// use flags as default
	c := flagConfig
	if err := yaml.NewDecoder(f, yaml.Strict(), yaml.Validator(validate)).Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding yaml: %w", err)
	}
	return &c, nil
}
