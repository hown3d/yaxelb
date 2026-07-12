package config

import (
	"testing"
)

func TestListeners_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "default config",
			cfg: Config{
				Algorithm: AlgorithmRandom,
				XdpMode:   XDPModeGeneric,
				Listeners: Listeners{
					{
						Port:     80,
						Protocol: TCP,
					},
					{
						Port:     8080,
						Protocol: UDP,
					},
				},
			},
		},
		{
			name: "duplicate port and protocol for listener",
			cfg: Config{
				Algorithm: AlgorithmRandom,
				XdpMode:   XDPModeGeneric,
				Listeners: Listeners{
					{
						Port:     80,
						Protocol: TCP,
					},
					{
						Port:     80,
						Protocol: TCP,
					},
				},
			},
			wantErr: true,
		},

		{
			name: "unknown protocol",
			cfg: Config{
				Algorithm: AlgorithmRandom,
				XdpMode:   XDPModeGeneric,
				Listeners: Listeners{
					{
						Port:     80,
						Protocol: "abc",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unknown xdp mode",
			cfg: Config{
				Algorithm: AlgorithmRandom,
				XdpMode:   "foo",
			},
			wantErr: true,
		},
		{
			name: "unknown algortihm",
			cfg: Config{
				Algorithm: "foo",
				XdpMode:   XDPModeGeneric,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validate.Struct(tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("validating config error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
