//go:build linux

package e2e

import (
	"io"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

type ipv4Suite struct {
	suite.Suite
	stack       *compose.DockerCompose
	lbContainer *testcontainers.DockerContainer
}

func TestIPv4(t *testing.T) {
	suite.Run(t, new(ipv4Suite))
}

func (s *ipv4Suite) SetupSuite() {
	t := s.T()
	s.stack = composeUp(t, IPv4)
	registerTracePrint(t)
	var err error
	s.lbContainer, err = s.stack.ServiceContainer(t.Context(), "lb")
	if err != nil {
		t.Fatal("getting lb container", err)
	}
	if err := setupLBInterfaceForNativeXDP(t.Context(), s.lbContainer); err != nil {
		t.Fatal("setup lb interface for native xdp", err)
	}
}

func (s *ipv4Suite) Test() {
	testcases := []struct {
		name    string
		cmd     []string
		wantErr bool
	}{
		{
			name: "http",
			cmd:  []string{"curl", "--connect-timeout", "3s", "-v", "http://10.0.0.2"},
		},
		{
			name: "netcat udp",
			cmd:  []string{"nc", "-vzu", "-w", "1", "10.0.0.2", "8080"},
		},
		{
			name: "netcat on port not bound by listener",
			cmd:  []string{"nc", "-vzu", "-w", "1", "10.0.0.2", "4200"},
		},
		{
			name:    "netcat with wrong protocol",
			cmd:     []string{"nc", "-vz", "-w", "1", "10.0.0.2", "4200"},
			wantErr: true,
		},
	}

	for _, tt := range testcases {
		s.Run(tt.name, func() {
			t := s.T()
			clientContainer, err := s.stack.ServiceContainer(t.Context(), "client")
			if err != nil {
				t.Errorf("getting client container: %v", err)
				return
			}
			code, r, err := clientContainer.Exec(t.Context(), tt.cmd, tcexec.Multiplexed())
			if err != nil {
				t.Errorf("executing curl in client: %v", err)
				return
			}
			if code != 0 && !tt.wantErr {
				log, _ := io.ReadAll(r)
				t.Errorf("command return error code != 0, got %d", code)
				t.Logf("output:\n%s", log)
				return
			}
		})
	}
}
