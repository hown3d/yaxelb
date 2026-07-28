//go:build linux

package e2e

import (
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"yaxelb/internal/bpf/testutil"

	"github.com/safchain/ethtool"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/vishvananda/netlink"
)

func TestYaxeLB(t *testing.T) {
	stack := composeUp(t)
	registerTracePrint(t)
	lbContainer, err := stack.ServiceContainer(t.Context(), "lb")
	if err != nil {
		t.Fatal("getting lb container", err)
	}
	if err := setupLBInterfaceForNativeXDP(t.Context(), lbContainer); err != nil {
		t.Fatal("setup lb interface for native xdp", err)
	}

	testcases := []struct {
		name    string
		cmd     []string
		wantErr bool
	}{
		{
			name: "http",
			cmd:  []string{"curl", "--connect-timeout", "1s", "-v", "http://10.0.0.2"},
		},
		{
			name: "netcat",
			cmd:  []string{"nc", "-vz", "-w", "1", "10.0.0.2", "8080"},
		},
		{
			name:    "netcat on port not bound by listener",
			cmd:     []string{"nc", "-vz", "-w", "1", "10.0.0.2", "4200"},
			wantErr: true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			clientContainer, err := stack.ServiceContainer(t.Context(), "client")
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

func composeUp(t *testing.T) *compose.DockerCompose {
	stack, err := compose.NewDockerComposeWith(
		compose.WithLogger(log.New(t.Output(), t.Name()+": ", 0)),

		compose.StackIdentifier(strings.ToLower(t.Name())),
		compose.WithStackFiles(composeFilePath()),
	)
	if err != nil {
		t.Fatalf("creating docker compose stack: %s", err)
	}
	t.Cleanup(func() {
		err = stack.Down(
			context.Background(),
			compose.RemoveOrphans(true),
			compose.RemoveVolumes(true),
			compose.RemoveImagesLocal,
		)
		if err != nil {
			log.Printf("Failed to stop stack: %v", err)
		}
	})
	if err := stack.
		WaitForService("lb", wait.ForLog("successfully attached program, waiting for signals")).
		Up(t.Context()); err != nil {

		logReader, err2 := lbContainerLogs(t.Context(), stack)
		if err2 == nil {
			defer logReader.Close()
			log, _ := io.ReadAll(logReader)
			t.Logf("lb container output:\n%s", log)
		}

		t.Fatalf("compose up: %s", err)
		return nil
	}
	return stack
}

func composeFilePath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't get filename")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "docker-compose.yaml")
}

// registerTracePrint will print all kernel traces after the test has been run.
// Traces are only printed in test verbose mode
func registerTracePrint(t *testing.T) {
	if testing.Verbose() {
		t.Cleanup(func() {
			testutil.PrintTraces(t)
		})
	}
}

func setupLBInterfaceForNativeXDP(ctx context.Context, lbContainer testcontainers.Container) error {
	link, err := findLBVeth(ctx, lbContainer)
	if err != nil {
		return fmt.Errorf("finding veth of lb: %w", err)
	}
	tool, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	return tool.Change(link.Attrs().Name, map[string]bool{
		// features are available here: https://elixir.bootlin.com/linux/v5.1.9/source/net/core/ethtool.c#L61
		"rx-gro":                 true,
		"tx-checksum-ip-generic": false,
	})
}

func findLBVeth(ctx context.Context, lbContainer testcontainers.Container) (netlink.Link, error) {
	code, r, err := lbContainer.Exec(ctx, []string{"cat", "/sys/class/net/eth0/iflink"}, tcexec.Multiplexed())
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("reading iflink of container returned exit code: %d", code)
	}
	linkRaw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	linkIndex, err := strconv.Atoi(strings.TrimSpace(string(linkRaw)))
	if err != nil {
		return nil, err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.Attrs().Index == linkIndex {
			return l, nil
		}
	}
	return nil, fmt.Errorf("link with index %d not found", linkIndex)
}

func lbContainerLogs(ctx context.Context, stack compose.ComposeStack) (io.ReadCloser, error) {
	lbContainer, err := stack.ServiceContainer(ctx, "lb")
	if err != nil {
		return nil, err
	}
	return lbContainer.Logs(ctx)
}
