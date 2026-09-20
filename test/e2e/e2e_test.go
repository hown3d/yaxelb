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
	"golang.org/x/sys/unix"
)

type IPFamily int

const IPv4 IPFamily = unix.AF_INET
const IPv6 IPFamily = unix.AF_INET6

func composeUp(t *testing.T, family IPFamily) *compose.DockerCompose {
	stack, err := compose.NewDockerComposeWith(
		compose.WithLogger(log.New(t.Output(), t.Name()+": ", 0)),

		compose.StackIdentifier(strings.ToLower(t.Name())),
		compose.WithStackFiles(composeFilePath(family)),
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

func composeFilePath(ipFamily IPFamily) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't get filename")
	}
	var composeFile string
	switch ipFamily {
	case IPv4:
		composeFile = "docker-compose.yaml"
	case IPv6:
		composeFile = "docker-compose-v6.yaml"
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", composeFile)
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
