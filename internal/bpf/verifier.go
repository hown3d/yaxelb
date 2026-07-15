package bpf

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

var tmpDir = filepath.Join(os.TempDir(), "yaxelb")

func writeVerifierLog(verifierErr *ebpf.VerifierError) error {
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(tmpDir, "verifier-*.log")
	if err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	defer f.Close()

	for _, line := range verifierErr.Log {
		_, err := fmt.Fprintln(f, line)
		if err != nil {
			return err
		}
	}
	return nil
}
