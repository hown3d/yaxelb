package testutil

import (
	"io"
	"os"
	"testing"
)

const kernelTraceFile = "/sys/kernel/tracing/trace"

type kernelTraces struct {
	f *os.File
}

func PrintTraces(t *testing.T) {
	trace, err := KernelTraceReader()
	if err != nil {
		t.Log(err)
		return
	}
	t.Log("kernel trace output")
	io.Copy(t.Output(), trace)
	if err := trace.Clear(); err != nil {
		t.Log("failed to clear trace", err)
	}
}

func KernelTraceReader() (*kernelTraces, error) {
	f, err := os.OpenFile(kernelTraceFile, os.O_RDONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &kernelTraces{
		f: f,
	}, nil
}

func (k kernelTraces) Read(b []byte) (n int, err error) {
	return k.f.Read(b)
}

func (k kernelTraces) Clear() error {
	return os.WriteFile(kernelTraceFile, []byte{}, 0o640)
}

func (k kernelTraces) Close() error {
	return k.f.Close()
}
