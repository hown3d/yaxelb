package testutil

import (
	"io"
	"os"
	"testing"
)

const kernelTraceFile = "/sys/kernel/tracing/trace"

type KernelTracer struct {
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

func KernelTraceReader() (*KernelTracer, error) {
	f, err := os.OpenFile(kernelTraceFile, os.O_RDONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &KernelTracer{
		f: f,
	}, nil
}

func (k KernelTracer) Read(b []byte) (n int, err error) {
	return k.f.Read(b)
}

func (k KernelTracer) Clear() error {
	return os.WriteFile(kernelTraceFile, []byte{}, 0o640)
}

func (k KernelTracer) Close() error {
	return k.f.Close()
}
