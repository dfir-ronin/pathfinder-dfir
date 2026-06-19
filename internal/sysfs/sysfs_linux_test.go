//go:build linux

package sysfs

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestScanImmutable_FifoDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan struct{})
	go func() {
		ScanImmutable([]string{dir})
		close(done)
	}()

	select {
	case <-done:
		// returned promptly -- good
	case <-time.After(5 * time.Second):
		t.Fatal("ScanImmutable hung opening a FIFO (needs O_NONBLOCK / regular-file gate)")
	}
}
