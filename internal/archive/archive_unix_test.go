//go:build linux

package archive

import (
	"archive/zip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFlushDirToZipSkipsFifoWithoutHanging(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "out")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(src, "good.txt")
	if err := os.WriteFile(good, []byte("readable"), 0644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(src, "pipe")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	zipPath := filepath.Join(base, "out.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	// If FlushDirToZip opened the FIFO this call would block forever and the
	// test would time out instead of returning.
	skipped, err := FlushDirToZip(zw, src, base)
	if err != nil {
		t.Fatalf("flush returned fatal error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}

	foundSkip := false
	for _, s := range skipped {
		if len(s) >= len(fifo) && s[:len(fifo)] == fifo {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected fifo in skip list, got %v", skipped)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "out/pipe" {
			t.Errorf("fifo must not produce a zip entry")
		}
	}
}
