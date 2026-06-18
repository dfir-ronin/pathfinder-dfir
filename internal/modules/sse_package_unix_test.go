//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSymlinkDereferenceAllowed_NonRegular(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	if _, ok, reason := symlinkDereferenceAllowed(link, root, true); ok || reason != "symlink target is not a regular file" {
		t.Errorf("fifo target: ok=%v reason=%q", ok, reason)
	}
}
