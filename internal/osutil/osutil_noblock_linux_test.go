//go:build linux

package osutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRegularNoBlock_ReadsRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileRegularNoBlock(p)
	if err != nil {
		t.Fatalf("ReadFileRegularNoBlock: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("got %q, want hello", b)
	}
}

func TestOpenRegularNoBlock_RejectsFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := OpenRegularNoBlock(p)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("err = %v, want ErrNotRegularFile", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRegularNoBlock blocked on a FIFO (the leak this fix prevents)")
	}
}

func TestOpenRegularNoBlock_RejectsDir(t *testing.T) {
	f, err := OpenRegularNoBlock(t.TempDir())
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("err = %v, want ErrNotRegularFile", err)
	}
}
