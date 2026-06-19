//go:build !linux
// +build !linux

package osutil

import (
	"errors"
	"io"
	"os"
)

// OpenNoAtime opens a file. On non-Linux platforms, it's identical to os.Open
// since O_NOATIME is not available.
func OpenNoAtime(path string) (*os.File, error) {
	return os.Open(path)
}

// ReadFileNoAtime reads a file. On non-Linux platforms, this is identical to
// os.ReadFile since O_NOATIME is not available.
func ReadFileNoAtime(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ErrNotRegularFile is returned by OpenRegularNoBlock when the path is not a
// regular file. O_NONBLOCK/O_NOATIME are unavailable here, so this is a plain
// open plus an fstat type check.
var ErrNotRegularFile = errors.New("not a regular file")

// OpenRegularNoBlock opens path and rejects non-regular files via fstat.
func OpenRegularNoBlock(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrNotRegularFile
	}
	return f, nil
}
