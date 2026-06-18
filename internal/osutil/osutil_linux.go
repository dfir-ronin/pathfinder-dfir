//go:build linux
// +build linux

package osutil

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// OpenNoAtime opens a file with O_RDONLY|O_NOATIME to avoid updating st_atime
// on evidence files. Falls back to plain O_RDONLY if the caller lacks
// CAP_FOWNER (e.g. non-root reading a file owned by another user).
func OpenNoAtime(path string) (*os.File, error) {
	f, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOATIME, 0)
	if err != nil {
		return os.Open(path)
	}
	return f, nil
}

// ReadFileNoAtime reads a file without updating its atime.
func ReadFileNoAtime(path string) ([]byte, error) {
	f, err := OpenNoAtime(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ErrNotRegularFile is returned by OpenRegularNoBlock when the path resolves to
// a FIFO, device, directory, or other non-regular file.
var ErrNotRegularFile = errors.New("not a regular file")

// OpenRegularNoBlock opens path with O_NONBLOCK so opening a FIFO with no writer
// returns immediately instead of blocking forever, then fstats the resulting fd
// and rejects anything that is not a regular file. Checking the fd (not the path)
// also closes the open-after-Lstat TOCTOU window in callers.
func OpenRegularNoBlock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOATIME, 0)
	if err != nil {
		// Fall back without O_NOATIME (lacking CAP_FOWNER on another user's file).
		f, err = os.OpenFile(path, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
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
