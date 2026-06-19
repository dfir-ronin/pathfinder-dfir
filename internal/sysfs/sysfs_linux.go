//go:build linux
// +build linux

package sysfs

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// FS_IOC_GETFLAGS ioctl for reading file attributes (ext2/3/4, xfs)
// Value: 0x80086601 on x86_64 Linux
const (
	fsIocGetFlags = 0x80086601
	fsImmutableFL = 0x00000010
)

// IsImmutable returns true if the file at path has the immutable attribute set.
// Requires root. Falls back gracefully if the ioctl is not supported.
func IsImmutable(path string) (bool, error) {
	// O_NONBLOCK so a FIFO/device with no peer cannot block the open forever.
	// O_NOATIME so probing the attribute does not stamp the file's access time.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOATIME, 0)
	if err != nil {
		// O_NOATIME requires ownership/CAP_FOWNER; retry without it.
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return false, err
		}
	}
	defer f.Close()

	var flags int32
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		fsIocGetFlags,
		uintptr(unsafe.Pointer(&flags)),
	)
	if errno != 0 {
		return false, errno
	}
	return flags&fsImmutableFL != 0, nil
}

// ImmutableResult holds the result for a single path
type ImmutableResult struct {
	Path      string
	Immutable bool
	Err       string
}

// ScanImmutable walks the given root directories and returns files with the
// immutable attribute. Skips /proc, /sys, /run, and /dev automatically.
func ScanImmutable(roots []string) []ImmutableResult {
	var results []ImmutableResult
	skip := map[string]bool{"/proc": true, "/sys": true, "/run": true, "/dev": true}

	for _, root := range roots {
		if skip[root] {
			continue
		}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return filepath.SkipDir
			}
			for skipped := range skip {
				if path == skipped || (len(path) > len(skipped) && path[:len(skipped)] == skipped && path[len(skipped)] == '/') {
					return filepath.SkipDir
				}
			}

			// The immutable attribute only applies to regular files and
			// directories; skip FIFOs, sockets, and devices entirely so a
			// planted special file cannot stall the walk.
			if !info.Mode().IsRegular() && !info.IsDir() {
				return nil
			}
			immutable, err := IsImmutable(path)
			if err != nil {
				return nil // ignore errors, continue walking
			}
			if immutable {
				results = append(results, ImmutableResult{
					Path:      path,
					Immutable: true,
				})
			}
			return nil
		})
	}
	return results
}
