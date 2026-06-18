//go:build !linux
// +build !linux

package sysfs

import (
	"os"
)

// IsImmutable returns true if the file at path has the immutable attribute set.
// On non-Linux platforms, this always returns false as immutable attributes are
// not supported.
func IsImmutable(path string) (bool, error) {
	// Check that the file exists
	_, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return false, nil
}

// ImmutableResult holds the result for a single path
type ImmutableResult struct {
	Path      string
	Immutable bool
	Err       string
}

// ScanImmutable walks the given root directories and returns files with the
// immutable attribute. On non-Linux platforms, this always returns an empty slice.
func ScanImmutable(roots []string) []ImmutableResult {
	return []ImmutableResult{}
}
