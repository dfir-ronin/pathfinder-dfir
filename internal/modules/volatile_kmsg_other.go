//go:build !linux

package modules

import "errors"

func readKmsgLines() ([]string, bool, error) {
	return nil, false, errors.New("kmsg not available on this platform")
}
