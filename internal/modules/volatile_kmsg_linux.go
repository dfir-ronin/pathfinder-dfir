//go:build linux

package modules

import (
	"strings"
	"syscall"
)

const (
	// maxKmsgBytes caps total bytes drained from /dev/kmsg. The kernel ring is
	// bounded, but a hostile module can spam it; this is a hard ceiling.
	maxKmsgBytes = 8 << 20
	// maxKmsgRecords caps the number of records retained, independent of size.
	maxKmsgRecords = 100000
)

func readKmsgLines() ([]string, bool, error) {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer syscall.Close(fd)

	buf := make([]byte, 8192)
	var lines []string
	var total int
	var capped bool
	for {
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			lines = append(lines, strings.TrimRight(string(buf[:n]), "\n"))
			total += n
			if total >= maxKmsgBytes || len(lines) >= maxKmsgRecords {
				capped = true
				break
			}
		}
		if err == syscall.EAGAIN {
			break // drained: non-blocking read has nothing left
		}
		if err == syscall.EPIPE {
			continue // record overwritten mid-read; skip and keep going
		}
		if err != nil {
			return lines, capped, err // surface real read errors instead of silent break
		}
	}
	return lines, capped, nil
}
