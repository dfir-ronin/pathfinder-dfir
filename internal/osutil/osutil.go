package osutil

import (
	"fmt"
	"io"
	"strings"
)

// IsCommentOrBlank reports whether a config line is blank or a '#'-comment
// after trimming leading whitespace. Callers whose comment syntax differs
// (';', '//') must not use this.
func IsCommentOrBlank(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}

// ReadFileCapped reads up to max bytes from path without updating its atime
// (via OpenNoAtime). The second return value is true when the file was longer
// than max, in which case the returned slice holds exactly the first max bytes.
// It reads max+1 bytes through an io.LimitReader so it works on /proc files,
// which report st_size == 0 and defeat any os.Stat-based size gate.
func ReadFileCapped(path string, max int64) ([]byte, bool, error) {
	f, err := OpenNoAtime(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

// ReadFileRegularNoBlock opens path via OpenRegularNoBlock (rejecting FIFOs,
// devices, and directories without blocking) and returns its full contents.
func ReadFileRegularNoBlock(path string) ([]byte, error) {
	f, err := OpenRegularNoBlock(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// FormatFileSize formats a byte count using binary (IEC) units, matching the
// MiB convention used for upload sizing in internal/cloud.
func FormatFileSize(n int64) string {
	const (
		KiB = int64(1024)
		MiB = 1024 * KiB
		GiB = 1024 * MiB
	)
	switch {
	case n >= GiB:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(GiB))
	case n >= MiB:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(MiB))
	case n >= KiB:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(KiB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
