package logutil

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/pathfinder/internal/osutil"
)

// MaxRotations is the maximum number of gzip-compressed rotations checked
// beyond the plain .1 rotation (i.e. checks .2.gz through .N.gz).
const MaxRotations = 5

// Read caps. Vars (not consts) so tests can shrink them. On a hostile host an
// attacker can plant a multi-GB or high-ratio log; these caps bound both the
// bytes read per source and the total held in memory so collection cannot be
// OOM-killed mid-run.
var (
	maxSourceBytes int64 = 100 << 20 // 100 MB per file/rotation
	maxTotalBytes  int64 = 200 << 20 // 200 MB across all rotations combined
)

// SourceStatus records the outcome of reading one rotation source so callers can
// log evidence gaps instead of silently treating a read error as absence.
type SourceStatus struct {
	Path  string
	State string // "read", "absent", or "error"
	Err   string
}

// ReadWithRotations reads a log file and its standard logrotate rotations:
//   - basePath          (current log, e.g. /var/log/auth.log)
//   - basePath.1        (first plain-text rotation)
//   - basePath.1.gz     (first rotation, already compressed)
//   - basePath.2.gz ... basePath.N.gz  (further compressed rotations)
//
// Files are opened with O_NOATIME to preserve evidence atime. Reads are capped
// per source and in aggregate; a truncated source is marked inline. Alongside
// the concatenated text, it returns a per-source status slice so callers can
// distinguish a source that was absent from one that errored while reading.
func ReadWithRotations(basePath string) (string, []SourceStatus) {
	var sb strings.Builder
	var statuses []SourceStatus
	remaining := maxTotalBytes

	add := func(text string, truncated bool) {
		if sb.Len() > 0 && len(text) > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(text)
		if truncated {
			sb.WriteString("\n[pathfinder: log truncated at read cap]\n")
		}
		remaining -= int64(len(text))
	}

	probe := func(path string, gzipped bool) {
		if remaining <= 0 {
			return
		}
		var (
			text  string
			trunc bool
			err   error
		)
		if gzipped {
			text, trunc, err = readGzipCapped(path, min64(maxSourceBytes, remaining))
		} else {
			text, trunc, err = readCapped(path, min64(maxSourceBytes, remaining))
		}
		switch {
		case err == nil:
			add(text, trunc)
			statuses = append(statuses, SourceStatus{Path: path, State: "read"})
		case errors.Is(err, fs.ErrNotExist):
			statuses = append(statuses, SourceStatus{Path: path, State: "absent"})
		default:
			statuses = append(statuses, SourceStatus{Path: path, State: "error", Err: err.Error()})
		}
	}

	probe(basePath, false)
	probe(basePath+".1", false)
	probe(basePath+".1.gz", true)
	for i := 2; i <= MaxRotations && remaining > 0; i++ {
		probe(fmt.Sprintf("%s.%d.gz", basePath, i), true)
	}

	return sb.String(), statuses
}

// readCapped reads up to limit bytes from path without updating atime.
// The second return value is true when the file was longer than the limit.
func readCapped(path string, limit int64) (string, bool, error) {
	data, trunc, err := osutil.ReadFileCapped(path, limit)
	if err != nil {
		return "", false, err
	}
	return string(data), trunc, nil
}

// readGzipCapped decompresses up to limit bytes. The LimitReader sits on the
// gzip reader's output, so a high-ratio bomb cannot expand past the cap.
func readGzipCapped(path string, limit int64) (string, bool, error) {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", false, err
	}
	defer gr.Close()
	data, err := io.ReadAll(io.LimitReader(gr, limit+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > limit {
		return string(data[:limit]), true, nil
	}
	return string(data), false, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
