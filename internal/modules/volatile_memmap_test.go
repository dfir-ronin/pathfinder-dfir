//go:build linux

package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pathfinder/internal/output"
)

// Map line format: address perms offset dev inode [pathname]
// Example: 7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /usr/lib/libc.so.6

func TestClassifyMapLine_ExecDeleted(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /tmp/evil.so (deleted)"
	kind, path, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true, got false")
	}
	if kind != anomalyExecDeleted {
		t.Errorf("kind: want anomalyExecDeleted (%d), got %d", anomalyExecDeleted, kind)
	}
	if path != "/tmp/evil.so (deleted)" {
		t.Errorf("path: got %q", path)
	}
}

func TestClassifyMapLine_Memfd(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 00:00 0 memfd:secret (deleted)"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyExecMemfd {
		t.Errorf("kind: want anomalyExecMemfd (%d), got %d", anomalyExecMemfd, kind)
	}
}

func TestClassifyMapLine_StagingPath(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /dev/shm/payload.so"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyExecStagingPath {
		t.Errorf("kind: want anomalyExecStagingPath (%d), got %d", anomalyExecStagingPath, kind)
	}
}

func TestClassifyMapLine_RWXFileBacked(t *testing.T) {
	line := "7f1234000000-7f1234001000 rwxp 00000000 fd:01 123456 /usr/local/lib/evil.so"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyRWXFileBacked {
		t.Errorf("kind: want anomalyRWXFileBacked (%d), got %d", anomalyRWXFileBacked, kind)
	}
}

func TestClassifyMapLine_UserHome(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /home/alice/.local/lib/mod.so"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyExecUserHome {
		t.Errorf("kind: want anomalyExecUserHome (%d), got %d", anomalyExecUserHome, kind)
	}
}

func TestClassifyMapLine_RootHome(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /root/.local/lib/mod.so"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyExecUserHome {
		t.Errorf("kind: want anomalyExecUserHome for /root/ path, got %d", kind)
	}
}

func TestClassifyMapLine_LegitLib(t *testing.T) {
	line := "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /usr/lib/x86_64-linux-gnu/libc.so.6"
	_, _, ok := classifyMapLine(line)
	if ok {
		t.Error("want ok=false for legitimate system library")
	}
}

func TestClassifyMapLine_NoExecNonRWX(t *testing.T) {
	line := "7f1234000000-7f1234001000 r--p 00000000 fd:01 123456 /tmp/evil.so"
	_, _, ok := classifyMapLine(line)
	if ok {
		t.Error("want ok=false: no exec bit, not rwxp")
	}
}

func TestClassifyMapLine_RWXPrioritisedOverUserHome(t *testing.T) {
	// /home path with rwxp: should be rwxpFileBacked (higher priority) not execUserHome
	line := "7f1234000000-7f1234001000 rwxp 00000000 fd:01 123456 /home/alice/lib/evil.so"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Fatal("want ok=true")
	}
	if kind != anomalyRWXFileBacked {
		t.Errorf("kind: rwxp must beat execUserHome; got %d", kind)
	}
}

func TestClassifyMapLine_DeletedFileStillExists_Suppressed(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "still_here.so")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("7f00-7f01 r-xp 00000000 fd:01 1 %s (deleted)", f)
	_, _, ok := classifyMapLine(line)
	if ok {
		t.Error("want false: file still exists on disk, must not be anomaly")
	}
}

func TestClassifyMapLine_DeletedFileGenuinelyMissing_Reported(t *testing.T) {
	line := "7f00-7f01 r-xp 00000000 fd:01 1 /nonexistent/does/not/exist.so (deleted)"
	kind, _, ok := classifyMapLine(line)
	if !ok {
		t.Error("want true: file genuinely absent")
	}
	if kind != anomalyExecDeleted {
		t.Errorf("want anomalyExecDeleted, got %d", kind)
	}
}

func TestMapAnomalySeverity_RWXFileBacked_IsMedium(t *testing.T) {
	if got := mapAnomalySeverity(anomalyRWXFileBacked); got != output.MEDIUM {
		t.Errorf("anomalyRWXFileBacked: want MEDIUM, got %v", got)
	}
}

func TestMapAnomalySeverity_ExecMemfd_IsHigh(t *testing.T) {
	if got := mapAnomalySeverity(anomalyExecMemfd); got != output.HIGH {
		t.Errorf("anomalyExecMemfd: want HIGH, got %v", got)
	}
}

func TestMapAnomalySeverity_ExecDeleted_IsHigh(t *testing.T) {
	if got := mapAnomalySeverity(anomalyExecDeleted); got != output.HIGH {
		t.Errorf("anomalyExecDeleted: want HIGH, got %v", got)
	}
}

func TestMapAnomalyKindString(t *testing.T) {
	cases := map[mapAnomalyKind]string{
		anomalyExecDeleted:     "execDeleted",
		anomalyExecMemfd:       "execMemfd",
		anomalyExecStagingPath: "execStagingPath",
		anomalyRWXFileBacked:   "rwxpFileBacked",
		anomalyExecUserHome:    "execUserHome",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("kind %d: String()=%q, want %q", k, got, want)
		}
	}
}

func TestDescribeMapKinds_Empty(t *testing.T) {
	if got := describeMapKinds(nil); got != "" {
		t.Errorf("empty hits: want %q, got %q", "", got)
	}
}

func TestDescribeMapKinds_SingleKind(t *testing.T) {
	hits := []mapHit{{Kind: anomalyExecMemfd}}
	if got := describeMapKinds(hits); got != "execMemfd" {
		t.Errorf("single kind: want %q, got %q", "execMemfd", got)
	}
}

func TestDescribeMapKinds_MultipleKinds(t *testing.T) {
	hits := []mapHit{{Kind: anomalyExecDeleted}, {Kind: anomalyExecMemfd}}
	want := "execDeleted + execMemfd"
	if got := describeMapKinds(hits); got != want {
		t.Errorf("multiple kinds: want %q, got %q", want, got)
	}
}

func TestDescribeMapKinds_Deduplication(t *testing.T) {
	hits := []mapHit{{Kind: anomalyRWXFileBacked}, {Kind: anomalyRWXFileBacked}}
	want := "rwxpFileBacked"
	if got := describeMapKinds(hits); got != want {
		t.Errorf("dedup: want %q, got %q", want, got)
	}
}

func TestDescribeMapKinds_CanonicalOrder(t *testing.T) {
	// Input order is reversed vs canonical; output must follow canonical order.
	hits := []mapHit{{Kind: anomalyExecUserHome}, {Kind: anomalyExecDeleted}}
	want := "execDeleted + execUserHome"
	if got := describeMapKinds(hits); got != want {
		t.Errorf("canonical order: want %q, got %q", want, got)
	}
}

func TestHighestMapSeverity_EmptySlice(t *testing.T) {
	if got := highestMapSeverity(nil); got != output.MEDIUM {
		t.Errorf("empty: want MEDIUM, got %v", got)
	}
}

func TestHighestMapSeverity_AllMedium(t *testing.T) {
	hits := []mapHit{{Kind: anomalyRWXFileBacked}, {Kind: anomalyExecUserHome}}
	if got := highestMapSeverity(hits); got != output.MEDIUM {
		t.Errorf("all medium kinds: want MEDIUM, got %v", got)
	}
}

func TestHighestMapSeverity_HasHighKind(t *testing.T) {
	hits := []mapHit{{Kind: anomalyRWXFileBacked}, {Kind: anomalyExecMemfd}}
	if got := highestMapSeverity(hits); got != output.HIGH {
		t.Errorf("mixed: want HIGH, got %v", got)
	}
}

func TestHighestMapSeverity_AllHigh(t *testing.T) {
	hits := []mapHit{{Kind: anomalyExecDeleted}, {Kind: anomalyExecMemfd}}
	if got := highestMapSeverity(hits); got != output.HIGH {
		t.Errorf("all high kinds: want HIGH, got %v", got)
	}
}

func TestDescribeMapKinds_IncludesStagingPath(t *testing.T) {
	hits := []mapHit{{Kind: anomalyExecStagingPath}}
	if got := describeMapKinds(hits); got != "execStagingPath" {
		t.Errorf("stagingPath: want %q, got %q", "execStagingPath", got)
	}
}

func TestHighestMapSeverity_StagingPathIsHigh(t *testing.T) {
	hits := []mapHit{{Kind: anomalyExecStagingPath}}
	if got := highestMapSeverity(hits); got != output.HIGH {
		t.Errorf("stagingPath: want HIGH, got %v", got)
	}
}
