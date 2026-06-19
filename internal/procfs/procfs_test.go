//go:build linux

package procfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseModuleLine_WithTaint(t *testing.T) {
	line := "custom_lkm 16384 0 - Live 0xffffffffc0a12000 (OE)"
	fields := strings.Fields(line)
	mod, ok := parseModuleLine(fields)
	if !ok {
		t.Fatal("want ok=true")
	}
	if mod.Name != "custom_lkm" {
		t.Errorf("Name: got %q, want custom_lkm", mod.Name)
	}
	if mod.Taint != "(OE)" {
		t.Errorf("Taint: got %q, want (OE)", mod.Taint)
	}
}

func TestParseModuleLine_NoTaint(t *testing.T) {
	line := "ext4 933888 4 - Live 0xffffffffc0900000"
	fields := strings.Fields(line)
	mod, ok := parseModuleLine(fields)
	if !ok {
		t.Fatal("want ok=true")
	}
	if mod.Taint != "" {
		t.Errorf("Taint: got %q, want empty", mod.Taint)
	}
}

func TestParseStatus_ColonSpaceSeparator(t *testing.T) {
	data := []byte("Name:\tbash\nState: S (sleeping)\nPPid:\t1000\nUid: 0\t0\t0\t0\n")
	var p Process
	parseStatus(data, &p)
	if p.Name != "bash" {
		t.Errorf("Name=%q, want bash", p.Name)
	}
	if p.State != "S (sleeping)" {
		t.Errorf("State=%q, want 'S (sleeping)'", p.State)
	}
	if p.PPid != 1000 {
		t.Errorf("PPid=%d, want 1000", p.PPid)
	}
	if p.UID != 0 {
		t.Errorf("UID=%d, want 0", p.UID)
	}
}

func TestReadKernelVersion_ReturnsNonEmpty(t *testing.T) {
	v, err := ReadKernelVersion()
	if err != nil {
		t.Skipf("cannot read /proc/version: %v", err)
	}
	if v == "" {
		t.Error("want non-empty kernel version")
	}
}

func TestParseUtmpFile_CorrectTimestamp(t *testing.T) {
	// Build a synthetic 384-byte utmp record. The Linux utmp binary layout
	// (glibc compat32) places tv_sec at offset 340 and tv_usec at offset 344,
	// both as little-endian int32. This test encodes known values there and
	// asserts that parseUtmpFile returns the correct time.Time, catching any
	// future offset regression immediately.
	const recordSize = 384
	rec := make([]byte, recordSize)

	// ut_type = 7 (USER_PROCESS) at offset 0, little-endian int16
	rec[0] = 7
	rec[1] = 0

	// ut_user = "testuser" at offset 44
	copy(rec[44:76], "testuser")

	// tv_sec = 1000000000 (2001-09-09T01:46:40Z) at offset 340
	const wantSec = 1000000000
	rec[340] = wantSec & 0xFF
	rec[341] = (wantSec >> 8) & 0xFF
	rec[342] = (wantSec >> 16) & 0xFF
	rec[343] = (wantSec >> 24) & 0xFF

	// tv_usec = 123456 at offset 344
	const wantUsec = 123456
	rec[344] = wantUsec & 0xFF
	rec[345] = (wantUsec >> 8) & 0xFF
	rec[346] = (wantUsec >> 16) & 0xFF
	rec[347] = (wantUsec >> 24) & 0xFF

	f, err := os.CreateTemp("", "utmp-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(rec); err != nil {
		t.Fatal(err)
	}
	f.Close()

	records, err := parseUtmpFile(f.Name())
	if err != nil {
		t.Fatalf("parseUtmpFile: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}

	got := records[0].Time()
	wantTime := time.Unix(wantSec, wantUsec*1000).UTC()
	if !got.Equal(wantTime) {
		t.Errorf("Time() = %v, want %v\n(got TVSec=%d, want %d)", got, wantTime, records[0].TVSec, wantSec)
	}
}

func TestParseUtmpFile_TrailingPartial(t *testing.T) {
	rec := make([]byte, utmpRecordSize)
	rec[0] = utTypeUser
	copy(rec[44:76], "alice")
	data := append(append([]byte{}, rec...), make([]byte, 100)...) // one full record + 100 partial bytes
	f := filepath.Join(t.TempDir(), "wtmp")
	if err := os.WriteFile(f, data, 0600); err != nil {
		t.Fatal(err)
	}
	recs, err := parseUtmpFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].User != "alice" {
		t.Errorf("User=%q, want alice", recs[0].User)
	}
}

func TestParseStatRaw_NormalProcess(t *testing.T) {
	// Format: pid (comm) state ppid pgrp session tty tpgid flags
	//         minflt cminflt majflt cmajflt utime stime cutime cstime
	//         priority nice threads itrealvalue starttime ...
	// After last ')': fields[0]=state fields[11]=utime fields[12]=stime fields[19]=starttime
	raw := "123 (bash) S 1 123 123 0 -1 4194560 0 0 0 0 100 50 0 0 20 0 1 0 500 12345678 100 18446744073709551615"
	sf, err := parseStatRaw(raw)
	if err != nil {
		t.Fatalf("parseStatRaw: %v", err)
	}
	if sf.utime != 100 {
		t.Errorf("utime: got %d, want 100", sf.utime)
	}
	if sf.stime != 50 {
		t.Errorf("stime: got %d, want 50", sf.stime)
	}
	if sf.starttime != 500 {
		t.Errorf("starttime: got %d, want 500", sf.starttime)
	}
}

func TestParseStatRaw_ProcessNameWithParens(t *testing.T) {
	// Comm field contains ')' -- last-paren strategy must still produce correct fields
	raw := "456 (my)proc) S 2 456 456 0 -1 4194560 0 0 0 0 200 75 0 0 20 0 1 0 1000 12345678 50 18446744073709551615"
	sf, err := parseStatRaw(raw)
	if err != nil {
		t.Fatalf("parseStatRaw: %v", err)
	}
	if sf.utime != 200 {
		t.Errorf("utime: got %d, want 200", sf.utime)
	}
	if sf.starttime != 1000 {
		t.Errorf("starttime: got %d, want 1000", sf.starttime)
	}
}

func TestParseStatRaw_TooFewFields(t *testing.T) {
	raw := "1 (init) S 0"
	_, err := parseStatRaw(raw)
	if err == nil {
		t.Error("expected error for too-few fields")
	}
}

func TestParseStatFile_Self(t *testing.T) {
	sf, err := parseStatFile(os.Getpid())
	if err != nil {
		t.Skipf("cannot read /proc/%d/stat: %v", os.Getpid(), err)
	}
	if sf.starttime == 0 {
		t.Error("starttime should be non-zero for a running process")
	}
}

func TestReadProcessCWD_Self(t *testing.T) {
	cwd := ReadProcessCWD(os.Getpid())
	if cwd == "" {
		t.Error("expected non-empty CWD for current process")
	}
}

func TestReadProcessCWD_NonExistentPID(t *testing.T) {
	cwd := ReadProcessCWD(99999999)
	if cwd != "" {
		t.Errorf("expected empty string for non-existent PID, got %q", cwd)
	}
}

func TestReadProcessCPUMem_YoungProcess(t *testing.T) {
	// startTime = now -> startAge < 30s -> cpuPct must be 0
	cpuPct, _, err := ReadProcessCPUMem(os.Getpid(), time.Now())
	if err != nil {
		t.Skipf("cannot read /proc/%d: %v", os.Getpid(), err)
	}
	if cpuPct != 0 {
		t.Errorf("expected cpuPct=0 for startAge<30s, got %.2f", cpuPct)
	}
}

func TestReadProcessCPUMem_OldProcess(t *testing.T) {
	// startTime 5 minutes ago -- process is old enough to get a real reading
	startTime := time.Now().Add(-5 * time.Minute)
	cpuPct, rssKB, err := ReadProcessCPUMem(os.Getpid(), startTime)
	if err != nil {
		t.Skipf("cannot read /proc/%d: %v", os.Getpid(), err)
	}
	if cpuPct < 0 {
		t.Errorf("cpuPct must be >= 0, got %.2f", cpuPct)
	}
	if rssKB <= 0 {
		t.Errorf("rssKB must be > 0 for running process, got %d", rssKB)
	}
}

func TestReadProcessCPUMem_NonExistentPID(t *testing.T) {
	_, _, err := ReadProcessCPUMem(99999999, time.Now().Add(-1*time.Minute))
	if err == nil {
		t.Error("expected error for non-existent PID")
	}
}
