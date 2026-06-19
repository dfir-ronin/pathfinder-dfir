package logutil

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shrink caps for fast tests, restore after.
func withSmallCaps(t *testing.T, perSource, total int64) {
	t.Helper()
	op, ot := maxSourceBytes, maxTotalBytes
	maxSourceBytes, maxTotalBytes = perSource, total
	t.Cleanup(func() { maxSourceBytes, maxTotalBytes = op, ot })
}

func TestReadWithRotations_CapsPlainFile(t *testing.T) {
	withSmallCaps(t, 10, 100)
	base := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(base, bytes.Repeat([]byte("A"), 50), 0600); err != nil {
		t.Fatal(err)
	}
	out, _ := ReadWithRotations(base)
	if strings.Count(out, "A") > 10 {
		t.Fatalf("expected at most 10 'A' bytes after cap, got %d", strings.Count(out, "A"))
	}
	if !strings.Contains(out, "truncated") {
		t.Fatalf("expected a truncation marker, got: %q", out)
	}
}

func TestReadWithRotations_CapsGzipBomb(t *testing.T) {
	withSmallCaps(t, 10, 100)
	dir := t.TempDir()
	base := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(base, []byte("head\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(dir, "auth.log.2.gz")
	f, err := os.Create(gz)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write(bytes.Repeat([]byte("B"), 100*1024)); err != nil {
		t.Fatal(err)
	}
	gw.Close()
	f.Close()

	out, _ := ReadWithRotations(base)
	if strings.Count(out, "B") > 10 {
		t.Fatalf("gzip content not capped: got %d 'B' bytes", strings.Count(out, "B"))
	}
}

func writeGz(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	gw.Close()
	f.Close()
}

func TestReadWithRotations_ReadsDotOneGz(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(base, []byte("current\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeGz(t, base+".1.gz", "rotated-one\n")
	out, _ := ReadWithRotations(base)
	if !strings.Contains(out, "rotated-one") {
		t.Fatalf(".1.gz not read: %q", out)
	}
}

func TestReadWithRotations_StatusStates(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(base, []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// .1 absent; .1.gz present but not valid gzip -> error
	if err := os.WriteFile(base+".1.gz", []byte("not gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	_, st := ReadWithRotations(base)
	states := map[string]string{}
	for _, s := range st {
		states[s.Path] = s.State
	}
	if states[base] != "read" {
		t.Errorf("base state=%q, want read", states[base])
	}
	if states[base+".1"] != "absent" {
		t.Errorf(".1 state=%q, want absent", states[base+".1"])
	}
	if states[base+".1.gz"] != "error" {
		t.Errorf(".1.gz state=%q, want error", states[base+".1.gz"])
	}
}
