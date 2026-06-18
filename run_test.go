package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/modules"
)

func entryNames(es []moduleEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.name
	}
	return out
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestModuleTable_FrozenOrder(t *testing.T) {
	wantStaged := []string{"volatile", "audit", "journal", "users", "persistence", "baseline"}
	if got := entryNames(stagedModules); !eqStr(got, wantStaged) {
		t.Errorf("stagedModules order = %v, want %v", got, wantStaged)
	}
	wantStream := []string{"bodyfile", "sse", "deepscan", "ioc"}
	if got := entryNames(streamModules); !eqStr(got, wantStream) {
		t.Errorf("streamModules order = %v, want %v", got, wantStream)
	}
}

func TestModuleTable_Gating(t *testing.T) {
	all := append(append([]moduleEntry{}, stagedModules...), streamModules...)

	full := &config.Config{
		RunVolatile: true, RunAudit: true, RunJournal: true, RunUsers: true,
		RunPersistence: true, RunBaseline: true, RunBodyfile: true, RunDeepScan: true,
		IOCFile: "x",
	}
	for _, m := range all {
		if !m.enabled(full) {
			t.Errorf("%s: enabled(full)=false, want true", m.name)
		}
	}

	empty := &config.Config{}
	for _, m := range all {
		want := m.name == "sse" // sse always runs
		if m.enabled(empty) != want {
			t.Errorf("%s: enabled(empty)=%v, want %v", m.name, m.enabled(empty), want)
		}
	}
}

func swapTables(staged, stream []moduleEntry) func() {
	prevStaged, prevStream := stagedModules, streamModules
	stagedModules, streamModules = staged, stream
	return func() { stagedModules, streamModules = prevStaged, prevStream }
}

func TestRunModules_NonStealthRunsEnabledInOrderAndSetsZipWriter(t *testing.T) {
	var calls []string
	mk := func(name string, on bool) moduleEntry {
		return moduleEntry{name,
			func(*config.Config) bool { return on },
			func(*modules.ModuleContext) { calls = append(calls, name) },
			func(*modules.ModuleContext) string { return "" }}
	}
	defer swapTables(
		[]moduleEntry{mk("a", true), mk("b", false), mk("c", true)},
		[]moduleEntry{mk("d", true), mk("e", false)},
	)()

	zw := zip.NewWriter(io.Discard)
	ctx := &modules.ModuleContext{}
	skips := runModules(ctx, &config.Config{}, zw, "")

	if got := calls; !eqStr(got, []string{"a", "c", "d"}) {
		t.Errorf("call order = %v, want [a c d]", got)
	}
	if ctx.ZipWriter != zw {
		t.Errorf("non-stealth did not set ctx.ZipWriter")
	}
	if len(skips) != 0 {
		t.Errorf("non-stealth skips = %v, want none", skips)
	}
}

func TestRunModules_StealthFlushesAllStagedDirsButRunsOnlyEnabled(t *testing.T) {
	base := t.TempDir()
	mkDir := func(name string) string {
		d := filepath.Join(base, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	dirA, dirB := mkDir("A"), mkDir("B")

	var ran []string
	mk := func(name string, on bool, dir string) moduleEntry {
		return moduleEntry{name,
			func(*config.Config) bool { return on },
			func(*modules.ModuleContext) { ran = append(ran, name) },
			func(*modules.ModuleContext) string { return dir }}
	}
	defer swapTables(
		[]moduleEntry{mk("a", true, dirA), mk("b", false, dirB)},
		nil,
	)()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	ctx := &modules.ModuleContext{}
	runModules(ctx, &config.Config{Stealth: true}, zw, base)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if !eqStr(ran, []string{"a"}) {
		t.Errorf("ran = %v, want [a] (b is disabled, must not run)", ran)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, fe := range zr.File {
		entries = append(entries, fe.Name)
	}
	hasA, hasB := false, false
	for _, e := range entries {
		if filepath.ToSlash(e) == "A/f.txt" {
			hasA = true
		}
		if filepath.ToSlash(e) == "B/f.txt" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("flush gated by run flag: entries=%v, want both A/f.txt and B/f.txt", entries)
	}
}
