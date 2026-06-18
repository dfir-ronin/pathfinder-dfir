//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pathfinder/internal/config"
)

func TestReadEvidenceFile_UnderCapNoTruncation(t *testing.T) {
	ctx, err := NewModuleContext(&config.Config{ReportDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cfg.conf")
	if err := os.WriteFile(p, []byte("line1\nline2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readEvidenceFile(ctx, p)
	if err != nil {
		t.Fatalf("readEvidenceFile: %v", err)
	}
	if string(data) != "line1\nline2\n" {
		t.Errorf("data = %q", data)
	}
}

func TestReadEvidenceFile_OverCapTruncatesAndLogs(t *testing.T) {
	ctx, err := NewModuleContext(&config.Config{ReportDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "huge.bin")
	if err := os.WriteFile(p, make([]byte, maxEvidenceFileBytes+100), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readEvidenceFile(ctx, p)
	if err != nil {
		t.Fatalf("readEvidenceFile: %v", err)
	}
	if int64(len(data)) != maxEvidenceFileBytes {
		t.Errorf("len = %d, want %d (capped)", len(data), maxEvidenceFileBytes)
	}
	logData, _ := os.ReadFile(filepath.Join(ctx.Dirs.Base, "commands.log"))
	if !strings.Contains(string(logData), "truncated") {
		t.Error("truncation was not recorded in commands.log")
	}
}

func TestReadEvidenceFile_MissingFileErrors(t *testing.T) {
	ctx, err := NewModuleContext(&config.Config{ReportDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceFile(ctx, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("expected error for missing file")
	}
}
