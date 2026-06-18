package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTool_FindsExecutableInTrustedDir(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho hi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveTool("mytool", []string{dir})
	if err != nil {
		t.Fatalf("resolveTool error: %v", err)
	}
	if got != bin {
		t.Fatalf("resolveTool = %q, want %q", got, bin)
	}
}

func TestResolveTool_IgnoresToolOutsideTrustedDirs(t *testing.T) {
	untrusted := t.TempDir()
	if err := os.WriteFile(filepath.Join(untrusted, "evil"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTool("evil", []string{t.TempDir()}); err == nil {
		t.Fatalf("resolveTool found a tool outside trusted dirs, want error")
	}
}

func TestResolveTool_RejectsPathSeparator(t *testing.T) {
	if _, err := resolveTool("../bin/sh", []string{t.TempDir()}); err == nil {
		t.Fatalf("resolveTool accepted a name with a path separator, want error")
	}
}

func TestResolveTool_SkipsNonExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTool("data", []string{dir}); err == nil {
		t.Fatalf("resolveTool returned a non-executable file, want error")
	}
}
