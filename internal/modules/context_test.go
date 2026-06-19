//go:build linux

package modules

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/output"
)

func TestNewModuleContext_SetsSelfPath(t *testing.T) {
	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	if ctx.SelfPath == "" {
		t.Error("SelfPath must be non-empty after NewModuleContext")
	}
}

func TestNewModuleContext_SetsOutputPrefix(t *testing.T) {
	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	want := filepath.Join(cfg.ReportDir, "pathfinder-")
	if ctx.OutputPrefix != want {
		t.Errorf("OutputPrefix = %q, want %q", ctx.OutputPrefix, want)
	}
}

func TestNewSectionWriter_StreamsToZipWhenZipWriterSet(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx.ZipWriter = zw

	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "test.txt", "LABEL", "source")
	w.Write("streamed content\n")
	w.Close()
	zw.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	var found bool
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "test.txt") {
			found = true
		}
	}
	if !found {
		var names []string
		for _, f := range zr.File {
			names = append(names, f.Name)
		}
		t.Errorf("test.txt not found in zip entries: %v", names)
	}

	// Confirm no file was created on disk
	if _, err := os.Stat(filepath.Join(ctx.Dirs.Volatile, "test.txt")); err == nil {
		t.Error("file should not exist on disk when ZipWriter is set")
	}
}

func TestNewSectionWriter_WritesToDiskWhenNoZipWriter(t *testing.T) {
	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// ZipWriter is nil by default

	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "disk.txt", "LABEL", "source")
	w.Write("on disk\n")
	w.Close()

	data, err := os.ReadFile(filepath.Join(ctx.Dirs.Volatile, "disk.txt"))
	if err != nil {
		t.Fatalf("expected file on disk: %v", err)
	}
	if !strings.Contains(string(data), "on disk") {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestNewSectionWriter_MultipleZipWritersAllHaveContent(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx.ZipWriter = zw

	names := []string{"a.txt", "b.txt", "c.txt"}
	writers := make([]*output.Writer, len(names))
	for i, name := range names {
		writers[i] = newSectionWriter(ctx, ctx.Dirs.Volatile, name, "LABEL", "src")
	}
	for i, w := range writers {
		w.Write("content-%d\n", i)
	}
	for _, w := range writers {
		w.Close()
	}
	zw.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	entryContent := make(map[string]string)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		entryContent[filepath.Base(f.Name)] = string(data)
	}
	for i, name := range names {
		content, ok := entryContent[name]
		if !ok {
			t.Errorf("zip entry %s missing", name)
			continue
		}
		want := fmt.Sprintf("content-%d", i)
		if !strings.Contains(content, want) {
			t.Errorf("zip entry %s: want %q in content, got: %q", name, want, content)
		}
	}
}

func TestWalkFiles_SkipsUserSuppliedFiles(t *testing.T) {
	dir := t.TempDir()
	normalFile := filepath.Join(dir, "normal.txt")
	iocFile := filepath.Join(dir, "ioc.txt")

	if err := os.WriteFile(normalFile, []byte("normal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iocFile, []byte("10.0.0.1\nevildomain.com"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{ReportDir: t.TempDir(), IOCFile: iocFile}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}

	var visited []string
	walkFiles(ctx, dir, func(path string, info os.FileInfo) {
		visited = append(visited, path)
	})

	for _, v := range visited {
		if v == iocFile {
			t.Errorf("walkFiles visited user-supplied IOC file %q; expected skip", iocFile)
		}
	}

	found := false
	for _, v := range visited {
		if v == normalFile {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("walkFiles did not visit normal file %q", normalFile)
	}
}
