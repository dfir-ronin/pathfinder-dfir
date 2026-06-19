//go:build linux

package modules

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pathfinder/internal/config"
)

func makeTestCtx(t *testing.T) *ModuleContext {
	t.Helper()
	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	return ctx
}

func makeTestCtxWithManifest(t *testing.T, manifestPath string) *ModuleContext {
	t.Helper()
	cfg := &config.Config{ReportDir: t.TempDir(), ManifestPath: manifestPath}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	return ctx
}

func openSSEZip(t *testing.T, ctx *ModuleContext) *zip.ReadCloser {
	t.Helper()
	if ctx.SSEZipPath == "" {
		t.Fatal("ctx.SSEZipPath is empty — RunSSEPackage did not produce a zip")
	}
	zr, err := zip.OpenReader(ctx.SSEZipPath)
	if err != nil {
		t.Fatalf("open SSE zip %s: %v", ctx.SSEZipPath, err)
	}
	t.Cleanup(func() { zr.Close() })
	return zr
}

func zipHasEntry(zr *zip.ReadCloser, name string) bool {
	for _, f := range zr.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

func TestWriteArtifactBlock_NoSkipsNoErrors(t *testing.T) {
	al := newSseArtifactLog("bash_history")
	al.collected = 3
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	writeArtifactBlock(w, al)
	w.Flush()
	got := buf.String()
	for _, want := range []string{
		"=== ARTIFACT: bash_history ===",
		"Collected : 3",
		"Skipped   : 0",
		"Errors    : 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestWriteArtifactBlock_SkipsGroupedByReason(t *testing.T) {
	al := newSseArtifactLog("system_files")
	al.collected = 10
	al.skippedByReason["excluded by path pattern"] = 5
	al.skippedByReason["exceeds max_file_size"] = 2
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	writeArtifactBlock(w, al)
	w.Flush()
	got := buf.String()
	for _, want := range []string{
		"Skipped   : 7",
		"excluded by path pattern",
		"exceeds max_file_size",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Higher count must appear before lower count
	iPath := strings.Index(got, "excluded by path pattern")
	iSize := strings.Index(got, "exceeds max_file_size")
	if iPath >= iSize {
		t.Errorf("expected path pattern (count=5) before max_file_size (count=2), got:\n%s", got)
	}
}

func TestWriteArtifactBlock_ErrorsListedPerFile(t *testing.T) {
	al := newSseArtifactLog("ssh_keys")
	al.errors = []sseLogEntry{{path: "/root/.ssh/id_rsa", reason: "permission denied"}}
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	writeArtifactBlock(w, al)
	w.Flush()
	got := buf.String()
	for _, want := range []string{
		"Errors    : 1",
		"/root/.ssh/id_rsa — permission denied",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRunSSEPackage_NoManifest(t *testing.T) {
	ctx := makeTestCtx(t)
	RunSSEPackage(ctx) // must not panic; SSEZipPath stays empty
	if ctx.SSEZipPath != "" {
		t.Error("SSEZipPath should be empty when no manifest is set")
	}
}

func TestRunSSEPackage_CollectsSingleFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "auth.log")
	os.WriteFile(src, []byte("log data"), 0600)

	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src)
	manifestPath := writeTempManifest(t, yml)

	ctx := makeTestCtxWithManifest(t, manifestPath)
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	entryName := "[root_dir]/" + strings.TrimPrefix(filepath.ToSlash(src), "/")
	if !zipHasEntry(zr, entryName) {
		t.Errorf("expected entry %q in SSE zip", entryName)
	}
}

func TestRunSSEPackage_OutputDirectory(t *testing.T) {
	src := filepath.Join(t.TempDir(), "auth.log")
	os.WriteFile(src, []byte("log"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    output_directory: /files/logs
`, src)
	manifestPath := writeTempManifest(t, yml)
	ctx := makeTestCtxWithManifest(t, manifestPath)
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/files/logs/auth.log") {
		t.Error("expected entry [root_dir]/files/logs/auth.log in SSE zip")
	}
}

func TestRunSSEPackage_OutputFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "original.log")
	os.WriteFile(src, []byte("log"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    output_directory: /files/logs
    output_file: renamed.log
`, src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/files/logs/renamed.log") {
		t.Error("expected entry [root_dir]/files/logs/renamed.log in SSE zip")
	}
}

func TestRunSSEPackage_CollectsDirectory(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "cron.service"), []byte("svc"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    output_directory: /files/system
`, srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/files/system/cron.service") {
		t.Error("expected entry [root_dir]/files/system/cron.service in SSE zip")
	}
}

func TestRunSSEPackage_CollectsDirMirrorsPath(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "hosts"), []byte("127.0.0.1"), 0600)

	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	entryName := "[root_dir]/" + strings.TrimPrefix(filepath.ToSlash(filepath.Join(srcDir, "hosts")), "/")
	if !zipHasEntry(zr, entryName) {
		t.Errorf("expected entry %q in SSE zip (path mirrored)", entryName)
	}
}

func TestRunSSEPackage_StoresHashesOnContext(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f.txt")
	os.WriteFile(src, []byte("data"), 0600)

	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	if ctx.SSEZipPath == "" {
		t.Fatal("SSEZipPath is empty")
	}
	if len(ctx.SSEZipSHA256) != 64 {
		t.Errorf("SSEZipSHA256 = %q, want 64-char hex", ctx.SSEZipSHA256)
	}
	if ctx.SSEArtifacts != 1 {
		t.Errorf("SSEArtifacts = %d, want 1", ctx.SSEArtifacts)
	}
	if ctx.SSECollected != 1 {
		t.Errorf("SSECollected = %d, want 1", ctx.SSECollected)
	}
}

func TestRunSSEPackage_AnyVersionAccepted(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("data"), 0600)

	yml := fmt.Sprintf("version: 2.0\nartifacts:\n  - collector: file\n    path: %s\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	entryName := "[root_dir]/" + strings.TrimPrefix(filepath.ToSlash(src), "/")
	if !zipHasEntry(zr, entryName) {
		t.Errorf("version 2.0 manifest should be accepted; entry %q missing", entryName)
	}
}

func TestRunSSEPackage_SkipsUnknownCollector(t *testing.T) {
	yml := "version: 1.0\nartifacts:\n  - collector: command\n    path: /etc/passwd\n"
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx) // must not panic
}

func TestRunSSEPackage_InvalidYAML(t *testing.T) {
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, ":::not yaml:::"))
	RunSSEPackage(ctx) // must not panic; SSEZipPath stays empty
	if ctx.SSEZipPath != "" {
		t.Error("invalid YAML should not produce a zip")
	}
}

func TestRunSSEPackage_SkipsMissingPath(t *testing.T) {
	yml := "version: 1.0\nartifacts:\n  - collector: file\n    path: /nonexistent/file/that/does/not/exist.txt\n"
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx) // must not panic
}

func writeTempManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunSSEPackage_Dir_CollectsFromMultipleManifests(t *testing.T) {
	src1 := filepath.Join(t.TempDir(), "file1.txt")
	src2 := filepath.Join(t.TempDir(), "file2.txt")
	os.WriteFile(src1, []byte("a"), 0600)
	os.WriteFile(src2, []byte("b"), 0600)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"),
		[]byte(fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src1)), 0600)
	os.WriteFile(filepath.Join(dir, "b.yaml"),
		[]byte(fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src2)), 0600)

	ctx := makeTestCtxWithManifest(t, dir)
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src1), "/")) {
		t.Errorf("entry for src1 missing from SSE zip")
	}
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src2), "/")) {
		t.Errorf("entry for src2 missing from SSE zip")
	}
}

func TestRunSSEPackage_Dir_Recursive(t *testing.T) {
	src := filepath.Join(t.TempDir(), "data.txt")
	os.WriteFile(src, []byte("x"), 0600)

	dir := t.TempDir()
	sub := filepath.Join(dir, "system")
	os.MkdirAll(sub, 0700)
	os.WriteFile(filepath.Join(sub, "system.yaml"),
		[]byte(fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src)), 0600)

	ctx := makeTestCtxWithManifest(t, dir)
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
		t.Errorf("entry from subdir manifest missing from SSE zip")
	}
}

func TestRunSSEPackage_SupportedOS_LinuxIncluded(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("data"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    supported_os: [linux, macos]\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
		t.Error("artifact with supported_os including linux should be collected")
	}
}

func TestRunSSEPackage_SupportedOS_AllIncluded(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("data"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    supported_os: [all]\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
		t.Error("artifact with supported_os: [all] should be collected")
	}
}

func TestRunSSEPackage_SupportedOS_NotLinux(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("data"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    supported_os: [macos, freebsd]\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	// No zip produced (all artifacts skipped) or zip exists but entry absent.
	if ctx.SSEZipPath != "" {
		zr := openSSEZip(t, ctx)
		if zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
			t.Error("artifact for non-Linux OS should not be collected")
		}
	}
}

func TestRunSSEPackage_SupportedOS_Empty(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("data"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
		t.Error("artifact with no supported_os should be collected")
	}
}

func TestRunSSEPackage_MaxDepth(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "root.log"), []byte("r"), 0600)
	sub := filepath.Join(srcDir, "sub")
	os.MkdirAll(sub, 0700)
	os.WriteFile(filepath.Join(sub, "deep.log"), []byte("d"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    output_directory: /out
    max_depth: 1
`, srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/root.log") {
		t.Error("root.log should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/sub/deep.log") {
		t.Error("deep.log should not be collected with max_depth=1")
	}
}

func TestRunSSEPackage_NamePattern(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "access.log"), []byte("l"), 0600)
	os.WriteFile(filepath.Join(srcDir, "config.yaml"), []byte("y"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    output_directory: /out\n    name_pattern: [\"*.log\"]\n", srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/access.log") {
		t.Error("access.log should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/config.yaml") {
		t.Error("config.yaml should not be collected (name_pattern: *.log)")
	}
}

func TestRunSSEPackage_ExcludeNamePattern(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "access.log"), []byte("l"), 0600)
	os.WriteFile(filepath.Join(srcDir, "cache.tmp"), []byte("t"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    output_directory: /out\n    exclude_name_pattern: [\"*.tmp\"]\n", srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/access.log") {
		t.Error("access.log should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/cache.tmp") {
		t.Error("cache.tmp should not be collected (exclude_name_pattern)")
	}
}

func TestRunSSEPackage_MaxFileSizeDir(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "small.log"), []byte("0123456789"), 0600)
	os.WriteFile(filepath.Join(srcDir, "large.log"), make([]byte, 2000), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    output_directory: /out\n    max_file_size: 1k\n", srcDir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/small.log") {
		t.Error("small.log should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/large.log") {
		t.Error("large.log should not be collected (exceeds max_file_size: 1k)")
	}
}

func TestRunSSEPackage_MaxFileSizeSingleFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "big.log")
	os.WriteFile(src, make([]byte, 2000), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    max_file_size: 1k\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	if ctx.SSEZipPath != "" {
		zr := openSSEZip(t, ctx)
		if zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
			t.Error("big.log should not be collected (exceeds max_file_size: 1k)")
		}
	}
}

func TestRunSSEPackage_InvalidMaxFileSize(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("x"), 0600)
	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    max_file_size: notvalid\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx) // must not panic; artifact skipped
	if ctx.SSEZipPath != "" {
		zr := openSSEZip(t, ctx)
		if zipHasEntry(zr, "[root_dir]/"+strings.TrimPrefix(filepath.ToSlash(src), "/")) {
			t.Error("artifact with invalid max_file_size should be skipped")
		}
	}
}

func TestRunSSEPackage_Dir_LargeManifestNoPanic(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f.txt")
	os.WriteFile(src, []byte("x"), 0600)
	var sb strings.Builder
	sb.WriteString("version: 1.0\nartifacts:\n")
	for i := 0; i < 51; i++ {
		fmt.Fprintf(&sb, "  - collector: file\n    path: %s\n", src)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "big.yaml"), []byte(sb.String()), 0600)
	ctx := makeTestCtxWithManifest(t, dir)
	RunSSEPackage(ctx) // must not panic
}

func TestRunSSEPackage_ExcludePathPattern(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	varDir := filepath.Join(root, "var")
	os.MkdirAll(procDir, 0700)
	os.MkdirAll(varDir, 0700)
	os.WriteFile(filepath.Join(procDir, "kcore"), []byte("huge"), 0600)
	os.WriteFile(filepath.Join(varDir, "syslog"), []byte("log"), 0600)

	yml := fmt.Sprintf(
		"version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    output_directory: /out\n    exclude_path_pattern: [%q]\n",
		root, procDir,
	)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/var/syslog") {
		t.Error("syslog should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/proc/kcore") {
		t.Error("proc/kcore should not be collected (excluded path)")
	}
}

func TestRunSSEPackage_ExcludePathPattern_PrefixBoundary(t *testing.T) {
	root := t.TempDir()
	procDataDir := filepath.Join(root, "proc-data")
	procDir := filepath.Join(root, "proc")
	os.MkdirAll(procDataDir, 0700)
	os.MkdirAll(procDir, 0700)
	os.WriteFile(filepath.Join(procDataDir, "info.txt"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(procDir, "status"), []byte("virtual"), 0600)

	yml := fmt.Sprintf(
		"version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    output_directory: /out\n    exclude_path_pattern: [%q]\n",
		root, procDir,
	)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)
	if !zipHasEntry(zr, "[root_dir]/out/proc-data/info.txt") {
		t.Error("proc-data/info.txt should be collected")
	}
	if zipHasEntry(zr, "[root_dir]/out/proc/status") {
		t.Error("proc/status should not be collected (excluded)")
	}
}

func TestCollectDirArtifact_FileType_RegularOnly(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "regular.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(srcDir, "regular.txt"), filepath.Join(srcDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{FileType: []string{"f"}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al1 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al1, 0, nil, time.Time{})
	collected := al1.collected
	skipped := s

	if collected != 1 {
		t.Errorf("collected = %d, want 1", collected)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestCollectDirArtifact_FileType_SymlinkOnly(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "regular.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(srcDir, "regular.txt"), filepath.Join(srcDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{FileType: []string{"l"}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al2 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al2, 0, nil, time.Time{})
	collected := al2.collected
	skipped := s

	if collected != 1 {
		t.Errorf("collected = %d, want 1", collected)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestCollectDirArtifact_FileType_Empty(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "regular.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(srcDir, "regular.txt"), filepath.Join(srcDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{FileType: []string{}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al3 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al3, 0, nil, time.Time{})
	collected := al3.collected
	skipped := s

	if collected != 2 {
		t.Errorf("collected = %d, want 2", collected)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

func TestIsExcludedPath(t *testing.T) {
	cases := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"/proc/self/fd", []string{"/proc"}, true},                // subpath matched
		{"/proc", []string{"/proc"}, true},                        // exact match
		{"/proc-data", []string{"/proc"}, false},                  // prefix boundary: /proc-data must not match /proc
		{"/var/log", []string{"/dev", "/proc", "/sys"}, false},    // path not in exclusion list
		{"/dev", []string{"/dev", "/proc"}, true},                 // exact match, first entry
		{"/", []string{"/proc"}, false},                           // root is not excluded
		{"/proc/self", []string{}, false},                         // empty exclusion list
		{"/sys/kernel", []string{"/sys"}, true},                   // subdirectory of excluded
		{"/run", []string{"/dev", "/proc", "/run", "/sys"}, true}, // UAC default exclusion
	}
	for _, tc := range cases {
		got := isExcludedPath(tc.path, tc.patterns)
		if got != tc.want {
			t.Errorf("isExcludedPath(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
		}
	}
}

func TestCollectDirArtifact_PathPattern(t *testing.T) {
	srcDir := t.TempDir()
	subDir := filepath.Join(srcDir, "subdir")
	if err := os.MkdirAll(subDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "target.txt"), []byte("t"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "other.txt"), []byte("o"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "toplevel.txt"), []byte("l"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{PathPattern: []string{"*/subdir/target.txt"}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al4 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al4, 0, nil, time.Time{})
	collected := al4.collected
	skipped := s

	if collected != 1 {
		t.Errorf("collected = %d, want 1", collected)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}
}

func TestCollectDirArtifact_PathPattern_Empty(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{PathPattern: []string{}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al5 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al5, 0, nil, time.Time{})
	collected := al5.collected
	skipped := s

	if collected != 2 {
		t.Errorf("collected = %d, want 2", collected)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
}

func TestCollectDirArtifact_PathPattern_MultiplePatterns(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "c.txt"), []byte("c"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	opts := sseFilterOpts{PathPattern: []string{"*/a.txt", "*/b.txt"}}
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	al6 := newSseArtifactLog("")
	s := collectDirArtifact(ctx, srcDir, "/out", opts, zw, &al6, 0, nil, time.Time{})
	collected := al6.collected
	skipped := s

	if collected != 2 {
		t.Errorf("collected = %d, want 2", collected)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestShellGlobToRegexp(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Primary UAC use-case: path_pattern matching across path separators.
		{"*/.git/hooks/*", "/home/user/.git/hooks/pre-commit", true},
		{"*/.git/hooks/*", "/var/repo/.git/hooks/post-receive", true},
		{"*/.git/hooks/*", "/etc/gitconfig", false},
		// Pattern with no trailing wildcard: full path after hooks not matched.
		{"*/.git/hooks/", "/home/user/.git/hooks/pre-commit", false},
		// Simple suffix glob.
		{"*.log", "/var/log/syslog.log", true},
		{"*.log", "/var/log/syslog", false},
		// Match-all glob.
		{"*", "/anything/at/all", true},
		// Literal path.
		{"/etc/passwd", "/etc/passwd", true},
		{"/etc/passwd", "/etc/shadow", false},
		// ? matches exactly one character.
		{"?etc/passwd", "/etc/passwd", true},
		{"?etc/passwd", "Xetc/passwd", true},
		{"?etc/passwd", "Xetc/shadow", false},
		// Dot in pattern is a literal dot, not a regex wildcard.
		{"*.log", "/var/log/syslog_log", false},
	}
	for _, tc := range cases {
		re := shellGlobToRegexp(tc.pattern)
		if re == nil {
			t.Errorf("shellGlobToRegexp(%q): returned nil (unexpected compile error)", tc.pattern)
			continue
		}
		got := re.MatchString(tc.path)
		if got != tc.want {
			t.Errorf("shellGlobToRegexp(%q).MatchString(%q) = %v, want %v",
				tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestCopyFileToZipEntry_SymlinkDereferenced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	want := []byte("symlink target content")
	if err := os.WriteFile(target, want, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := copyFileToZipEntry(link, zw, "out/link.txt"); err != nil {
		t.Fatalf("copyFileToZipEntry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(zr.File))
	}
	entry := zr.File[0]
	// Verify mtime matches the target file, not the symlink.
	targetFi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	entryMtime := entry.Modified.UTC().Truncate(2 * time.Second)
	targetMtime := targetFi.ModTime().UTC().Truncate(2 * time.Second)
	if !entryMtime.Equal(targetMtime) {
		t.Errorf("entry mtime = %v, want target mtime %v", entryMtime, targetMtime)
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		t.Error("zip entry must not be marked as a symlink — entry would be unextractable")
	}
	rc, err := entry.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestCopyFileToZipEntry_ContentAndName(t *testing.T) {
	src := filepath.Join(t.TempDir(), "data.txt")
	want := []byte("test content")
	if err := os.WriteFile(src, want, 0600); err != nil {
		t.Fatal(err)
	}
	known := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(src, known, known); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if err := copyFileToZipEntry(src, zw, "var/log/data.txt"); err != nil {
		t.Fatalf("copyFileToZipEntry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open zip reader: %v", err)
	}

	if len(zr.File) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(zr.File))
	}
	entry := zr.File[0]

	if entry.Name != "var/log/data.txt" {
		t.Errorf("entry name = %q, want %q", entry.Name, "var/log/data.txt")
	}

	rc, err := entry.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}

	if entry.Modified.UTC().Truncate(2*time.Second) != known.Truncate(2*time.Second) {
		t.Errorf("mtime = %v, want %v", entry.Modified, known)
	}
}

func sseLogPath(ctx *ModuleContext) string {
	return ctx.Dirs.Base + "-sse-log.txt"
}

func readSseLog(t *testing.T, ctx *ModuleContext) string {
	t.Helper()
	data, err := os.ReadFile(sseLogPath(ctx))
	if err != nil {
		t.Fatalf("sse-log.txt not found: %v", err)
	}
	return string(data)
}

func TestRunSSEPackage_LogFileCreated(t *testing.T) {
	src := filepath.Join(t.TempDir(), "auth.log")
	os.WriteFile(src, []byte("log data"), 0600)

	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    description: auth log\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	for _, want := range []string{
		"=== ARTIFACT: auth log ===",
		"Collected : 1",
		"Skipped   : 0",
		"Errors    : 0",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in log:\n%s", want, content)
		}
	}
	if strings.Contains(content, src) {
		t.Errorf("collected file path should not appear in log, got:\n%s", content)
	}
}

func TestRunSSEPackage_LogSkipsUnsupportedCollector(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("x"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: browser
    path: /some/path
    description: Browser History
  - collector: file
    path: %s
    description: target file
`, src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, `artifact "Browser History" — skipped: unsupported collector: browser`) {
		t.Errorf("expected artifact skip entry, got:\n%s", content)
	}
}

func TestRunSSEPackage_LogErrorsLstatFailure(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(src, []byte("x"), 0600)

	missing := "/nonexistent/path/does-not-exist.log"
	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    description: multi path artifact
    path:
      - %s
      - %s
`, src, missing)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "Errors    : 1") {
		t.Errorf("expected Errors : 1 in log, got:\n%s", content)
	}
	if !strings.Contains(content, missing) {
		t.Errorf("expected %q in log, got:\n%s", missing, content)
	}
}

func TestRunSSEPackage_LogNotCreatedWhenNoZip(t *testing.T) {
	// No manifest → no zip → no log
	ctx := makeTestCtx(t)
	RunSSEPackage(ctx)
	if _, err := os.Stat(sseLogPath(ctx)); err == nil {
		t.Error("sse-log.txt must not be created when no manifest is set")
	}
}

func TestRunSSEPackage_LogDirSkipsBySize(t *testing.T) {
	dir := t.TempDir()
	// Small file, should be collected
	os.WriteFile(filepath.Join(dir, "small.log"), []byte("ok"), 0600)
	// Large file, should be skipped
	os.WriteFile(filepath.Join(dir, "big.log"), make([]byte, 200), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    max_file_size: 100B
`, dir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "exceeds max_file_size") {
		t.Errorf("expected exceeds max_file_size in log, got:\n%s", content)
	}
	if strings.Contains(content, "small.log") {
		t.Errorf("small.log must not appear in log, got:\n%s", content)
	}
}

func TestRunSSEPackage_LogDirSkipsByNamePattern(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "match.log"), []byte("ok"), 0600)
	os.WriteFile(filepath.Join(dir, "nomatch.txt"), []byte("ok"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    name_pattern:
      - "*.log"
`, dir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "excluded by name pattern") {
		t.Errorf("expected excluded by name pattern in log, got:\n%s", content)
	}
}

func TestRunSSEPackage_LogDirSkipsByExcludeNamePattern(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "keep.log"), []byte("ok"), 0600)
	os.WriteFile(filepath.Join(dir, "skip.tmp"), []byte("ok"), 0600)

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    exclude_name_pattern:
      - "*.tmp"
`, dir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "excluded by name pattern") {
		t.Errorf("expected excluded by name pattern in log, got:\n%s", content)
	}
}

func TestRunSSEPackage_LogDirSkipsByFileType(t *testing.T) {
	dir := t.TempDir()
	// Regular file, should be collected when file_type is "f"
	os.WriteFile(filepath.Join(dir, "keep.log"), []byte("ok"), 0600)
	// Symlink, should be skipped when file_type only allows "f"
	target := filepath.Join(dir, "keep.log")
	os.Symlink(target, filepath.Join(dir, "link.log"))

	yml := fmt.Sprintf(`version: 1.0
artifacts:
  - collector: file
    path: %s
    file_type:
      - f
`, dir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "unsupported file type") {
		t.Errorf("expected unsupported file type in log, got:\n%s", content)
	}
}

func TestCollectDirArtifact_WalkErrorOnInaccessibleDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod 000 has no effect as root")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "secret.log"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0700) })

	ctx := makeTestCtx(t)
	al := newSseArtifactLog("test")
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	collectDirArtifact(ctx, root, "", sseFilterOpts{}, zw, &al, 0, nil, time.Time{})

	if len(al.errors) == 0 {
		t.Error("expected at least one error entry for the inaccessible directory")
	}
}

func TestRunSSEPackage_PathWithSpaces(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "file with spaces.log")
	if err := os.WriteFile(src, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	yml := fmt.Sprintf("version: 1.0\nartifacts:\n  - collector: file\n    path:\n      - %q\n", src)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	zr := openSSEZip(t, ctx)
	entryName := "[root_dir]/" + strings.TrimPrefix(filepath.ToSlash(src), "/")
	if !zipHasEntry(zr, entryName) {
		t.Errorf("expected entry %q for path with spaces", entryName)
	}
}

func TestRunSSEPackage_NoZipNoLog_WhenAllArtifactsFiltered(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	yml := fmt.Sprintf(
		"version: 1.0\nartifacts:\n  - collector: file\n    path: %s\n    supported_os: [macos]\n",
		src,
	)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	if ctx.SSEZipPath != "" {
		t.Error("SSEZipPath should be empty when all artifacts are filtered")
	}
	logPath := ctx.Dirs.Base + "-sse-log.txt"
	if _, err := os.Stat(logPath); err == nil {
		t.Error("log file must not exist when no zip was produced")
	}
}

func TestRunSSEPackage_MaxTotalSize(t *testing.T) {
	dir := t.TempDir()
	// Two 10-byte files; limit is 15 bytes so only one fits.
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.log"), []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}

	yml := fmt.Sprintf(`version: 1.0
max_total_size: 15B
artifacts:
  - collector: file
    path: %s
    output_directory: /out
`, dir)
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, yml))
	RunSSEPackage(ctx)

	if ctx.SSEZipPath == "" {
		t.Fatal("expected a zip to be produced")
	}
	zr := openSSEZip(t, ctx)
	fileCount := 0
	for range zr.File {
		fileCount++
	}
	if fileCount != 1 {
		t.Errorf("expected 1 collected file (size limit), got %d", fileCount)
	}

	content := readSseLog(t, ctx)
	if !strings.Contains(content, "total size limit reached") {
		t.Errorf("expected 'total size limit reached' in log, got:\n%s", content)
	}
}

func TestSymlinkDereferenceAllowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	root := t.TempDir()
	inside := filepath.Join(root, "real.txt")
	if err := os.WriteFile(inside, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOPSECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	mklink := func(name, target string) string {
		p := filepath.Join(root, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inLink := mklink("in.txt", inside)
	outLink := mklink("out.txt", outside)
	brokenLink := mklink("broken.txt", filepath.Join(root, "does-not-exist"))

	if real, ok, _ := symlinkDereferenceAllowed(inLink, root, true); !ok || real != inside {
		t.Errorf("in-scope contained: ok=%v real=%q, want true %q", ok, real, inside)
	}
	if _, ok, reason := symlinkDereferenceAllowed(outLink, root, true); ok || reason != "symlink target outside collection scope" {
		t.Errorf("out-of-scope contained: ok=%v reason=%q", ok, reason)
	}
	if real, ok, _ := symlinkDereferenceAllowed(outLink, "", false); !ok || real != outside {
		t.Errorf("cross-tree literal: ok=%v real=%q, want true %q", ok, real, outside)
	}
	if _, ok, reason := symlinkDereferenceAllowed(brokenLink, "", false); ok || reason != "broken or cyclic symlink" {
		t.Errorf("broken: ok=%v reason=%q", ok, reason)
	}
}

func zipHasEntryContaining(zr *zip.ReadCloser, sub string) bool {
	for _, f := range zr.File {
		if strings.Contains(f.Name, sub) {
			return true
		}
	}
	return false
}

func zipHasEntryWithContent(zr *zip.ReadCloser, needle string) bool {
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

func TestRunSSEPackage_GlobSymlinkContainment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "ok.log"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(srcDir, "ok.log"), filepath.Join(srcDir, "good.log")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(srcDir, "evil.log")); err != nil {
		t.Fatal(err)
	}

	manifest := "version: 1.0\nartifacts:\n  - collector: file\n    path: " + filepath.Join(srcDir, "*.log") + "\n"
	ctx := makeTestCtxWithManifest(t, writeTempManifest(t, manifest))
	RunSSEPackage(ctx)
	zr := openSSEZip(t, ctx)

	if !zipHasEntryContaining(zr, "ok.log") {
		t.Error("ok.log should be collected")
	}
	if zipHasEntryWithContent(zr, "TOPSECRET") {
		t.Error("out-of-scope symlink target leaked into archive")
	}
}

func TestCollectDirArtifact_SymlinkContainment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "real.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(srcDir, "real.txt"), filepath.Join(srcDir, "in.txt")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(srcDir, "out.txt")); err != nil {
		t.Fatal(err)
	}

	ctx := makeTestCtx(t)
	al := newSseArtifactLog("")
	zw := zip.NewWriter(io.Discard)
	defer zw.Close()
	_ = collectDirArtifact(ctx, srcDir, "/out", sseFilterOpts{}, zw, &al, 0, nil, time.Time{})

	if al.collected != 2 {
		t.Errorf("collected = %d, want 2 (real.txt + dereferenced in.txt)", al.collected)
	}
	if al.skippedByReason["symlink target outside collection scope"] != 1 {
		t.Errorf("out-of-scope skip count = %d, want 1", al.skippedByReason["symlink target outside collection scope"])
	}
	if len(al.followedSymlinks) != 1 {
		t.Errorf("followedSymlinks = %d, want 1", len(al.followedSymlinks))
	}
}

func TestCollectDirArtifact_DeadlineRecorded(t *testing.T) {
	ctx := makeTestCtx(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	al := newSseArtifactLog("t")
	var total int64
	past := time.Now().Add(-time.Second)
	collectDirArtifact(ctx, src, "out", sseFilterOpts{}, zw, &al, 0, &total, past)
	zw.Close()
	found := false
	for _, e := range al.errors {
		if strings.Contains(e.reason, "deadline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("timeout not recorded in artifact log: %+v", al.errors)
	}
}
