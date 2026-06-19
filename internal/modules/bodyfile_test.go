//go:build linux

package modules

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pathfinder/internal/config"
)

func newTestContext(t *testing.T) *ModuleContext {
	t.Helper()
	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	return ctx
}

func TestAnalyzeBodyfile_VolatileCappedAt20(t *testing.T) {
	ctx := newTestContext(t)

	// mode 33188 = 0o100644: regular file, no exec bit
	// atime/mtime = now → recent activity
	now := time.Now().Unix()
	var sb strings.Builder
	sb.WriteString("# MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime\n")
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&sb, "abc|/tmp/testfile%d|%d|33188|0|0|100|%d|%d|%d|0\n",
			i, 1000+i, now, now, now)
	}

	analyzeBodyfile(ctx, []byte(sb.String()))

	volatileFindings := 0
	for _, f := range ctx.Registry.All() {
		if f.Label == "Recent activity in volatile/hidden path" {
			volatileFindings++
		}
	}
	// Expect all 25 hits stored in registry (first 20 via Add, remainder via AddSilent)
	if volatileFindings != 25 {
		t.Errorf("want 25 volatile registry entries (all hits stored), got %d", volatileFindings)
	}
}

// TestNewSectionWriterWithBuf_ZipModeSharesBuffer verifies that in zip mode the
// section writer uses the caller's buffer directly (no second buffer is allocated).
// The caller's buffer must contain the written content after Close, and the zip
// entry must contain the same content.
func TestNewSectionWriterWithBuf_ZipModeSharesBuffer(t *testing.T) {
	var zipOut bytes.Buffer
	zw := zip.NewWriter(&zipOut)

	cfg := &config.Config{ReportDir: t.TempDir()}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx.ZipWriter = zw

	var buf bytes.Buffer
	w := newSectionWriterWithBuf(ctx, ctx.Dirs.Bodyfile, "bodyfile.txt", "LABEL", "src", &buf)
	w.WriteString("line1\n")
	w.WriteString("line2\n")

	// buf must be populated before Close (content is shared, not deferred)
	if !strings.Contains(buf.String(), "line1") {
		t.Errorf("bodyBuf should contain written content before Close; got: %q", buf.String())
	}

	w.Close()
	zw.Close()

	// Verify zip entry contains the content
	zr, err := zip.NewReader(bytes.NewReader(zipOut.Bytes()), int64(zipOut.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	var entryContent string
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "bodyfile.txt") {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			entryContent = string(data)
		}
	}
	if !strings.Contains(entryContent, "line1") || !strings.Contains(entryContent, "line2") {
		t.Errorf("zip entry missing expected content; got: %q", entryContent)
	}
}

func TestAnalyzeBodyfile_OutputPrefix_Skipped(t *testing.T) {
	ctx := newTestContext(t)
	// OutputPrefix = cfg.ReportDir + "/pathfinder-"; cfg.ReportDir is t.TempDir() under /tmp
	// so this path would normally trigger "volatile/hidden path" detection
	now := time.Now().Unix()
	manifestPath := ctx.OutputPrefix + "myhost-20260520_145704-manifest.txt"
	zipPath := ctx.OutputPrefix + "myhost-20260520_145704.zip"

	var sb strings.Builder
	sb.WriteString("# MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime\n")
	fmt.Fprintf(&sb, "abc|%s|1000|33188|0|0|100|%d|%d|%d|0\n", manifestPath, now, now, now)
	fmt.Fprintf(&sb, "abc|%s|1001|33188|0|0|100|%d|%d|%d|0\n", zipPath, now, now, now)

	analyzeBodyfile(ctx, []byte(sb.String()))

	for _, f := range ctx.Registry.All() {
		if f.Label == "Recent activity in volatile/hidden path" {
			t.Errorf("pathfinder output file should be skipped, got finding: %s", f.Message)
		}
	}
}

func TestAnalyzeBodyfile_VolatileExecLabel(t *testing.T) {
	ctx := newTestContext(t)
	now := time.Now().Unix()
	// mode 33261 = 0o100755: regular file, exec bit set - triggers VOLATILE-EXEC path
	line := fmt.Sprintf("abc|/tmp/malware|1000|33261|0|0|100|%d|%d|%d|0\n", now, now, now)
	data := "# MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime\n" + line

	analyzeBodyfile(ctx, []byte(data))

	for _, f := range ctx.Registry.All() {
		if f.Label == "Executable in volatile/hidden path" {
			return
		}
	}
	t.Error("want finding with label 'Executable in volatile/hidden path', got none")
}

func TestBfTime(t *testing.T) {
	tests := []struct {
		ts   int64
		want string
	}{
		{0, "N/A"},
		{-1, "N/A"},
		{1609459200, "2021-01-01 00:00:00"},
	}
	for _, tc := range tests {
		got := bfTime(tc.ts)
		if got != tc.want {
			t.Errorf("bfTime(%d) = %q, want %q", tc.ts, got, tc.want)
		}
	}
}

func TestBfIsHiddenPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home/user/.ssh/authorized_keys", true},
		{"/home/user/.bashrc", true},
		{"/.hidden/bin/tool", true},
		{"/usr/bin/python3", false},
		{"/etc/profile", false},
		{"/tmp/normalfile", false},
	}
	for _, tc := range tests {
		got := bfIsHiddenPath(tc.path)
		if got != tc.want {
			t.Errorf("bfIsHiddenPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestBfIsKnownHiddenSafe(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/skel/.bashrc", true},
		{"/etc/selinux/config", true},
		{"/etc/.pwd.lock", true},
		{"/etc/.updated", true},
		{"/home/user/.bashrc", false},
		{"/tmp/.hidden", false},
	}
	for _, tc := range tests {
		got := bfIsKnownHiddenSafe(tc.path)
		if got != tc.want {
			t.Errorf("bfIsKnownHiddenSafe(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestAnalyzeBodyfile_TimestompFuture(t *testing.T) {
	ctx := newTestContext(t)
	now := time.Now().Unix()
	// mode 33261 = 0o100755: regular exec file in /usr/bin, triggers inSysBin
	futureMtime := now + 7200
	line := fmt.Sprintf("abc|/usr/bin/evil|1000|33261|0|0|100|%d|%d|%d|0\n",
		now, futureMtime, now)
	// also a clean line that must NOT fire
	safeMtime := now - 86400
	safeLine := fmt.Sprintf("abc|/usr/bin/safe|1001|33261|0|0|100|%d|%d|%d|0\n",
		now, safeMtime, now)
	data := "# header\n" + line + safeLine

	analyzeBodyfile(ctx, []byte(data))

	found := 0
	for _, f := range ctx.Registry.All() {
		if f.Label == "Timestomped binary: future mtime" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("want 1 TIMESTOMP-FUTURE finding, got %d", found)
	}
}

func TestAnalyzeBodyfile_SuidNonstandard(t *testing.T) {
	ctx := newTestContext(t)
	now := time.Now().Unix()
	old := now - 10*86400
	// mode 35309 = 0o104755: regular file with SUID bit, uid=0, path outside SafeDirs
	// /tmp/ is not in ioc.SafeDirs (/usr/, /bin/, /sbin/, /lib/, /lib64/, /opt/, /snap/)
	// old atime/mtime keeps recentActivity false so VOLATILE-EXEC does not co-fire
	line := fmt.Sprintf("abc|/tmp/suidbin|1000|35309|0|0|100|%d|%d|%d|0\n", old, old, now)
	data := "# header\n" + line

	analyzeBodyfile(ctx, []byte(data))

	found := 0
	for _, f := range ctx.Registry.All() {
		if f.Label == "SUID binary in non-standard path" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("want 1 SUID-NONSTANDARD finding, got %d", found)
	}
}

func TestAnalyzeBodyfile_FhsViolation(t *testing.T) {
	ctx := newTestContext(t)
	now := time.Now().Unix()
	// mode 33261 = 0o100755: regular exec file in /etc/, triggers FHS violation
	line := fmt.Sprintf("abc|/etc/backdoor|1000|33261|0|0|100|%d|%d|%d|0\n", now, now, now)
	data := "# header\n" + line

	analyzeBodyfile(ctx, []byte(data))

	found := 0
	for _, f := range ctx.Registry.All() {
		if f.Label == "FHS violation: executable in non-exec directory" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("want 1 FHS-VIOLATION finding, got %d", found)
	}
}

func TestAnalyzeBodyfile_BinReplace(t *testing.T) {
	ctx := newTestContext(t)
	now := time.Now().Unix()
	sevenDaysAgo := now - 7*86400
	thirtyDaysAgo := now - 30*86400

	// Fires: mtime=now (recent), btime=30 days ago (old)
	hitLine := fmt.Sprintf("abc|/usr/bin/ssh|1000|33261|0|0|100|%d|%d|%d|%d\n",
		now, now, now, thirtyDaysAgo)
	// Does not fire: btime=0 (statx not available)
	noBtimeLine := fmt.Sprintf("abc|/usr/bin/ls|1001|33261|0|0|100|%d|%d|%d|0\n",
		now, now, now)
	// Does not fire: mtime is old (not recently modified)
	oldMtimeLine := fmt.Sprintf("abc|/usr/bin/cat|1002|33261|0|0|100|%d|%d|%d|%d\n",
		now, sevenDaysAgo-3600, now, thirtyDaysAgo)
	data := "# header\n" + hitLine + noBtimeLine + oldMtimeLine

	analyzeBodyfile(ctx, []byte(data))

	found := 0
	for _, f := range ctx.Registry.All() {
		if f.Label == "System binary replacement heuristic" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("want 1 BIN-REPLACE finding, got %d", found)
	}
}
