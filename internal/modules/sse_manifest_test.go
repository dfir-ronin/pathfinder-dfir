//go:build linux

// internal/modules/sse_manifest_test.go
package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadManifest_StringPath(t *testing.T) {
	yml := `
version: 1.0
artifacts:
  - description: Test
    collector: file
    path: /etc/passwd /etc/shadow
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(m.Artifacts))
	}
	if len(m.Artifacts[0].Path) != 2 {
		t.Errorf("want 2 path tokens, got %d: %v", len(m.Artifacts[0].Path), m.Artifacts[0].Path)
	}
	if m.Artifacts[0].Path[0] != "/etc/passwd" {
		t.Errorf("want /etc/passwd, got %q", m.Artifacts[0].Path[0])
	}
}

func TestLoadManifest_ListPath(t *testing.T) {
	yml := `
version: 1.0
artifacts:
  - collector: file
    path:
      - /etc/passwd
      - /etc/shadow
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if len(m.Artifacts[0].Path) != 2 {
		t.Errorf("want 2 path tokens, got %d", len(m.Artifacts[0].Path))
	}
	if m.Artifacts[0].Path[1] != "/etc/shadow" {
		t.Errorf("want /etc/shadow, got %q", m.Artifacts[0].Path[1])
	}
}

func TestLoadManifest_OptionalFields(t *testing.T) {
	yml := `
version: 1.0
artifacts:
  - collector: file
    path: /etc/passwd
    output_directory: /files/system
    output_file: passwd.txt
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	a := m.Artifacts[0]
	if a.OutputDirectory != "/files/system" {
		t.Errorf("want /files/system, got %q", a.OutputDirectory)
	}
	if a.OutputFile != "passwd.txt" {
		t.Errorf("want passwd.txt, got %q", a.OutputFile)
	}
}

func TestLoadManifest_InvalidYAML(t *testing.T) {
	f := writeTempFile(t, "key: [unclosed")
	_, err := loadManifest(f)
	if err == nil {
		t.Error("want error for invalid YAML, got nil")
	}
}

func TestLoadManifest_FileNotFound(t *testing.T) {
	_, err := loadManifest("/nonexistent/path/manifest.yaml")
	if err == nil {
		t.Error("want error for missing file, got nil")
	}
}

func TestReadHomeDirs_IncludesRoot(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	f := writeTempFile(t, passwd)
	homes := readHomeDirs(f)
	if len(homes) != 1 || homes[0] != "/root" {
		t.Errorf("want [/root], got %v", homes)
	}
}

func TestReadHomeDirs_IncludesUID1000(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	f := writeTempFile(t, passwd)
	homes := readHomeDirs(f)
	if len(homes) != 2 {
		t.Fatalf("want 2 homes, got %v", homes)
	}
}

func TestReadHomeDirs_ExcludesNologin(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nsvc:x:1001:1001:svc:/home/svc:/usr/sbin/nologin\n"
	f := writeTempFile(t, passwd)
	homes := readHomeDirs(f)
	if len(homes) != 1 || homes[0] != "/root" {
		t.Errorf("want only [/root], got %v", homes)
	}
}

func TestReadHomeDirs_ExcludesBinFalse(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nbob:x:1002:1002:bob:/home/bob:/bin/false\n"
	f := writeTempFile(t, passwd)
	homes := readHomeDirs(f)
	if len(homes) != 1 || homes[0] != "/root" {
		t.Errorf("want only [/root], got %v", homes)
	}
}

func TestReadHomeDirs_EmptyFile(t *testing.T) {
	f := writeTempFile(t, "")
	homes := readHomeDirs(f)
	if len(homes) != 0 {
		t.Errorf("want empty, got %v", homes)
	}
}

func TestExpandUserHomes_NoPlaceholder(t *testing.T) {
	got := expandUserHomes("/etc/passwd", "/dev/null")
	if len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("want [/etc/passwd], got %v", got)
	}
}

func TestExpandUserHomes_WithPlaceholder(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n"
	f := writeTempFile(t, passwd)
	got := expandUserHomes(uacUserHomePlaceholder+"/.bashrc", f)
	if len(got) != 1 || got[0] != "/root/.bashrc" {
		t.Errorf("want [/root/.bashrc], got %v", got)
	}
}

func TestExpandUserHomes_MultipleUsers(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
	f := writeTempFile(t, passwd)
	got := expandUserHomes(uacUserHomePlaceholder+"/.ssh", f)
	if len(got) != 2 {
		t.Errorf("want 2 expanded paths, got %v", got)
	}
}

func TestExpandUserHomes_EmptyPasswd(t *testing.T) {
	f := writeTempFile(t, "")
	got := expandUserHomes(uacUserHomePlaceholder+"/.bashrc", f)
	if len(got) != 0 {
		t.Errorf("want empty slice, got %v", got)
	}
}

func TestResolveTokens_LiteralPath(t *testing.T) {
	got := resolveTokens([]string{"/etc/passwd"}, "/dev/null")
	if len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("want [/etc/passwd], got %v", got)
	}
}

func TestResolveTokens_GlobMatches(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.log"), []byte{}, 0600)
	os.WriteFile(filepath.Join(dir, "b.log"), []byte{}, 0600)

	got := resolveTokens([]string{filepath.Join(dir, "*.log")}, "/dev/null")
	if len(got) != 2 {
		t.Errorf("want 2 matches, got %v", got)
	}
}

func TestLoadManifest_ExcludePathPattern(t *testing.T) {
	yml := `
version: 1.0
artifacts:
  - collector: file
    path: /var/log
    exclude_path_pattern: ["/dev", "/proc", "/sys"]
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	a := m.Artifacts[0]
	if len(a.ExcludePathPattern) != 3 {
		t.Fatalf("ExcludePathPattern: want 3, got %v", a.ExcludePathPattern)
	}
	if a.ExcludePathPattern[0] != "/dev" {
		t.Errorf("ExcludePathPattern[0]: want /dev, got %q", a.ExcludePathPattern[0])
	}
	if a.ExcludePathPattern[2] != "/sys" {
		t.Errorf("ExcludePathPattern[2]: want /sys, got %q", a.ExcludePathPattern[2])
	}
}

func TestResolveTokens_GlobNoMatch(t *testing.T) {
	got := resolveTokens([]string{"/nonexistent/path/*.txt"}, "/dev/null")
	if len(got) != 0 {
		t.Errorf("want empty for no-match glob, got %v", got)
	}
}

func TestResolveTokens_UserHome(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", "alice")
	os.MkdirAll(home, 0700)
	os.WriteFile(filepath.Join(home, ".bashrc"), []byte{}, 0600)
	os.WriteFile(filepath.Join(home, ".bash_profile"), []byte{}, 0600)

	passwd := fmt.Sprintf("alice:x:1000:1000:Alice:%s:/bin/bash\n", home)
	passwdPath := writeTempFile(t, passwd)

	// Pattern with glob: verifies both user_home expansion and glob resolution
	got := resolveTokens([]string{uacUserHomePlaceholder + "/.bash*"}, passwdPath)
	if len(got) != 2 {
		t.Errorf("want 2 matches (.bashrc, .bash_profile), got %v", got)
	}
}

func TestResolveTokens_MultipleTokens(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	os.WriteFile(f1, []byte{}, 0600)
	os.WriteFile(f2, []byte{}, 0600)

	got := resolveTokens([]string{f1, f2}, "/dev/null")
	if len(got) != 2 {
		t.Errorf("want 2 tokens, got %v", got)
	}
}

func TestEntryNameForPath_NoOutputDir(t *testing.T) {
	got := entryNameForPath("/var/log/auth.log", "auth.log", "")
	want := "[root_dir]/var/log/auth.log"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEntryNameForPath_WithOutputDirAndRel(t *testing.T) {
	got := entryNameForPath("/var/log/auth.log", "auth.log", "/files/logs")
	want := "[root_dir]/files/logs/auth.log"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEntryNameForPath_RenamedFile(t *testing.T) {
	got := entryNameForPath("/var/log/auth.log", "renamed.log", "/files/logs")
	want := "[root_dir]/files/logs/renamed.log"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEntryNameForPath_DirRelPath(t *testing.T) {
	got := entryNameForPath("/var/log/sub/file.log", "sub/file.log", "/out")
	want := "[root_dir]/out/sub/file.log"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEntryNameForPath_LeadingSlashStripped(t *testing.T) {
	got := entryNameForPath("/etc/passwd", "passwd", "/files/system")
	want := "[root_dir]/files/system/passwd"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEntryNameForPath_MirrorsAbsPathWhenNoOutputDir(t *testing.T) {
	got := entryNameForPath("/etc/systemd/system/cron.service", "cron.service", "")
	want := "[root_dir]/etc/systemd/system/cron.service"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLoadManifestDir_MergesArtifacts(t *testing.T) {
	dir := t.TempDir()
	yml1 := "version: 1.0\nartifacts:\n  - collector: file\n    path: /etc/passwd\n"
	yml2 := "version: 1.0\nartifacts:\n  - collector: file\n    path: /etc/shadow\n  - collector: file\n    path: /etc/hosts\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yml1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(yml2), 0600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifestDir(dir)
	if err != nil {
		t.Fatalf("loadManifestDir: %v", err)
	}
	if len(m.Artifacts) != 3 {
		t.Errorf("want 3 artifacts, got %d", len(m.Artifacts))
	}
}

func TestLoadManifestDir_Recursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "logs")
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatal(err)
	}
	yml := "version: 1.0\nartifacts:\n  - collector: file\n    path: /var/log/syslog\n"
	if err := os.WriteFile(filepath.Join(sub, "logs.yaml"), []byte(yml), 0600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifestDir(dir)
	if err != nil {
		t.Fatalf("loadManifestDir: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Errorf("want 1 artifact from subdir, got %d", len(m.Artifacts))
	}
}

func TestLoadManifestDir_SkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("key: [unclosed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte("version: 1.0\nartifacts:\n  - collector: file\n    path: /etc/passwd\n"), 0600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifestDir(dir)
	if err != nil {
		t.Fatalf("loadManifestDir: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Errorf("want 1 artifact (bad.yaml skipped), got %d", len(m.Artifacts))
	}
}

func TestLoadManifestDir_AcceptsAnyVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "v2.yaml"), []byte("version: 2.0\nartifacts:\n  - collector: file\n    path: /etc/passwd\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v1.yaml"), []byte("version: 1.0\nartifacts:\n  - collector: file\n    path: /etc/shadow\n"), 0600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifestDir(dir)
	if err != nil {
		t.Fatalf("loadManifestDir: %v", err)
	}
	// Both files should load; version is no longer checked.
	if len(m.Artifacts) != 2 {
		t.Errorf("want 2 artifacts (version no longer gated), got %d", len(m.Artifacts))
	}
}

func TestLoadManifestDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	m, err := loadManifestDir(dir)
	if err != nil {
		t.Fatalf("loadManifestDir: %v", err)
	}
	if len(m.Artifacts) != 0 {
		t.Errorf("want 0 artifacts, got %d", len(m.Artifacts))
	}
}

func TestParseFileSize_Empty(t *testing.T) {
	n, err := parseFileSize("")
	if err != nil || n != 0 {
		t.Errorf("want (0, nil), got (%d, %v)", n, err)
	}
}

func TestParseFileSize_Bytes(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int64
	}{
		{"100b", 100}, {"100c", 100}, {"100B", 100},
	} {
		n, err := parseFileSize(tc.s)
		if err != nil || n != tc.want {
			t.Errorf("parseFileSize(%q): want %d, got %d, err %v", tc.s, tc.want, n, err)
		}
	}
}

func TestParseFileSize_Kilobytes(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int64
	}{
		{"1k", 1024}, {"1K", 1024}, {"1kb", 1024}, {"1KB", 1024}, {"2k", 2048},
	} {
		n, err := parseFileSize(tc.s)
		if err != nil || n != tc.want {
			t.Errorf("parseFileSize(%q): want %d, got %d, err %v", tc.s, tc.want, n, err)
		}
	}
}

func TestParseFileSize_Megabytes(t *testing.T) {
	n, err := parseFileSize("10mb")
	if err != nil || n != 10*1024*1024 {
		t.Errorf("parseFileSize(10mb): want %d, got %d err %v", 10*1024*1024, n, err)
	}
	n, err = parseFileSize("10MB")
	if err != nil || n != 10*1024*1024 {
		t.Errorf("parseFileSize(10MB): want %d, got %d err %v", 10*1024*1024, n, err)
	}
}

func TestParseFileSize_Gigabytes(t *testing.T) {
	n, err := parseFileSize("2g")
	if err != nil || n != 2*1024*1024*1024 {
		t.Errorf("parseFileSize(2g): want %d, got %d err %v", int64(2*1024*1024*1024), n, err)
	}
}

func TestParseFileSize_PlainNumber(t *testing.T) {
	n, err := parseFileSize("512")
	if err != nil || n != 512 {
		t.Errorf("parseFileSize(512): want 512, got %d err %v", n, err)
	}
}

func TestParseFileSize_Invalid(t *testing.T) {
	_, err := parseFileSize("notanumber")
	if err == nil {
		t.Error("want error for invalid size, got nil")
	}
}

func TestParseFileSize_Negative(t *testing.T) {
	_, err := parseFileSize("-1k")
	if err == nil {
		t.Error("want error for negative size, got nil")
	}
}

func TestLoadManifest_NewFields(t *testing.T) {
	yml := `
version: 1.0
artifacts:
  - collector: file
    path: /var/log
    supported_os: [linux, macos]
    max_depth: 2
    name_pattern: ["*.log", "*.txt"]
    exclude_name_pattern: ["*.tmp"]
    max_file_size: 10MB
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	a := m.Artifacts[0]
	if len(a.SupportedOS) != 2 || a.SupportedOS[0] != "linux" {
		t.Errorf("SupportedOS: got %v", a.SupportedOS)
	}
	if a.MaxDepth != 2 {
		t.Errorf("MaxDepth: want 2, got %d", a.MaxDepth)
	}
	if len(a.NamePattern) != 2 || a.NamePattern[0] != "*.log" {
		t.Errorf("NamePattern: got %v", a.NamePattern)
	}
	if len(a.ExcludeNamePattern) != 1 || a.ExcludeNamePattern[0] != "*.tmp" {
		t.Errorf("ExcludeNamePattern: got %v", a.ExcludeNamePattern)
	}
	if a.MaxFileSize != "10MB" {
		t.Errorf("MaxFileSize: want 10MB, got %q", a.MaxFileSize)
	}
}

func TestLoadManifest_UAC_UnknownFieldsIgnored(t *testing.T) {
	// UAC artifacts contain many fields Pathfinder doesn't use.
	// yaml.v3 must silently ignore them (no parse error).
	yml := `
version: 1.1
artifacts:
  - description: Collect bash history
    supported_os: [linux, macos]
    collector: file
    path: /home/user/.bash_history
    exclude_nologin_users: true
    max_depth: 3
    name_pattern: [".bash_history*"]
    max_file_size: 10mb
    condition: "test -f /home/user/.bash_history"
    foreach: "user in users"
    is_file_list: false
    file_type: [f]
    modifier: false
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest with UAC fields: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(m.Artifacts))
	}
	a := m.Artifacts[0]
	if a.Collector != "file" {
		t.Errorf("Collector: want file, got %q", a.Collector)
	}
	if a.MaxDepth != 3 {
		t.Errorf("MaxDepth: want 3, got %d", a.MaxDepth)
	}
	if a.MaxFileSize != "10mb" {
		t.Errorf("MaxFileSize: want 10mb, got %q", a.MaxFileSize)
	}
	// Unknown fields (condition, foreach, is_file_list, file_type, modifier) must not cause errors.
}

func TestLoadManifest_TabIndented(t *testing.T) {
	// UAC files use tabs for indentation; yaml.v3 rejects tabs without pre-processing.
	yml := "version: 1.0\nartifacts:\n  -\n\t\tdescription: Test\n\t\tcollector: file\n\t\tpath: /etc/passwd\n"
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest with tab-indented YAML: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(m.Artifacts))
	}
	if len(m.Artifacts[0].Path) != 1 || m.Artifacts[0].Path[0] != "/etc/passwd" {
		t.Errorf("unexpected path: %v", m.Artifacts[0].Path)
	}
}

func TestLoadManifest_PercentUserHome(t *testing.T) {
	yml := "version: 1.1\nartifacts:\n  - description: Test\n    collector: file\n    supported_os: [linux]\n    path: %user_home%/.config/app\n"
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if len(m.Artifacts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(m.Artifacts))
	}
	if len(m.Artifacts[0].Path) != 1 {
		t.Fatalf("want 1 path token, got %v", m.Artifacts[0].Path)
	}
	// loadManifest stores the internal placeholder; expandUserHomes expands it later.
	if m.Artifacts[0].Path[0] != uacUserHomePlaceholder+"/.config/app" {
		t.Errorf("want __user_home__/.config/app, got %q", m.Artifacts[0].Path[0])
	}
}

func TestExpandUserHomes_Placeholder(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
	f := writeTempFile(t, passwd)
	got := expandUserHomes(uacUserHomePlaceholder+"/.ssh", f)
	want := []string{"/root/.ssh", "/home/alice/.ssh"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("[%d] want %q, got %q", i, want[i], g)
		}
	}
}

func TestLoadManifest_PathPatternAndFileType(t *testing.T) {
	yml := `
version: 1.1
artifacts:
  - collector: file
    path: /
    path_pattern: ["*/.git/hooks/*"]
    file_type: [f, l]
    exclude_nologin_users: true
    ignore_date_range: false
    exclude_path_pattern: ["/dev", "/proc"]
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	a := m.Artifacts[0]
	if len(a.PathPattern) != 1 || a.PathPattern[0] != "*/.git/hooks/*" {
		t.Errorf("PathPattern: got %v", a.PathPattern)
	}
	if len(a.FileType) != 2 || a.FileType[0] != "f" || a.FileType[1] != "l" {
		t.Errorf("FileType: got %v", a.FileType)
	}
}

func TestResolveTokens_TempDirectory(t *testing.T) {
	// Tokens containing %temp_directory% are UAC-internal paths that don't
	// exist outside a UAC run; they must be silently dropped.
	got := resolveTokens([]string{"%temp_directory%/files/shell/bash_histfile.txt", "/etc/passwd"}, "/dev/null")
	if len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("want [/etc/passwd], got %v", got)
	}
}

func TestResolveTokens_TempDirectoryOnly(t *testing.T) {
	// Artifact whose only path token is %temp_directory%-based resolves to empty.
	got := resolveTokens([]string{"%temp_directory%/files/shell/bash_histfile.txt"}, "/dev/null")
	if len(got) != 0 {
		t.Errorf("want empty slice, got %v", got)
	}
}

func TestResolveTokens_UnknownPlaceholder(t *testing.T) {
	// Any token containing a % is a UAC-internal placeholder that cannot
	// resolve to a real path outside a UAC run; it must be silently dropped.
	got := resolveTokens([]string{"%output_directory%/files/logs.txt", "/etc/passwd"}, "/dev/null")
	if len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("want [/etc/passwd], got %v", got)
	}
}

func TestHasUACPlaceholder(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"%temp_directory%/files/logs.txt", true},
		{"%user_home%/.bashrc", true},
		{"%output_directory%/out.txt", true},
		{"/home/user/100%_done.log", false},   // literal % in filename, not a placeholder
		{"/Downloads/file%20name.pdf", false}, // URL-encoded, no closing %
		{"/etc/passwd", false},                // no %
		{"%%double%%", true},                  // degenerate: %% still matches
	}
	for _, tc := range cases {
		got := hasUACPlaceholder(tc.s)
		if got != tc.want {
			t.Errorf("hasUACPlaceholder(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestResolveTokens_LiteralPercentNotDropped(t *testing.T) {
	// A path with a literal % that is not a %placeholder% pattern must be preserved.
	got := resolveTokens([]string{"/home/user/100%_done.log"}, "/dev/null")
	if len(got) != 1 || got[0] != "/home/user/100%_done.log" {
		t.Errorf("want [/home/user/100%%_done.log], got %v", got)
	}
}

func TestEntryNameForPath_NoTraversal(t *testing.T) {
	cases := []struct {
		name, absPath, rel, outputDir string
	}{
		{"abs traversal", "/tmp/../../etc/shadow", "", ""},
		{"rel traversal in outputDir", "/x", "../../etc/cron.d/x", "/var/log"},
		{"dotdot outputDir", "/x", "evil", "../../../etc"},
		{"clean abs", "/etc/passwd", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := entryNameForPath(c.absPath, c.rel, c.outputDir)
			if !strings.HasPrefix(got, sseRootDir+"/") {
				t.Fatalf("entry %q does not start with %q/", got, sseRootDir)
			}
			for _, seg := range strings.Split(got, "/") {
				if seg == ".." {
					t.Fatalf("entry %q contains a .. component", got)
				}
			}
		})
	}
}

func TestResolveTargets_Provenance(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.log"), []byte("y"), 0600); err != nil {
		t.Fatal(err)
	}
	got := resolveTargets([]string{filepath.Join(dir, "*.log")}, "/dev/null")
	if len(got) != 2 {
		t.Fatalf("glob: got %d targets, want 2", len(got))
	}
	for _, rt := range got {
		if !rt.fromGlob {
			t.Errorf("glob match %s: fromGlob=false, want true", rt.path)
		}
		if rt.globBase != dir {
			t.Errorf("glob match %s: globBase=%q, want %q", rt.path, rt.globBase, dir)
		}
	}
	lit := resolveTargets([]string{"/etc/passwd"}, "/dev/null")
	if len(lit) != 1 || lit[0].fromGlob || lit[0].path != "/etc/passwd" {
		t.Errorf("literal: got %+v, want one {/etc/passwd false}", lit)
	}
}

func TestGlobBaseDir(t *testing.T) {
	cases := []struct{ pattern, want string }{
		{"/tmp/*.log", "/tmp"},
		{"/var/log/*/app.conf", "/var/log"},
		{"/home/alice/.ssh/*", "/home/alice/.ssh"},
		{"/*.conf", "/"},
	}
	for _, c := range cases {
		if got := globBaseDir(c.pattern); got != c.want {
			t.Errorf("globBaseDir(%q) = %q, want %q", c.pattern, got, c.want)
		}
	}
}

func TestLoadManifest_MaxFileSizeIntegerYAML(t *testing.T) {
	// UAC specifies max_file_size as an unquoted integer (e.g. 1073741824).
	// yaml.v3 converts integer scalars to string fields as their decimal string.
	yml := `
version: 1.1
artifacts:
  - collector: file
    path: /var/log
    max_file_size: 1073741824
`
	f := writeTempFile(t, yml)
	m, err := loadManifest(f)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	a := m.Artifacts[0]
	if a.MaxFileSize != "1073741824" {
		t.Errorf("MaxFileSize: want \"1073741824\", got %q", a.MaxFileSize)
	}
	n, err := parseFileSize(a.MaxFileSize)
	if err != nil {
		t.Fatalf("parseFileSize(%q): %v", a.MaxFileSize, err)
	}
	const wantBytes = int64(1073741824)
	if n != wantBytes {
		t.Errorf("parseFileSize: want %d bytes (1 GB), got %d", wantBytes, n)
	}
}
