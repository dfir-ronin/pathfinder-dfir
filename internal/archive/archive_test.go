package archive

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWriteManifest_ContainsExpectedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.txt")
	start := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 17, 10, 5, 0, 0, time.UTC)

	p := ManifestParams{
		CaseID:        "CASE-001",
		Examiner:      "analyst",
		Notes:         "test note",
		Hostname:      "target-host",
		OS:            "Ubuntu 22.04",
		Arch:          "amd64",
		IPs:           []string{"10.0.0.1"},
		Mounts:        []string{"/dev/sda1 /"},
		StartTime:     start,
		EndTime:       end,
		Mode:          "full",
		ManifestPath:  "/opt/uac",
		IOCFile:       "",
		SuppressFile:  "",
		Stealth:       false,
		Artifacts:     10,
		Collected:     42,
		Skipped:       2,
		MainZipPath:   "/tmp/pathfinder.zip",
		MainZipSize:   2 * 1024 * 1024,
		MainZipMD5:    "aabbcc",
		MainZipSHA256: "ddeeff",
		SSEZipPath:    "/tmp/pathfinder-sse.zip",
		SSEZipSize:    1024 * 1024 * 1024,
		SSEZipSHA256:  "445566",
	}

	if err := WriteManifest(path, p); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	for _, want := range []string{
		"PATHFINDER ACQUISITION MANIFEST",
		"Case ID:",
		"CASE-001",
		"analyst",
		"test note",
		"target-host",
		"Ubuntu 22.04",
		"amd64",
		"10.0.0.1",
		"/dev/sda1 /",
		"2026-05-17T10:00:00Z",
		"2026-05-17T10:05:00Z",
		"full",
		"/opt/uac",
		"(none)",            // IOCFile empty → (none)
		"Artifacts:     10", // Artifacts
		"Collected:     42 files",
		"Skipped:       2 files",
		"pathfinder.zip",
		"2.0 MB",
		"aabbcc",
		"ddeeff",
		"pathfinder-sse.zip",
		"1.0 GB",
		"445566",
		"<- authoritative", // SSE inline marker
		"SHA-256 is authoritative",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
}

func TestWriteManifest_NoSSESection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.txt")
	p := ManifestParams{
		CaseID:        "X",
		Examiner:      "e",
		Hostname:      "h",
		StartTime:     time.Now(),
		EndTime:       time.Now(),
		Mode:          "full",
		MainZipPath:   "/tmp/main.zip",
		MainZipMD5:    "aa",
		MainZipSHA256: "bb",
		// SSEZipPath intentionally empty
	}
	if err := WriteManifest(path, p); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "SSE:") {
		t.Error("manifest should not contain SSE section when SSEZipPath is empty")
	}
}

func TestFormatSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tc := range cases {
		got := formatSize(tc.n)
		if got != tc.want {
			t.Errorf("formatSize(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestFileHashes(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hello")
	f.Close()

	md5sum, sha256sum, err := FileHashes(f.Name())
	if err != nil {
		t.Fatalf("FileHashes: %v", err)
	}
	// echo -n "hello" | md5sum
	wantMD5 := "5d41402abc4b2a76b9719d911017c592"
	// echo -n "hello" | sha256sum
	wantSHA := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if md5sum != wantMD5 {
		t.Errorf("md5 = %q, want %q", md5sum, wantMD5)
	}
	if sha256sum != wantSHA {
		t.Errorf("sha256 = %q, want %q", sha256sum, wantSHA)
	}
}

func TestFlushDirToZip_AddsEntries(t *testing.T) {
	srcDir := t.TempDir()
	subDir := filepath.Join(srcDir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "a.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("world"), 0600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	baseDir := filepath.Dir(srcDir)

	if _, err := FlushDirToZip(zw, srcDir, baseDir); err != nil {
		t.Fatalf("FlushDirToZip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}

	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}

	srcName := filepath.Base(srcDir)
	wantA := srcName + "/sub/a.txt"
	wantB := srcName + "/b.txt"
	if !names[wantA] {
		t.Errorf("expected entry %q; got %v", wantA, names)
	}
	if !names[wantB] {
		t.Errorf("expected entry %q; got %v", wantB, names)
	}
}

func TestFileHashes_NonEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
		t.Fatal(err)
	}
	md5sum, sha256sum, err := FileHashes(path)
	if err != nil {
		t.Fatalf("FileHashes: %v", err)
	}
	if md5sum == "" || sha256sum == "" {
		t.Error("FileHashes returned empty hashes")
	}
	// deterministic
	md5b, sha256b, _ := FileHashes(path)
	if md5sum != md5b || sha256sum != sha256b {
		t.Error("FileHashes is not deterministic")
	}
}

func TestVerifyZip_TruncatedArchive(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.zip")
	if err := os.WriteFile(bad, []byte("not a zip file at all"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyZip(bad); err == nil {
		t.Fatalf("VerifyZip on garbage returned nil error, want error")
	}
}

func TestVerifyZip_GoodArchive_CRC(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "good.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	hdr := &zip.FileHeader{Name: "a.txt", Method: zip.Store}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	count, err := VerifyZip(zipPath)
	if err != nil {
		t.Fatalf("VerifyZip on good archive: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestWriteManifestRendersArchiveSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.txt")
	p := ManifestParams{
		CaseID:         "PF-1",
		MainZipPath:    "/tmp/PF-1.zip",
		ArchiveSkipped: []string{"/var/log/locked.bin", "/etc/secret"},
	}
	if err := WriteManifest(path, p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"Unreadable (not archived): 2 files",
		"/var/log/locked.bin",
		"/etc/secret",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, got)
		}
	}
}

func TestVerifyZip_CorruptEntryDetected(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "bad.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// Store (uncompressed) so the literal bytes appear in the file and can be
	// flipped, producing a CRC mismatch while the central directory stays intact.
	hdr := &zip.FileHeader{Name: "a.txt", Method: zip.Store}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	raw, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	idx := bytes.Index(raw, []byte("hello world"))
	if idx < 0 {
		t.Fatal("stored content not found in zip")
	}
	raw[idx] = 'H' // corrupt one byte of the stored data
	if err := os.WriteFile(zipPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyZip(zipPath); err == nil {
		t.Error("VerifyZip accepted an archive with a corrupt entry; want error")
	}
}

func TestFlushDirToZipStoresSymlinkWithoutFollowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	base := t.TempDir()
	src := filepath.Join(base, "out")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	// Secret lives OUTSIDE the walked dir; the only way its bytes reach the
	// zip is by following the symlink.
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(src, "notes.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "out.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	skipped, err := FlushDirToZip(zw, src, base)
	if err != nil {
		t.Fatalf("flush returned fatal error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Errorf("symlink should be stored, not skipped; got %v", skipped)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var found *zip.File
	for _, f := range zr.File {
		if f.Name == "out/notes.txt" {
			found = f
		}
	}
	if found == nil {
		t.Fatal("expected entry out/notes.txt")
	}
	if found.Mode()&os.ModeSymlink == 0 {
		t.Errorf("entry should carry symlink mode bits, mode=%v", found.Mode())
	}
	rc, err := found.Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(content) == "TOPSECRET" {
		t.Fatal("symlink was followed: target content leaked into archive")
	}
	if string(content) != secret {
		t.Errorf("symlink entry content = %q, want target path %q", content, secret)
	}
}

func TestFlushDirToZipSkipsUnreadableFileWithoutPhantomEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based unreadable file not enforceable on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	base := t.TempDir()
	src := filepath.Join(base, "out")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(src, "good.txt")
	if err := os.WriteFile(good, []byte("readable"), 0644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(src, "bad.bin")
	if err := os.WriteFile(bad, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0644) })

	zipPath := filepath.Join(base, "out.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	skipped, err := FlushDirToZip(zw, src, base)
	if err != nil {
		t.Fatalf("flush returned fatal error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}

	foundSkip := false
	for _, s := range skipped {
		if s == bad {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected %s in skip list, got %v", bad, skipped)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if strings.HasSuffix(f.Name, "bad.bin") {
			t.Errorf("unreadable file leaked into archive as entry %q", f.Name)
		}
	}
	hasGood := false
	for _, n := range names {
		if strings.HasSuffix(n, "good.txt") {
			hasGood = true
		}
	}
	if !hasGood {
		t.Errorf("readable file missing from archive; entries=%v", names)
	}
}
