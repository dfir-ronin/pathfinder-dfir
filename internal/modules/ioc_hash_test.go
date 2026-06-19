//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pathfinder/internal/ioc"
)

func TestHashFileDigests_AllThree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	md5h, sha1h, sha256h, err := hashFileDigests(path, 0, true, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if md5h != "5eb63bbbe01eeed093cb22bb8f5acdc3" {
		t.Errorf("md5 = %q", md5h)
	}
	if sha1h != "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" {
		t.Errorf("sha1 = %q", sha1h)
	}
	if sha256h != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Errorf("sha256 = %q", sha256h)
	}
}

func TestHashFileDigests_OnlyRequested(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	md5h, sha1h, sha256h, err := hashFileDigests(path, 0, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if md5h != "" || sha1h != "" {
		t.Errorf("unrequested digests not empty: md5=%q sha1=%q", md5h, sha1h)
	}
	if sha256h == "" {
		t.Error("sha256 requested but empty")
	}
}

func TestHashFileDigests_TooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	if err := os.WriteFile(path, make([]byte, 200), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hashFileDigests(path, 100, true, true, true); err != errFileTooLarge {
		t.Errorf("want errFileTooLarge, got %v", err)
	}
}

func TestIocLiveScanners_NilProcs(t *testing.T) {
	ctx := makeTestCtx(t)
	w := newSectionWriter(ctx, ctx.Dirs.IOC, "01_test.txt", "test", "src")
	defer w.Close()
	sh := &ioc.IOCSet{}
	if n := iocScanLiveCmdlines(ctx, w, sh, nil); n != 0 {
		t.Errorf("cmdlines: got %d, want 0", n)
	}
	if n := iocScanLiveProcesses(ctx, w, sh, nil); n != 0 {
		t.Errorf("processes: got %d, want 0", n)
	}
}
