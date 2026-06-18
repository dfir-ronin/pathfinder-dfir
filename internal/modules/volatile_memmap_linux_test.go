//go:build linux

package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyMapLine_DeletedFileEACCES_Suppressed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "locked.so")
	if err := os.WriteFile(f, []byte("x"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	line := fmt.Sprintf("7f00-7f01 r-xp 00000000 fd:01 1 %s (deleted)", f)
	_, _, ok := classifyMapLine(line)
	if ok {
		t.Error("want false: EACCES on stat must not produce anomaly")
	}
}
