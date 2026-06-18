package modules

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/output"
)

func TestIocCheckDpkgHashesDir_RegistersMatch(t *testing.T) {
	dir := t.TempDir()
	// md5 of "hello world" is 5eb63bbbe01eeed093cb22bb8f5acdc3.
	md5 := "5eb63bbbe01eeed093cb22bb8f5acdc3"
	content := md5 + "  usr/bin/foo\n"
	if err := os.WriteFile(filepath.Join(dir, "pkg.md5sums"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	sh := &ioc.IOCSet{Hashes: map[string]struct{}{md5: {}}}
	ctx := &ModuleContext{Registry: output.NewRegistry()}
	w := output.NewWriterFromIO(&bytes.Buffer{})
	count := 0

	iocCheckDpkgHashesDir(ctx, w, sh, &count, dir)

	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	high, _, _, _ := ctx.Registry.Counts()
	if high != 1 {
		t.Errorf("registry HIGH = %d, want 1 (dpkg hit must reach the Registry)", high)
	}
}
