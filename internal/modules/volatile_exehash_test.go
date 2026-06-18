package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileNoAtime_CorrectDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFileNoAtime(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
