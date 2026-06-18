package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileCapped_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(p, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	data, trunc, err := ReadFileCapped(p, 1024)
	if err != nil {
		t.Fatalf("ReadFileCapped: %v", err)
	}
	if trunc {
		t.Error("trunc=true for a file under the limit")
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want %q", data, "hello")
	}
}

func TestReadFileCapped_OverLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(p, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	data, trunc, err := ReadFileCapped(p, 4)
	if err != nil {
		t.Fatalf("ReadFileCapped: %v", err)
	}
	if !trunc {
		t.Error("trunc=false for a file over the limit")
	}
	if string(data) != "0123" {
		t.Errorf("data = %q, want first 4 bytes %q", data, "0123")
	}
}

func TestReadFileCapped_ExactLimitNotTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "exact.txt")
	if err := os.WriteFile(p, []byte("abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	data, trunc, err := ReadFileCapped(p, 4)
	if err != nil {
		t.Fatalf("ReadFileCapped: %v", err)
	}
	if trunc {
		t.Error("a file exactly at the limit must not report truncated")
	}
	if string(data) != "abcd" {
		t.Errorf("data = %q, want %q", data, "abcd")
	}
}

func TestReadFileCapped_MissingFileErrors(t *testing.T) {
	if _, _, err := ReadFileCapped(filepath.Join(t.TempDir(), "nope"), 16); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestFormatFileSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{3901166, "3.7 MiB"},
		{1048576, "1.0 MiB"},
		{2621440, "2.5 MiB"},
		{1073741824, "1.0 GiB"},
		{2469606195, "2.3 GiB"},
	}
	for _, tc := range cases {
		got := FormatFileSize(tc.n)
		if got != tc.want {
			t.Errorf("FormatFileSize(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestIsCommentOrBlank(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"# comment", true},
		{"   # indented", true},
		{"real line", false},
		{"key = value # trailing", false},
	}
	for _, c := range cases {
		if got := IsCommentOrBlank(c.in); got != c.want {
			t.Errorf("IsCommentOrBlank(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestFormatFileSize_Binary(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
	}
	for _, c := range cases {
		if got := FormatFileSize(c.in); got != c.want {
			t.Errorf("FormatFileSize(%d)=%q want %q", c.in, got, c.want)
		}
	}
}
