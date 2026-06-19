package ioc_test

import (
	"testing"

	"github.com/pathfinder/internal/ioc"
)

func TestMatchProcess_AnchoredLiteral(t *testing.T) {
	sh := &ioc.IOCSet{Processes: []ioc.Matcher{{Raw: "sh", IsLiteral: true}}}
	cases := []struct {
		in   string
		want bool
	}{
		{"sh", true},      // exact comm
		{"/bin/sh", true}, // basename
		{"bash", false},   // substring FP
		{"ssh", false},    // substring FP
		{"flush", false},  // substring FP
	}
	for _, c := range cases {
		if _, ok := sh.MatchProcess(c.in); ok != c.want {
			t.Errorf("MatchProcess(%q) = %v, want %v", c.in, ok, c.want)
		}
	}
}

func TestMatchFilename_BoundedLiteral(t *testing.T) {
	sh := &ioc.IOCSet{Filenames: []ioc.Matcher{{Raw: "evil.sh", IsLiteral: true}}}
	cases := []struct {
		in   string
		want bool
	}{
		{"/tmp/evil.sh", true},      // path segment
		{"evil.sh", true},           // bare
		{"ran evil.sh today", true}, // word-bounded
		{"myevil.sh", false},        // left boundary fail
		{"evil.shar", false},        // right boundary fail
	}
	for _, c := range cases {
		if _, ok := sh.MatchFilename(c.in); ok != c.want {
			t.Errorf("MatchFilename(%q) = %v, want %v", c.in, ok, c.want)
		}
	}
}

func TestMatchProcess_RegexUnchanged(t *testing.T) {
	m, err := ioc.CompileMatcherForTest("regex:kworker/u[0-9]+")
	if err != nil {
		t.Fatal(err)
	}
	sh := &ioc.IOCSet{Processes: []ioc.Matcher{m}}
	if _, ok := sh.MatchProcess("kworker/u8:1"); !ok {
		t.Error("regex process matcher should still match")
	}
}

func TestHashLengths(t *testing.T) {
	sh := &ioc.IOCSet{Hashes: map[string]struct{}{
		"5eb63bbbe01eeed093cb22bb8f5acdc3":                                 {}, // md5 (32)
		"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed":                         {}, // sha1 (40)
		"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9": {}, // sha256 (64)
	}}
	md5, sha1, sha256 := sh.HashLengths()
	if !md5 || !sha1 || !sha256 {
		t.Errorf("HashLengths() = %v/%v/%v, want all true", md5, sha1, sha256)
	}

	empty := &ioc.IOCSet{Hashes: map[string]struct{}{}}
	if m, s, x := empty.HashLengths(); m || s || x {
		t.Errorf("empty HashLengths() = %v/%v/%v, want all false", m, s, x)
	}
}
