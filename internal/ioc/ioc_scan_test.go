package ioc_test

import (
	"strings"
	"testing"

	"github.com/pathfinder/internal/ioc"
)

func TestIOCScanText_LongLineNotDropped(t *testing.T) {
	// A single line well beyond bufio.Scanner's 64 KB default token size,
	// with the indicator at the end (minified webshell / base64 blob shape).
	long := strings.Repeat("a", 100000) + " needle"
	matchers := []ioc.Matcher{{Raw: "needle", IsLiteral: true}}
	hits := ioc.IOCScanText(long, matchers)
	if len(hits) != 1 {
		t.Fatalf("got %d hits on a >64KB line, want 1 (line was silently dropped)", len(hits))
	}
}
