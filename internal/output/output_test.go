package output

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRegistry_ConcurrentAdd(t *testing.T) {
	SetQuiet(true)
	t.Cleanup(func() { SetQuiet(false) })

	r := NewRegistry()
	const goroutines = 50
	const perGoroutine = 21 // divisible by 3 for even per-severity counts

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				switch j % 3 {
				case 0:
					r.Add(HIGH, "test", "high finding", "high finding")
				case 1:
					r.Add(MEDIUM, "test", "medium finding", "medium finding")
				case 2:
					r.Add(LOW, "test", "low finding", "low finding")
				}
			}
		}(i)
	}
	wg.Wait()

	total := goroutines * perGoroutine
	all := r.All()
	if len(all) != total {
		t.Fatalf("expected %d findings, got %d", total, len(all))
	}

	high, medium, low, _ := r.Counts()
	perSev := goroutines * (perGoroutine / 3) // 7 of each severity per goroutine
	if high != perSev || medium != perSev || low != perSev {
		t.Fatalf("counts mismatch: high=%d medium=%d low=%d (want %d each)", high, medium, low, perSev)
	}
}

type mockEngine struct {
	suppress bool
}

func (m *mockEngine) Check(module, label, msg string) (bool, string) {
	if m.suppress {
		return true, "profile"
	}
	return false, ""
}

func (m *mockEngine) Counts() (profile, user int) { return 0, 0 }

func TestRegistry_SuppressedFindingNotStored(t *testing.T) {
	SetQuiet(true)
	t.Cleanup(func() { SetQuiet(false) })

	r := NewRegistry()
	r.SetEngine(&mockEngine{suppress: true})
	r.Add(HIGH, "test", "test label", "test message")

	if len(r.All()) != 0 {
		t.Fatalf("suppressed finding should not be stored in registry")
	}
	h, m, l, _ := r.Counts()
	if h+m+l != 0 {
		t.Fatalf("suppressed finding should not affect severity counts")
	}
}

func TestRegistry_UnsuppressedFindingStored(t *testing.T) {
	SetQuiet(true)
	t.Cleanup(func() { SetQuiet(false) })

	r := NewRegistry()
	r.SetEngine(&mockEngine{suppress: false})
	r.Add(HIGH, "test", "test label", "test message")

	if len(r.All()) != 1 {
		t.Fatalf("unsuppressed finding should be stored")
	}
}

func TestRegistry_NilEngineStoresAll(t *testing.T) {
	SetQuiet(true)
	t.Cleanup(func() { SetQuiet(false) })

	r := NewRegistry()
	r.Add(MEDIUM, "test", "test label", "test message")

	if len(r.All()) != 1 {
		t.Fatalf("finding should be stored when no engine is set")
	}
}

func TestAddSilent_StoresWithoutPrinting(t *testing.T) {
	SetQuiet(true)
	t.Cleanup(func() { SetQuiet(false) })

	r := NewRegistry()
	r.AddSilent(HIGH, "test", "silent label", "silent message")
	all := r.All()
	if len(all) != 1 {
		t.Fatalf("want 1 finding, got %d", len(all))
	}
	if all[0].Label != "silent label" {
		t.Errorf("unexpected label: %s", all[0].Label)
	}
}

func TestNewWriterFromIO_WritesContent(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterFromIO(&buf)
	w.Write("hello %s", "world")
	w.Close()
	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("got %q", buf.String())
	}
}

func TestNewWriterFromIO_CloseCallsUnderlyingCloser(t *testing.T) {
	closed := false
	wc := &testWriteCloser{closeFunc: func() { closed = true }}
	w := NewWriterFromIO(wc)
	w.Close()
	if !closed {
		t.Error("Close did not call underlying io.Closer")
	}
}

func TestNewWriterFromIO_CloseOnPlainWriterDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterFromIO(&buf) // bytes.Buffer is not io.Closer
	w.Close()                  // must not panic
}

func TestNewWriter_StillWritesToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.txt")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	w.Write("on disk")
	w.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file not readable after Close: %v", err)
	}
	if !strings.Contains(string(data), "on disk") {
		t.Errorf("unexpected content: %q", string(data))
	}
}

type testWriteCloser struct {
	bytes.Buffer
	closeFunc func()
}

func (m *testWriteCloser) Close() error {
	if m.closeFunc != nil {
		m.closeFunc()
	}
	return nil
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"HIGH", HIGH, false},
		{"MEDIUM", MEDIUM, false},
		{"LOW", LOW, false},
		{"INFO", INFO, false},
		{"low", LOW, true},
		{"", LOW, true},
		{"CRITICAL", LOW, true},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseSeverity(%q): wantErr=%v got err=%v", c.in, c.wantErr, err)
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseSeverity(%q): want %q got %q", c.in, c.want, got)
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++
			}
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

func TestChapterBorderWidth(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = pw

	Chapter("[TEST] short title")

	pw.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, pr)

	found := false
	for _, line := range strings.Split(buf.String(), "\n") {
		clean := stripANSI(line)
		if strings.Contains(clean, "┌") {
			found = true
			got := len([]rune(clean))
			if got != 84 {
				t.Errorf("chapter border width = %d, want 84", got)
			}
		}
	}
	if !found {
		t.Error("no border line found in Chapter output")
	}
}

func TestPrintFindingNoPaddedBrackets(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = pw

	printFinding(HIGH, "msg")
	printFinding(LOW, "msg")
	printFinding(INFO, "msg")

	pw.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, pr)
	got := buf.String()

	for _, want := range []string{"[ HIGH ]", "[ LOW  ]", "[ INFO ]"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got: %q", want, got)
		}
	}
}
