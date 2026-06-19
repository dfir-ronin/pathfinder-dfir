package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SuppressEngine is implemented by suppress.Engine; kept as interface to avoid import cycle.
type SuppressEngine interface {
	Check(module, label, msg string) (bool, string)
	Counts() (profile, user int)
}

type Severity string

const (
	HIGH   Severity = "HIGH"
	MEDIUM Severity = "MEDIUM"
	LOW    Severity = "LOW"
	INFO   Severity = "INFO"
)

// ANSI colours (Blade Runner palette: crimson / forest / sage / orange / ochre / amber)
const (
	cCrimson = "\033[38;5;160m" // deep crimson (banner, HIGH)
	cOrange  = "\033[38;5;166m" // burnt orange (MEDIUM)
	cOchre   = "\033[38;5;178m" // golden ochre (LOW)
	cAmber   = "\033[38;5;136m" // dark amber (Warn)
	cForest  = "\033[38;5;22m"  // dark forest green (Chapter, Ok)
	cSage    = "\033[38;5;64m"  // muted sage (banner art, metadata, Info)
	cGray    = "\033[2;37m"     // dim gray (INFO, Note, Skip)
	cWhite   = "\033[1;37m"     // bright white (chapter title)
	cReset   = "\033[0m"
)

var quietMode bool

// SetQuiet suppresses all informational stdout output. Findings are still
// registered; only terminal UI output is silenced.
func SetQuiet(b bool) { quietMode = b }

// Finding represents a single triage observation
type Finding struct {
	Severity  Severity
	Module    string
	Label     string
	Message   string
	Timestamp time.Time
}

// Registry is a thread-safe store for findings
type Registry struct {
	mu             sync.Mutex
	findings       []Finding
	engine         SuppressEngine
	showSuppressed bool
}

func NewRegistry() *Registry { return &Registry{} }

// SetEngine attaches a suppression engine. Call once before Add is called concurrently.
func (r *Registry) SetEngine(e SuppressEngine) { r.engine = e }

// SetShowSuppressed controls whether suppressed findings are printed with a [SUPPRESSED] tag.
func (r *Registry) SetShowSuppressed(b bool) { r.showSuppressed = b }

// Engine returns the attached SuppressEngine and true, or nil and false if none is set.
func (r *Registry) Engine() (SuppressEngine, bool) { return r.engine, r.engine != nil }

// ParseSeverity converts a string to a Severity, returning an error for unknown values.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case HIGH, MEDIUM, LOW, INFO:
		return Severity(s), nil
	default:
		return LOW, fmt.Errorf("unknown severity %q", s)
	}
}

func (r *Registry) Add(sev Severity, module, label, msg string) {
	if r.engine != nil {
		if suppressed, _ := r.engine.Check(module, label, msg); suppressed {
			if r.showSuppressed {
				printSuppressed(sev, msg)
			}
			return
		}
	}
	r.mu.Lock()
	r.findings = append(r.findings, Finding{
		Severity:  sev,
		Module:    module,
		Label:     label,
		Message:   msg,
		Timestamp: time.Now().UTC(),
	})
	r.mu.Unlock()
	printFinding(sev, msg)
}

// AddSilent stores the finding in the registry without printing to the console.
// Use it when the finding must appear in findings_summary.txt and Report.md
// but should not emit a live terminal line (e.g. overflow detections beyond a console cap).
func (r *Registry) AddSilent(sev Severity, module, label, msg string) {
	if r.engine != nil {
		if suppressed, _ := r.engine.Check(module, label, msg); suppressed {
			return
		}
	}
	r.mu.Lock()
	r.findings = append(r.findings, Finding{
		Severity:  sev,
		Module:    module,
		Label:     label,
		Message:   msg,
		Timestamp: time.Now().UTC(),
	})
	r.mu.Unlock()
}

func (r *Registry) All() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

func (r *Registry) Counts() (high, medium, low, info int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.findings {
		switch f.Severity {
		case HIGH:
			high++
		case MEDIUM:
			medium++
		case LOW:
			low++
		case INFO:
			info++
		}
	}
	return
}

type FindingCounts struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type FindingJSON struct {
	Severity  string    `json:"severity"`
	Module    string    `json:"module"`
	Label     string    `json:"label"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type FindingsReport struct {
	CaseID   string        `json:"case_id"`
	Host     string        `json:"host"`
	ScanTime time.Time     `json:"scan_time"`
	Verdict  string        `json:"verdict"`
	Counts   FindingCounts `json:"counts"`
	Findings []FindingJSON `json:"findings"`
	OS       string        `json:"os,omitempty"`
	Arch     string        `json:"arch,omitempty"`
	CPU      string        `json:"cpu,omitempty"`
	MemTotal string        `json:"mem_total,omitempty"`
	TimeZone string        `json:"timezone,omitempty"`
	Mounts   []string      `json:"mounts,omitempty"`
	TempDir  string        `json:"temp_dir,omitempty"`
	Kernel   string        `json:"kernel,omitempty"`
	IPs      []string      `json:"ips,omitempty"`
}

// WriteJSONReport serialises all findings plus metadata to path as indented JSON.
func (r *Registry) WriteJSONReport(path string, report FindingsReport) error {
	findings := r.All()
	report.Findings = make([]FindingJSON, 0, len(findings))
	for _, f := range findings {
		report.Findings = append(report.Findings, FindingJSON{
			Severity:  string(f.Severity),
			Module:    f.Module,
			Label:     f.Label,
			Message:   f.Message,
			Timestamp: f.Timestamp,
		})
	}
	h, m, l, _ := r.Counts()
	report.Counts = FindingCounts{High: h, Medium: m, Low: l}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func sevLabel(sev Severity) string {
	switch sev {
	case HIGH:
		return "[ HIGH ]"
	case MEDIUM:
		return "[MEDIUM]"
	case LOW:
		return "[ LOW  ]"
	case INFO:
		return "[ INFO ]"
	default:
		return "[" + string(sev) + "]"
	}
}

func printFinding(sev Severity, msg string) {
	if quietMode {
		return
	}
	var col string
	switch sev {
	case HIGH:
		col = cCrimson
	case MEDIUM:
		col = cOrange
	case LOW:
		col = cOchre
	case INFO:
		col = cGray
	}
	fmt.Printf("%s  ▸ %s%s %s\n", col, sevLabel(sev), cReset, msg)
}

func printSuppressed(sev Severity, msg string) {
	if quietMode {
		return
	}
	fmt.Printf("%s  ▸ [SUPPRESSED] %s%s %s\n", cGray, sevLabel(sev), cReset, msg)
}

// Writer writes output to a single named file
type Writer struct {
	path    string
	f       io.Writer
	mu      sync.Mutex
	onClose func(string)
}

func NewWriter(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return &Writer{path: path, f: f}, nil
}

// NewWriterFromIO creates a Writer backed by an existing io.Writer.
// Path is always ""; onClose is called with "" on Close if set.
func NewWriterFromIO(w io.Writer) *Writer {
	return &Writer{f: w}
}

func (w *Writer) WriteHeader(label, source string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	hr := strings.Repeat("─", 60)
	fmt.Fprintf(w.f, "# Label     : %s\n", label)
	fmt.Fprintf(w.f, "# Source    : %s\n", source)
	fmt.Fprintf(w.f, "# Timestamp : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w.f, "%s\n\n", hr)
}

func (w *Writer) Write(format string, args ...interface{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(w.f, format, args...)
}

func (w *Writer) WriteString(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprint(w.f, s)
}

func (w *Writer) WriteSectionHeader(title string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	hr := strings.Repeat("─", 60)
	fmt.Fprintf(w.f, "\n%s\n# %s\n%s\n\n", hr, title, hr)
}

func (w *Writer) SetOnClose(fn func(string)) { w.onClose = fn }

func (w *Writer) Close() {
	if w.f != nil {
		if c, ok := w.f.(io.Closer); ok {
			c.Close()
		}
	}
	if w.onClose != nil {
		w.onClose(w.path)
	}
}

func (w *Writer) Path() string { return w.path }

// MasterLog is a structured command/event log
type MasterLog struct {
	f  *os.File
	mu sync.Mutex
}

func NewMasterLog(path string) (*MasterLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return &MasterLog{f: f}, nil
}

func (m *MasterLog) Log(module, action, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(m.f, "%s\t%s\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339),
		module, action, detail)
}

func (m *MasterLog) Close() {
	if m.f != nil {
		m.f.Close()
	}
}

// Chapter prints a section heading to stdout
func Chapter(title string) {
	if quietMode {
		return
	}
	h := strings.Repeat("─", 80)
	fmt.Printf("\n%s  ┌%s┐%s\n", cForest, h, cReset)
	fmt.Printf("%s  │%s  %-78s%s%s│%s\n", cForest, cWhite, title, cReset, cForest, cReset)
	fmt.Printf("%s  └%s┘%s\n\n", cForest, h, cReset)
}

func Info(msg string) {
	if !quietMode {
		fmt.Printf("%s  [~] %s%s\n", cSage, msg, cReset)
	}
}
func Ok(msg string) {
	if !quietMode {
		fmt.Printf("%s  [+] %s%s\n", cForest, msg, cReset)
	}
}
func Warn(msg string) {
	if !quietMode {
		fmt.Printf("%s  [!] %s%s\n", cAmber, msg, cReset)
	}
}
func Note(msg string) {
	if !quietMode {
		fmt.Printf("%s  [~] %s%s\n", cGray, msg, cReset)
	}
}
func Skip(msg string) {
	if !quietMode {
		fmt.Printf("%s  [-] SKIPPED — %s%s\n", cGray, msg, cReset)
	}
}

// Colour accessors (Blade Runner palette)
func CrimsonColor() string { return cCrimson }
func ForestColor() string  { return cForest }
func SageColor() string    { return cSage }
func OrangeColor() string  { return cOrange }
func OchreColor() string   { return cOchre }
func GrayColor() string    { return cGray }
func AmberColor() string   { return cAmber }
func WhiteColor() string   { return cWhite }
func ResetColor() string   { return cReset }
