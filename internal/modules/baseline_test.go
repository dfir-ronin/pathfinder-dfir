package modules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pathfinder/internal/output"
)

func TestMatchTaintBits_OOTisMediumNotHigh(t *testing.T) {
	// bit 12 (4096) = TAINT_OOT_MODULE -- must be MEDIUM, not HIGH
	matched, highest, unknown := matchTaintBits(1 << 12)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].sev != output.MEDIUM {
		t.Errorf("bit 12 severity: want MEDIUM, got %s", matched[0].sev)
	}
	if unknown != 0 {
		t.Errorf("unexpected unknown bits: 0x%x", unknown)
	}
	if highest != output.MEDIUM {
		t.Errorf("bit 12 highest: want MEDIUM, got %s", highest)
	}
}

func TestMatchTaintBits_UnsignedIsHigh(t *testing.T) {
	// bit 13 (8192) = TAINT_UNSIGNED_MODULE -- must be HIGH
	matched, highest, _ := matchTaintBits(1 << 13)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].sev != output.HIGH {
		t.Errorf("bit 13 severity: want HIGH, got %s", matched[0].sev)
	}
	if highest != output.HIGH {
		t.Errorf("highest: want HIGH, got %s", highest)
	}
}

func TestMatchTaintBits_UnknownBits(t *testing.T) {
	// bit 18 (1<<18 = 262144) is beyond the table
	matched, highest, unknown := matchTaintBits(1 << 18)
	if len(matched) != 0 {
		t.Errorf("expected 0 known matches, got %d", len(matched))
	}
	if unknown == 0 {
		t.Error("expected non-zero unknown bits")
	}
	if highest != output.MEDIUM {
		t.Errorf("unknown bits should escalate to MEDIUM, got %s", highest)
	}
}

func TestMatchTaintBits_Zero(t *testing.T) {
	matched, highest, unknown := matchTaintBits(0)
	if len(matched) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matched))
	}
	if highest != output.LOW {
		t.Errorf("expected LOW for clean kernel, got %s", highest)
	}
	if unknown != 0 {
		t.Errorf("expected 0 unknown bits, got 0x%x", unknown)
	}
}

func TestMatchTaintBits_ForcedLoadIsHigh(t *testing.T) {
	// bit 1 (2) = TAINT_FORCED_MODULE -- must stay HIGH
	_, highest, _ := matchTaintBits(1 << 1)
	if highest != output.HIGH {
		t.Errorf("bit 1 highest: want HIGH, got %s", highest)
	}
}

func TestParseModuleTaintLetters_OE(t *testing.T) {
	got := parseModuleTaintLetters("(OE)")
	if !got['O'] {
		t.Error("expected O flag")
	}
	if !got['E'] {
		t.Error("expected E flag")
	}
}

func TestParseModuleTaintLetters_Empty(t *testing.T) {
	got := parseModuleTaintLetters("")
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestParseModuleTaintLetters_LowercaseIgnored(t *testing.T) {
	got := parseModuleTaintLetters("(live)")
	if len(got) != 0 {
		t.Errorf("expected empty map for lowercase, got %v", got)
	}
}

func TestParseModuleTaintLetters_SingleO(t *testing.T) {
	got := parseModuleTaintLetters("(O)")
	if !got['O'] {
		t.Error("expected O flag")
	}
	if got['E'] {
		t.Error("unexpected E flag")
	}
}

func TestParseModuleTaintLetters_BothOAndE(t *testing.T) {
	// When both O and E are present, E must be recognized
	got := parseModuleTaintLetters("(OE)")
	if !got['E'] {
		t.Error("expected E flag when both O and E present")
	}
	if !got['O'] {
		t.Error("expected O flag when both O and E present")
	}
}

func TestClassifyHostsEntryIP_Loopback(t *testing.T) {
	if got := classifyHostsEntryIP("127.0.0.1"); got != hostsClassSkip {
		t.Errorf("127.0.0.1: want skip, got %d", got)
	}
	if got := classifyHostsEntryIP("::1"); got != hostsClassSkip {
		t.Errorf("::1: want skip, got %d", got)
	}
}

func TestClassifyHostsEntryIP_NullRoute(t *testing.T) {
	if got := classifyHostsEntryIP("0.0.0.0"); got != hostsClassSkip {
		t.Errorf("0.0.0.0: want skip, got %d", got)
	}
}

func TestClassifyHostsEntryIP_Multicast(t *testing.T) {
	if got := classifyHostsEntryIP("ff02::1"); got != hostsClassSkip {
		t.Errorf("ff02::1: want skip, got %d", got)
	}
}

func TestClassifyHostsEntryIP_RFC1918(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.50", "fd12:3456::1"} {
		if got := classifyHostsEntryIP(ip); got != hostsClassLow {
			t.Errorf("%s: want LOW, got %d", ip, got)
		}
	}
}

func TestClassifyHostsEntryIP_PublicRouted(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.1"} {
		if got := classifyHostsEntryIP(ip); got != hostsClassMedium {
			t.Errorf("%s: want MEDIUM, got %d", ip, got)
		}
	}
}

func TestClassifyHostsEntryIP_Invalid(t *testing.T) {
	if got := classifyHostsEntryIP("not-an-ip"); got != hostsClassSkip {
		t.Errorf("invalid IP: want skip, got %d", got)
	}
}

func TestIsNonStandardModulePath_Standard(t *testing.T) {
	paths := []string{
		"/lib/modules/5.15.0-139-generic/kernel/drivers/net/dummy.ko",
		"/lib/modules/6.1.0/extra/dkms_module.ko",
		"",
	}
	for _, p := range paths {
		if isNonStandardModulePath(p) {
			t.Errorf("%q: want false (standard), got true", p)
		}
	}
}

func TestIsNonStandardModulePath_NonStandard(t *testing.T) {
	paths := []string{
		"/tmp/evil.ko",
		"/home/user/.local/bad.ko",
		"/root/rootkit.ko",
	}
	for _, p := range paths {
		if !isNonStandardModulePath(p) {
			t.Errorf("%q: want true (non-standard), got false", p)
		}
	}
}

func TestAnalyzeCmdline_Clean(t *testing.T) {
	params := []string{"BOOT_IMAGE=/vmlinuz-5.15.0", "root=/dev/sda1", "quiet", "splash"}
	findings := analyzeCmdline(params)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean cmdline, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzeCmdline_StandardInit(t *testing.T) {
	for _, p := range []string{
		"init=/sbin/init",
		"init=/lib/systemd/systemd",
		"init=/usr/lib/systemd/systemd",
	} {
		findings := analyzeCmdline([]string{p})
		if len(findings) != 0 {
			t.Errorf("%s: expected 0 findings, got %d", p, len(findings))
		}
	}
}

func TestAnalyzeCmdline_NonStandardInit(t *testing.T) {
	findings := analyzeCmdline([]string{"init=/tmp/evil"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].sev != output.HIGH {
		t.Errorf("expected HIGH, got %s", findings[0].sev)
	}
}

func TestAnalyzeCmdline_Rdinit(t *testing.T) {
	findings := analyzeCmdline([]string{"rdinit=/sbin/evil"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].sev != output.HIGH {
		t.Errorf("expected HIGH, got %s", findings[0].sev)
	}
}

func TestAnalyzeCmdline_RecoveryMode(t *testing.T) {
	for _, param := range []string{"rd.break", "single", "emergency", "rescue", "systemd.break"} {
		findings := analyzeCmdline([]string{param})
		if len(findings) != 1 {
			t.Errorf("%q: expected 1 finding, got %d", param, len(findings))
			continue
		}
		if findings[0].sev != output.MEDIUM {
			t.Errorf("%q: expected MEDIUM, got %s", param, findings[0].sev)
		}
	}
}

func TestAnalyzeCmdline_LSMDisabled(t *testing.T) {
	findings := analyzeCmdline([]string{"security=none"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].sev != output.HIGH {
		t.Errorf("expected HIGH, got %s", findings[0].sev)
	}
}

func TestAnalyzeCmdline_HardeningDisabled(t *testing.T) {
	for _, param := range []string{"nokaslr", "nosmap", "nosmep", "mitigations=off", "pti=off"} {
		findings := analyzeCmdline([]string{param})
		if len(findings) != 1 {
			t.Errorf("%q: expected 1 finding, got %d", param, len(findings))
			continue
		}
		if findings[0].sev != output.MEDIUM {
			t.Errorf("%q: expected MEDIUM, got %s", param, findings[0].sev)
		}
	}
}

func TestAnalyzeCmdline_StandardRdinit(t *testing.T) {
	for _, p := range []string{
		"rdinit=/sbin/init",
		"rdinit=/lib/systemd/systemd",
		"rdinit=/usr/lib/systemd/systemd",
	} {
		findings := analyzeCmdline([]string{p})
		if len(findings) != 0 {
			t.Errorf("%s: expected 0 findings for standard rdinit, got %d", p, len(findings))
		}
	}
}

func TestCollectDpkgInstalls_Basic(t *testing.T) {
	lines := []string{
		"2026-01-01 startup archives unpack",
		"2026-01-02 install curl:amd64 <none> 7.81.0",
		"2026-01-03 upgrade vim:amd64 2:8.1 2:8.2",
		"2026-01-04 install wget:amd64 <none> 1.21.2",
	}
	got := collectDpkgInstalls(lines, 30)
	if len(got) != 2 {
		t.Errorf("expected 2 install lines, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "wget") {
		t.Errorf("expected wget first (most recent), got %q", got[0])
	}
}

func TestCollectDpkgInstalls_Limit(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = fmt.Sprintf("2026-01-%02d install pkg%d:amd64 <none> 1.0", i+1, i)
	}
	got := collectDpkgInstalls(lines, 30)
	if len(got) != 30 {
		t.Errorf("expected 30, got %d", len(got))
	}
}

func TestCollectDpkgInstalls_Empty(t *testing.T) {
	got := collectDpkgInstalls([]string{"2026-01-01 startup"}, 30)
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
