//go:build linux

package modules

import (
	"testing"

	"github.com/pathfinder/internal/output"
)

func TestGtfobinsSUIDAbused_Contains(t *testing.T) {
	abused := []string{"bash", "python3", "find", "vim", "curl", "nc", "systemctl"}
	for _, name := range abused {
		if !gtfobinsSUIDAbused[name] {
			t.Errorf("%q: want in gtfobinsSUIDAbused", name)
		}
	}
}

func TestExpectedSUIDBinaries_Contains(t *testing.T) {
	expected := []string{"passwd", "sudo", "su", "ping", "mount", "fusermount"}
	for _, name := range expected {
		if !expectedSUIDBinaries[name] {
			t.Errorf("%q: want in expectedSUIDBinaries", name)
		}
	}
}

func TestGtfobinsSUIDAbused_DoesNotContainExpected(t *testing.T) {
	for name := range expectedSUIDBinaries {
		if gtfobinsSUIDAbused[name] {
			t.Errorf("%q: must not appear in both gtfobinsSUIDAbused and expectedSUIDBinaries", name)
		}
	}
}

func TestExtractNOPASSWDPaths_MultipleRules(t *testing.T) {
	content := "admin ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/dpkg\nuser ALL=(ALL) NOPASSWD: /bin/ls\n"
	paths := extractNOPASSWDPaths(content)
	if len(paths) != 3 {
		t.Fatalf("got %d paths: %v", len(paths), paths)
	}
}

func TestExtractNOPASSWDPaths_NoNOPASSWD(t *testing.T) {
	content := "user ALL=(ALL) ALL\n"
	paths := extractNOPASSWDPaths(content)
	if len(paths) != 0 {
		t.Errorf("want empty, got %v", paths)
	}
}

func TestExtractNOPASSWDPaths_RelativePathSkipped(t *testing.T) {
	content := "user ALL=(ALL) NOPASSWD: apt-get\n"
	paths := extractNOPASSWDPaths(content)
	if len(paths) != 0 {
		t.Errorf("relative path must be skipped, got %v", paths)
	}
}

func TestExtractNOPASSWDPaths_CommentedLineSkipped(t *testing.T) {
	content := "# user ALL=(ALL) NOPASSWD: /usr/bin/apt-get\n"
	paths := extractNOPASSWDPaths(content)
	if len(paths) != 0 {
		t.Errorf("commented NOPASSWD line must be skipped, got %v", paths)
	}
}

func TestExtractNOPASSWDPaths_MixedCommentAndActive(t *testing.T) {
	content := "# admin ALL=(ALL) NOPASSWD: /usr/bin/vim\nuser ALL=(ALL) NOPASSWD: /usr/bin/ls\n"
	paths := extractNOPASSWDPaths(content)
	if len(paths) != 1 || paths[0] != "/usr/bin/ls" {
		t.Errorf("only active lines must be parsed, got %v", paths)
	}
}

func TestParseGetcapLine_ValidLine(t *testing.T) {
	path, caps, ok := parseGetcapLine("/usr/bin/ping cap_net_raw=ep")
	if !ok || path != "/usr/bin/ping" || len(caps) != 1 || caps[0] != "cap_net_raw" {
		t.Errorf("got path=%q caps=%v ok=%v", path, caps, ok)
	}
}

func TestParseGetcapLine_MultipleCaps(t *testing.T) {
	path, caps, ok := parseGetcapLine("/usr/bin/foo cap_setuid=ep cap_setgid=ep")
	if !ok || path != "/usr/bin/foo" || len(caps) != 2 {
		t.Errorf("got path=%q caps=%v ok=%v", path, caps, ok)
	}
	if caps[0] != "cap_setuid" || caps[1] != "cap_setgid" {
		t.Errorf("cap names: got %v", caps)
	}
}

func TestParseGetcapLine_TooFewFields(t *testing.T) {
	_, _, ok := parseGetcapLine("/usr/bin/ping")
	if ok {
		t.Error("single-field line must return ok=false")
	}
}

func TestParseGetcapLine_PlusDelimitedFormat(t *testing.T) {
	path, caps, ok := parseGetcapLine("/usr/bin/ping cap_net_raw+ep")
	if !ok || path != "/usr/bin/ping" || len(caps) != 1 || caps[0] != "cap_net_raw" {
		t.Errorf("plus-delimited cap: got path=%q caps=%v ok=%v", path, caps, ok)
	}
}

func TestParseGetcapLine_MixedDelimiters(t *testing.T) {
	path, caps, ok := parseGetcapLine("/usr/bin/foo cap_setuid=ep cap_net_raw+ep")
	if !ok || path != "/usr/bin/foo" || len(caps) != 2 {
		t.Errorf("mixed delimiters: got path=%q caps=%v ok=%v", path, caps, ok)
	}
	if caps[0] != "cap_setuid" || caps[1] != "cap_net_raw" {
		t.Errorf("cap names wrong: got %v", caps)
	}
}

func TestParseGetcapLine_Empty(t *testing.T) {
	_, _, ok := parseGetcapLine("")
	if ok {
		t.Error("empty line must return ok=false")
	}
}

func TestDangerousCapabilities_Contains(t *testing.T) {
	high := []string{"cap_setuid", "cap_setgid", "cap_sys_ptrace", "cap_sys_admin"}
	for _, c := range high {
		if sev, ok := dangerousFileCaps[c]; !ok || sev != output.HIGH {
			t.Errorf("%q: want HIGH in dangerousFileCaps", c)
		}
	}
	med := []string{"cap_dac_override", "cap_net_raw"}
	for _, c := range med {
		if sev, ok := dangerousFileCaps[c]; !ok || sev != output.MEDIUM {
			t.Errorf("%q: want MEDIUM in dangerousFileCaps", c)
		}
	}
}

func TestIsAuthFailureLine_DbusNotMatched(t *testing.T) {
	line := `May 17 03:32:18 ubuntu dbus-daemon[768]: [system] Failed to activate service 'org.bluez': timed out`
	if isAuthFailureLine(line) {
		t.Error("dbus 'Failed to activate service' must not match auth failure")
	}
}

func TestIsAuthFailureLine_SSHFailedPassword(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2`
	if !isAuthFailureLine(line) {
		t.Error("SSH 'Failed password' must match auth failure")
	}
}

func TestIsAuthFailureLine_SSHFailedPublickey(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: Failed publickey for root from 192.168.1.1 port 22 ssh2`
	if !isAuthFailureLine(line) {
		t.Error("SSH 'Failed publickey' must match auth failure")
	}
}

func TestIsAuthFailureLine_InvalidUser(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: Invalid user admin from 192.168.1.1 port 22`
	if !isAuthFailureLine(line) {
		t.Error("SSH 'Invalid user' must match auth failure")
	}
}

func TestIsAuthFailureLine_InvalidAloneNotMatched(t *testing.T) {
	line := `May 18 04:00:00 ubuntu kernel: Invalid argument`
	if isAuthFailureLine(line) {
		t.Error("bare 'Invalid' without 'user' must not match auth failure")
	}
}

func TestIsAuthFailureLine_AuthenticationFailure(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: pam_unix(sshd:auth): authentication failure; uid=0`
	if !isAuthFailureLine(line) {
		t.Error("'authentication failure' must match auth failure")
	}
}

func TestIsAuthFailureLine_TooManyAttempts(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: Disconnecting authenticating user root 192.168.1.1 port 22: Too many authentication failures [preauth]`
	if !isAuthFailureLine(line) {
		t.Error("'Too many authentication failures' must match auth failure")
	}
}

func TestIsAuthFailureLine_MaxAttemptsExceeded(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: error: maximum authentication attempts exceeded for root from 192.168.1.1 port 22 ssh2 [preauth]`
	if !isAuthFailureLine(line) {
		t.Error("'maximum authentication attempts exceeded' must match auth failure")
	}
}

func TestIsAuthFailureLine_ClosedByInvalidUser(t *testing.T) {
	line := `May 18 04:00:00 ubuntu sshd[1234]: Connection closed by invalid user admin 192.168.1.1 port 22 [preauth]`
	if !isAuthFailureLine(line) {
		t.Error("'Connection closed by invalid user' must match auth failure")
	}
}

func TestCapAllowlist_NoCrossCapability(t *testing.T) {
	if capAllowlist["/usr/bin/newuidmap"]["cap_setgid"] {
		t.Error("newuidmap must not allow cap_setgid — it only performs UID mapping")
	}
	if capAllowlist["/usr/bin/newgidmap"]["cap_setuid"] {
		t.Error("newgidmap must not allow cap_setuid — it only performs GID mapping")
	}
	if !capAllowlist["/usr/bin/newuidmap"]["cap_setuid"] {
		t.Error("newuidmap must allow cap_setuid")
	}
	if !capAllowlist["/usr/bin/newgidmap"]["cap_setgid"] {
		t.Error("newgidmap must allow cap_setgid")
	}
}

func TestSSHBruteForceThresholds(t *testing.T) {
	if sshBruteForceHighThreshold != 100 {
		t.Errorf("sshBruteForceHighThreshold = %d, want 100", sshBruteForceHighThreshold)
	}
	if sshBruteForceMediumThreshold != 20 {
		t.Errorf("sshBruteForceMediumThreshold = %d, want 20", sshBruteForceMediumThreshold)
	}
}

func TestPamLineSuspicious(t *testing.T) {
	cases := []struct {
		line    string
		wantHit string
		wantOK  bool
	}{
		{"auth required pam_exec.so /usr/local/bin/x", "pam_exec", true},
		{"session optional pam_exec.so seteuid /tmp/run", "pam_exec", true},
		{"auth required pam_unix.so", "", false},
		{"session optional pam_tmpdir.so", "", false}, // FP: was matched by "/tmp"
		{"auth required pam_unix.so dir=/tmp/sess", "/tmp", true},
		{"auth required pam_unix.so file=/dev/shm/s", "/dev/shm", true},
	}
	for _, c := range cases {
		hit, ok := pamLineSuspicious(c.line)
		if ok != c.wantOK || (ok && hit != c.wantHit) {
			t.Errorf("pamLineSuspicious(%q) = (%q,%v), want (%q,%v)", c.line, hit, ok, c.wantHit, c.wantOK)
		}
	}
}
