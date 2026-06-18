//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

func TestFormatAge_Hours(t *testing.T) {
	d := 4*time.Hour + 32*time.Minute
	got := formatAge(d)
	if got != "4h32m" {
		t.Errorf("got %q, want 4h32m", got)
	}
}

func TestFormatAge_MinutesOnly(t *testing.T) {
	d := 45 * time.Minute
	got := formatAge(d)
	if got != "45m" {
		t.Errorf("got %q, want 45m", got)
	}
}

func TestIsSuspiciousSystemUserShell_Nologin_Clean(t *testing.T) {
	e := procfs.PasswdEntry{Username: "news", UID: 9, Shell: "/usr/sbin/nologin"}
	if isSuspiciousSystemUserShell(e) {
		t.Error("want false for /usr/sbin/nologin")
	}
}

func TestIsSuspiciousSystemUserShell_BinFalse_Clean(t *testing.T) {
	e := procfs.PasswdEntry{Username: "daemon", UID: 1, Shell: "/bin/false"}
	if isSuspiciousSystemUserShell(e) {
		t.Error("want false for /bin/false")
	}
}

func TestIsSuspiciousSystemUserShell_BashShell_Flagged(t *testing.T) {
	e := procfs.PasswdEntry{Username: "news", UID: 9, Shell: "/bin/bash"}
	if !isSuspiciousSystemUserShell(e) {
		t.Error("want true for system user with /bin/bash")
	}
}

func TestIsSuspiciousSystemUserShell_RootExcluded(t *testing.T) {
	e := procfs.PasswdEntry{Username: "root", UID: 0, Shell: "/bin/bash"}
	if isSuspiciousSystemUserShell(e) {
		t.Error("want false for root (UID 0)")
	}
}

func TestIsSuspiciousSystemUserShell_NologinWithSpace_Flagged(t *testing.T) {
	e := procfs.PasswdEntry{Username: "news", UID: 9, Shell: "/usr/sbin/nologin "}
	if !isSuspiciousSystemUserShell(e) {
		t.Error("want true for nologin with trailing space")
	}
}

func TestIsSuspiciousSystemUserShell_AllowlistedSync_Clean(t *testing.T) {
	e := procfs.PasswdEntry{Username: "sync", UID: 4, Shell: "/bin/sync"}
	if isSuspiciousSystemUserShell(e) {
		t.Error("want false for allowlisted sync user")
	}
}

func TestClassifyShellsEntry_TrailingSpace_Malformed(t *testing.T) {
	sev, label, flagged := classifyShellsEntry("/usr/sbin/nologin ")
	if !flagged {
		t.Fatal("want flagged=true for trailing space")
	}
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if label != "Malformed /etc/shells entry" {
		t.Errorf("label: got %q", label)
	}
}

func TestClassifyShellsEntry_StagingPath_High(t *testing.T) {
	sev, label, flagged := classifyShellsEntry("/tmp/fake_nologin")
	if !flagged {
		t.Fatal("want flagged=true for staging path")
	}
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if label != "Staging-path shell in /etc/shells" {
		t.Errorf("label: got %q", label)
	}
}

func TestClassifyShellsEntry_MissingFile_Medium(t *testing.T) {
	sev, label, flagged := classifyShellsEntry("/usr/bin/shell_that_does_not_exist_pathfinder")
	if !flagged {
		t.Fatal("want flagged=true for missing file")
	}
	if sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", sev)
	}
	if label != "Non-existent shell in /etc/shells" {
		t.Errorf("label: got %q", label)
	}
}

func TestClassifyShellsEntry_ValidBash_Clean(t *testing.T) {
	_, _, flagged := classifyShellsEntry("/bin/bash")
	if flagged {
		t.Error("want flagged=false for /bin/bash (which exists)")
	}
}

func TestClassifyShellsEntry_Comment_Clean(t *testing.T) {
	_, _, flagged := classifyShellsEntry("# /bin/bash")
	if flagged {
		t.Error("want flagged=false for comment line")
	}
}

func TestClassifyShellsEntry_InaccessibleDir_Medium(t *testing.T) {
	dir, err := os.MkdirTemp("", "pathfinder-shells-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	shellPath := filepath.Join(dir, "fake_shell")
	if err := os.WriteFile(shellPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)

	sev, label, flagged := classifyShellsEntry(shellPath)
	if !flagged {
		t.Error("want flagged=true for inaccessible path")
	}
	if sev != output.MEDIUM {
		t.Errorf("want MEDIUM, got %s", sev)
	}
	if label != "Non-existent shell in /etc/shells" {
		t.Errorf("unexpected label: %q", label)
	}
}

func TestCountBtmpFailures_FiltersNonUserProcess(t *testing.T) {
	records := []procfs.UtmpRecord{
		{Type: 7, User: "attacker"},
		{Type: 2, User: ""},
		{Type: 8, User: ""},
		{Type: 7, User: "attacker2"},
	}
	if got := countBtmpFailures(records); got != 2 {
		t.Errorf("want 2, got %d", got)
	}
}

func TestCountBtmpFailures_AllNonUserProcess(t *testing.T) {
	records := []procfs.UtmpRecord{
		{Type: 2},
		{Type: 5},
	}
	if got := countBtmpFailures(records); got != 0 {
		t.Errorf("want 0, got %d", got)
	}
}

func TestCountBtmpFailures_Empty(t *testing.T) {
	if got := countBtmpFailures(nil); got != 0 {
		t.Errorf("want 0, got %d", got)
	}
}

func TestDiffContainsAdditions_ContentWithPlusSpace_NoFalsePositive(t *testing.T) {
	diff := " root:x:0:0:root,+admin:/root:/bin/bash\n"
	if diffContainsAdditions(diff) {
		t.Error("context line with '+ ' inside content must not count as an addition")
	}
}

func TestDiffContainsAdditions_RealAddition(t *testing.T) {
	diff := "--- /etc/passwd-\n+++ /etc/passwd\n+newuser:x:1001:1001::/home/newuser:/bin/bash\n"
	if !diffContainsAdditions(diff) {
		t.Error("want true for a real added line")
	}
}

func TestDiffContainsRemovals_HeaderNotCounted(t *testing.T) {
	diff := "--- /etc/passwd-\n+++ /etc/passwd\n context line\n"
	if diffContainsRemovals(diff) {
		t.Error("--- header line must not count as a removal")
	}
}

func TestDiffContainsRemovals_RealRemoval(t *testing.T) {
	diff := "--- /etc/passwd-\n+++ /etc/passwd\n-olduser:x:1002:1002::/home/olduser:/bin/bash\n"
	if !diffContainsRemovals(diff) {
		t.Error("want true for a real removed line")
	}
}
