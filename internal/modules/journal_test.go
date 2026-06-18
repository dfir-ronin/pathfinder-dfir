//go:build linux

package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pathfinder/internal/config"
)

func newRootTestContext(t *testing.T) *ModuleContext {
	t.Helper()
	cfg := &config.Config{ReportDir: t.TempDir(), IsRoot: true}
	ctx, err := NewModuleContext(cfg)
	if err != nil {
		t.Fatalf("NewModuleContext: %v", err)
	}
	return ctx
}

// TestJournalRaw_VolatileJournal covers Oracle Linux / RHEL where journald defaults to
// volatile storage at /run/log/journal and /var/log/journal does not exist.
func TestJournalRaw_VolatileJournal(t *testing.T) {
	tmpDir := t.TempDir()

	// Only the volatile path has files (simulates Oracle Linux)
	volatileDir := filepath.Join(tmpDir, "run", "abc123")
	if err := os.MkdirAll(volatileDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatileDir, "system.journal"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}

	orig := journalSourceDirs
	journalSourceDirs = []string{
		filepath.Join(tmpDir, "var"), // does not exist
		filepath.Join(tmpDir, "run"), // has files
	}
	defer func() { journalSourceDirs = orig }()

	ctx := newRootTestContext(t)
	journalRaw(ctx)

	copied := filepath.Join(ctx.Dirs.Journal, "raw", "abc123", "system.journal")
	if _, err := os.Stat(copied); err != nil {
		t.Errorf("volatile journal file not copied: %v", err)
	}
}

// TestJournalRaw_PersistentJournal covers Ubuntu / Debian where journald defaults to
// persistent storage at /var/log/journal.
func TestJournalRaw_PersistentJournal(t *testing.T) {
	tmpDir := t.TempDir()

	persistentDir := filepath.Join(tmpDir, "var", "abc123")
	if err := os.MkdirAll(persistentDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(persistentDir, "system.journal"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}

	orig := journalSourceDirs
	journalSourceDirs = []string{
		filepath.Join(tmpDir, "var"),         // has files
		filepath.Join(tmpDir, "nonexistent"), // does not exist
	}
	defer func() { journalSourceDirs = orig }()

	ctx := newRootTestContext(t)
	journalRaw(ctx)

	copied := filepath.Join(ctx.Dirs.Journal, "raw", "abc123", "system.journal")
	if _, err := os.Stat(copied); err != nil {
		t.Errorf("persistent journal file not copied: %v", err)
	}
}

func TestIsVacuumMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"Vacuuming done, freed 1.5G in 3 journal files.", true},
		{"VACUUMING DONE, freed 500M in 1 journal files.", true},
		{"Deleted archived journal /var/log/journal/abc/system@xyz.journal (2.0G).", true},
		{"Freed 100M of old journal files.", true},
		{"Started Journal Service.", false},
		{"Journal started.", false},
		{"", false},
		{"Runtime journal (/run/log/journal) is 8.0M, max 56.1M, 48.1M free.", false},
	}
	for _, tc := range cases {
		got := isVacuumMessage(tc.msg)
		if got != tc.want {
			t.Errorf("isVacuumMessage(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestIsBinaryMismatch(t *testing.T) {
	cases := []struct {
		comm string
		exe  string
		want bool
	}{
		// exact match, no mismatch
		{"sshd", "/usr/sbin/sshd", false},
		{"nginx", "/usr/sbin/nginx", false},
		// empty exe: kernel thread, skip
		{"kworker/0:1", "", false},
		// empty comm: skip
		{"", "/usr/bin/foo", false},
		// 15-char truncation: "systemd-network" (15 chars) is prefix of "systemd-networkd"
		{"systemd-network", "/usr/lib/systemd/systemd-networkd", false},
		// known interpreter: exact name
		{"bash", "/bin/bash", false},
		{"java", "/usr/lib/jvm/java-11-openjdk/bin/java", false},
		{"node", "/usr/bin/node", false},
		// known interpreter: versioned prefix
		{"python3.11", "/usr/bin/python3.11", false},
		{"perl5", "/usr/bin/perl5", false},
		// masquerade: should flag
		{"kworker/1:0", "/tmp/.evil", true},
		{"rcu_sched", "/dev/shm/.x1", true},
		{"systemd", "/var/tmp/backdoor", true},
	}
	for _, tc := range cases {
		got := isBinaryMismatch(tc.comm, tc.exe)
		if got != tc.want {
			t.Errorf("isBinaryMismatch(%q, %q) = %v, want %v", tc.comm, tc.exe, got, tc.want)
		}
	}
}

func TestExtractUnit(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"unit ssh.service entered failed state", "ssh.service"},
		{"unit nginx.service: start operation timed out", "nginx.service"},
		{"ssh service restarted", ""},
		{"some random message", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractUnit(tc.msg)
		if got != tc.want {
			t.Errorf("extractUnit(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestJournalTS(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{"1000000000", 1000},
		{"1716768000000000", 1716768000},
		{"abc", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := journalTS(tc.raw)
		if got != tc.want {
			t.Errorf("journalTS(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestFormatGapDuration(t *testing.T) {
	cases := []struct {
		secs int64
		want string
	}{
		{45 * 60, "45m"},
		{3600, "1h0m"},
		{3*3600 + 30*60, "3h30m"},
		{25 * 3600, "25h0m"},
	}
	for _, tc := range cases {
		got := formatGapDuration(tc.secs)
		if got != tc.want {
			t.Errorf("formatGapDuration(%d) = %q, want %q", tc.secs, got, tc.want)
		}
	}
}

func TestJournalAnalyzeContinuity(t *testing.T) {
	t.Run("start_without_reboot_fires", func(t *testing.T) {
		ctx := newRootTestContext(t)
		w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
		defer w.Close()

		entries := []journalEntry{
			{Message: "journal started", Timestamp: "1000000000"},
		}
		hits := journalAnalyzeContinuity(ctx, w, entries)
		if hits != 1 {
			t.Errorf("hits = %d, want 1 (no preceding reboot)", hits)
		}
	})

	t.Run("start_100s_after_reboot_no_fire", func(t *testing.T) {
		ctx := newRootTestContext(t)
		w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
		defer w.Close()

		// Reboot at 900s, journal start at 1000s (100s gap -- within 300s window).
		// Entries are in non-chronological buffer order to simulate the concat bug.
		entries := []journalEntry{
			{Message: "journal started", Timestamp: "1000000000"},
			{Message: "system is rebooting", Timestamp: "900000000"},
		}
		hits := journalAnalyzeContinuity(ctx, w, entries)
		if hits != 0 {
			t.Errorf("hits = %d, want 0 (reboot 100s before start is safe)", hits)
		}
	})
}

func TestJournalAnalyzeSSHBruteForce(t *testing.T) {
	var entries []journalEntry
	for i := 0; i < 10; i++ {
		entries = append(entries, journalEntry{Message: "Failed password for root from 1.2.3.4 port 22 ssh2"})
	}
	for i := 0; i < 10; i++ {
		entries = append(entries, journalEntry{Message: "Failed publickey for bob from 1.2.3.4 port 22 ssh2"})
	}
	for i := 0; i < 5; i++ {
		entries = append(entries, journalEntry{Message: "Invalid user admin from 1.2.3.4 port 22"})
	}

	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	hits := journalAnalyzeSSHBruteForce(ctx, w, entries)
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	_, m, _, _ := ctx.Registry.Counts()
	if m != 1 {
		t.Errorf("MEDIUM = %d, want 1 (25 combined auth failures should cross the 20 threshold)", m)
	}
}

func TestJournalAnalyzeCredentials_ShellSwap(t *testing.T) {
	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	entries := []journalEntry{
		// Original case: nologin to bash (must still fire)
		{Message: "changed user 'www-data' shell from /sbin/nologin to /bin/bash"},
		// Expanded: nologin to zsh (new)
		{Message: "changed user 'daemon' shell from /sbin/nologin to /usr/bin/zsh"},
		// Expanded: chsh with interactive shell (new)
		{SyslogID: "chsh", Message: "changed user 'bob' shell to /bin/sh"},
		// No-op: normal login line
		{Message: "pam_unix(login:session): session opened for user root"},
	}
	hits := journalAnalyzeCredentials(ctx, w, entries)
	if hits != 3 {
		t.Errorf("hits = %d, want 3", hits)
	}
}

func TestJournalAnalyzeTimeGaps(t *testing.T) {
	makeEntries := func(gapSecs int64) []journalEntry {
		base := int64(1_000_000_000)
		return []journalEntry{
			{Timestamp: fmt.Sprintf("%d", base)},
			{Timestamp: fmt.Sprintf("%d", base+gapSecs*1_000_000)},
		}
	}

	t.Run("three_hour_gap_no_fire", func(t *testing.T) {
		ctx := newRootTestContext(t)
		w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
		defer w.Close()
		hits := journalAnalyzeTimeGaps(ctx, w, makeEntries(3*3600))
		if hits != 0 {
			t.Errorf("hits = %d, want 0 (3h gap below new 4h MED threshold)", hits)
		}
	})

	t.Run("six_hour_gap_fires_med", func(t *testing.T) {
		ctx := newRootTestContext(t)
		w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
		defer w.Close()
		hits := journalAnalyzeTimeGaps(ctx, w, makeEntries(6*3600))
		if hits != 1 {
			t.Errorf("hits = %d, want 1 (6h gap between new 4h MED and 8h HIGH)", hits)
		}
	})

	t.Run("nine_hour_gap_fires_high", func(t *testing.T) {
		ctx := newRootTestContext(t)
		w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
		defer w.Close()
		hits := journalAnalyzeTimeGaps(ctx, w, makeEntries(9*3600))
		if hits != 1 {
			t.Errorf("hits = %d, want 1 (9h gap above new 8h HIGH threshold)", hits)
		}
	})
}

func TestJournalAnalyzeAccounts(t *testing.T) {
	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	entries := []journalEntry{
		{Message: "new user: name=attacker, UID=1001, GID=1001"},
		{Message: "delete user 'bob'"},
		{Message: "normal log message"},
	}
	hits := journalAnalyzeAccounts(ctx, w, entries)
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	h, m, _, _ := ctx.Registry.Counts()
	if h != 1 {
		t.Errorf("HIGH = %d, want 1", h)
	}
	if m != 1 {
		t.Errorf("MEDIUM = %d, want 1", m)
	}
}

func TestJournalAnalyzeGroupChanges(t *testing.T) {
	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	entries := []journalEntry{
		{Message: "user 'bob' added to group 'docker'"},
		{Message: "user 'alice' added to group 'users'"},
	}
	hits := journalAnalyzeGroupChanges(ctx, w, entries)
	if hits != 1 {
		t.Errorf("hits = %d, want 1 (only 'docker' is sensitive)", hits)
	}
	h, _, _, _ := ctx.Registry.Counts()
	if h != 1 {
		t.Errorf("HIGH = %d, want 1", h)
	}
}

func TestJournalAnalyzeVacuum(t *testing.T) {
	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	entries := []journalEntry{
		{Section: "journald_vacuum", Message: "Vacuuming done, freed 1.5G in 3 journal files."},
		{Section: "auth_ssh", Message: "sshd started"},
	}
	hits := journalAnalyzeVacuum(ctx, w, entries)
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	_, m, _, _ := ctx.Registry.Counts()
	if m != 1 {
		t.Errorf("MEDIUM = %d, want 1", m)
	}
}

func TestGroupNamesAfter(t *testing.T) {
	cases := []struct {
		msg  string
		want []string
	}{
		{"add 'user' to group 'sudo'", []string{"sudo"}},
		{"user added by root to group adm", []string{"adm"}},
		{"new user added to group admin", []string{"admin"}},
		{"to group docker by id=0", []string{"docker"}},
		{"add user to groups sudo,wheel", []string{"sudo", "wheel"}},
		{"no marker here", nil},
	}
	for _, c := range cases {
		got := groupNamesAfter(c.msg)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("groupNamesAfter(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestGroupMembership_NoSubstringFP(t *testing.T) {
	if sensitiveGroups["admin"] {
		t.Skip("admin unexpectedly sensitive; test assumption invalid")
	}
	for _, g := range groupNamesAfter("new user added to group admin") {
		if sensitiveGroups[g] {
			t.Errorf("admin membership should not be flagged via token %q", g)
		}
	}
	hit := false
	for _, g := range groupNamesAfter("user added by root to group adm") {
		if sensitiveGroups[g] {
			hit = true
		}
	}
	if !hit {
		t.Error("adm membership should be flagged")
	}
}

func TestGroupMembership_MultiGroup(t *testing.T) {
	// canonical usermod multi-group output: a sensitive group in 2nd position must be caught
	hit := false
	for _, g := range groupNamesAfter("add user to groups docker,wheel") {
		if sensitiveGroups[g] {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected a sensitive group in multi-group list")
	}
}

func TestJournalAnalyzeBinaryMismatch_Dedup(t *testing.T) {
	ctx := newRootTestContext(t)
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "test.txt", "LABEL", "src")
	defer w.Close()

	entries := []journalEntry{
		{Comm: "kworker/0:1", Exe: "/tmp/.evil"},
		{Comm: "kworker/0:1", Exe: "/tmp/.evil"},
		{Comm: "rcu_sched", Exe: "/dev/shm/.x1"},
	}
	hits := journalAnalyzeBinaryMismatch(ctx, w, entries)
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (kworker+evil once, rcu_sched+x1 once)", hits)
	}
	_, m, _, _ := ctx.Registry.Counts()
	if m != 2 {
		t.Errorf("MEDIUM = %d, want 2", m)
	}
}
