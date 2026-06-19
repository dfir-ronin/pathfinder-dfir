package modules

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
)

// RunJournal executes the -journal module (systemd journal collection and analysis)
func RunJournal(ctx *ModuleContext) {
	output.Chapter("[JOURNAL] Collecting systemd journal...")
	output.Info("Output → " + ctx.Dirs.Journal)

	journalRaw(ctx)
	analyzeJournal(ctx, journalFiltered(ctx))

	ctx.Log.Log("journal", "complete", "all sections done")
}

// maxJournalBytes caps the concatenated journalctl output buffer. Seven 30-day
// queries on a busy host can run to hundreds of MiB; this bounds the peak.
const maxJournalBytes = 128 << 20

const (
	journalGapHighSecs = 8 * 3600
	journalGapMedSecs  = 4 * 3600
)

// journalSourceDirs lists candidate directories for raw journal files.
// RHEL/Oracle Linux default to /run/log/journal (volatile); Debian/Ubuntu use /var/log/journal.
var journalSourceDirs = []string{"/var/log/journal", "/run/log/journal"}

func journalRaw(ctx *ModuleContext) {
	if !ctx.Cfg.IsRoot {
		output.Skip("journal collection requires root")
		return
	}

	output.Info("Copying journal raw files...")

	var count int
	if ctx.ZipWriter != nil {
		for _, src := range journalSourceDirs {
			count += copyJournalDirToZip(ctx, src)
		}
	} else {
		dst := filepath.Join(ctx.Dirs.Journal, "raw")
		if err := os.MkdirAll(dst, 0700); err != nil {
			output.Warn("journal/raw: cannot create output dir")
			return
		}
		for _, src := range journalSourceDirs {
			count += copyJournalDir(src, dst)
		}
	}

	if count == 0 {
		output.Note("No journal files found")
		return
	}
	output.Ok(fmt.Sprintf("Journal raw: %d files copied", count))
	ctx.Log.Log("journal", "journal_raw", fmt.Sprintf("%d files", count))
}

func copyJournalDir(src, dst string) int {
	count := 0
	filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			os.MkdirAll(target, 0700)
			return nil
		}
		if copyFileNoAtime(path, target) == nil {
			count++
		}
		return nil
	})
	return count
}

func copyJournalDirToZip(ctx *ModuleContext, src string) int {
	rawBase := filepath.Join(ctx.Dirs.Journal, "raw")
	count := 0
	filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		entryName := zipEntryName(ctx.Dirs.Base, filepath.Join(rawBase, rel))
		hdr := &zip.FileHeader{
			Name:   entryName,
			Method: zip.Deflate,
		}
		if fi, err := d.Info(); err == nil {
			hdr.Modified = fi.ModTime()
		}
		fw, err := ctx.ZipWriter.CreateHeader(hdr)
		if err != nil {
			return nil
		}
		f, err := osutil.OpenNoAtime(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		if _, err := io.Copy(fw, f); err == nil {
			count++
		}
		return nil
	})
	return count
}

func journalFiltered(ctx *ModuleContext) []byte {
	if !ctx.Cfg.IsRoot {
		output.Skip("journal filtered requires root")
		return nil
	}

	base := []string{"-o", "json", "--no-pager", "-S", "30 days ago"}
	mkargs := func(extra ...string) []string {
		args := make([]string, len(base), len(base)+len(extra))
		copy(args, base)
		return append(args, extra...)
	}

	type query struct {
		section string
		args    []string
	}
	queries := []query{
		{"auth_ssh", mkargs("SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=login")},
		{"sudo", mkargs("SYSLOG_IDENTIFIER=sudo")},
		{"cron", mkargs("SYSLOG_IDENTIFIER=cron", "SYSLOG_IDENTIFIER=CRON")},
		{"kernel_oom", mkargs("_TRANSPORT=kernel", "-p", "0..4")},
		{"high_priority", mkargs("-p", "0..3")},
		{"journald_vacuum", mkargs("SYSLOG_IDENTIFIER=systemd-journald")},
		{"account_mgmt", mkargs(
			"SYSLOG_IDENTIFIER=useradd",
			"SYSLOG_IDENTIFIER=userdel",
			"SYSLOG_IDENTIFIER=usermod",
			"SYSLOG_IDENTIFIER=groupadd",
			"SYSLOG_IDENTIFIER=passwd",
			"SYSLOG_IDENTIFIER=chsh",
		)},
	}

	var buf bytes.Buffer
	totalLines := 0
	capped := false
	for _, q := range queries {
		fmt.Fprintf(&buf, "{\"_pathfinder_section\":%q}\n", q.section)
		out, _ := execFallback(ctx, "journalctl", q.args...)
		if out != "" {
			remaining := maxJournalBytes - buf.Len()
			if remaining <= 0 {
				// Section marker already pushed the buffer to the ceiling; stop.
				capped = true
			} else {
				if len(out) > remaining {
					out = out[:remaining]
					capped = true
				}
				buf.WriteString(out)
				totalLines += strings.Count(out, "\n")
			}
		}
		if capped {
			break
		}
	}
	if capped {
		ctx.Log.Log("journal", "truncated", fmt.Sprintf("buffer capped at %d bytes", maxJournalBytes))
		output.Warn(fmt.Sprintf("journal output truncated at %d bytes", maxJournalBytes))
	}

	data := buf.Bytes()
	filteredPath := filepath.Join(ctx.Dirs.Journal, "journal_filtered.json")

	if ctx.ZipWriter != nil {
		entryName := zipEntryName(ctx.Dirs.Base, filteredPath)
		hdr := &zip.FileHeader{
			Name:     entryName,
			Method:   zip.Deflate,
			Modified: time.Now(),
		}
		if fw, err := ctx.ZipWriter.CreateHeader(hdr); err == nil {
			fw.Write(data)
		}
	} else {
		if err := os.WriteFile(filteredPath, data, 0600); err != nil {
			output.Warn("journal_filtered: cannot create output file")
		}
	}

	output.Ok(fmt.Sprintf("Journal filtered: ~%d events", totalLines))
	ctx.Log.Log("journal", "journal_filtered", fmt.Sprintf("~%d events", totalLines))
	return data
}

type journalEntry struct {
	Message   string `json:"MESSAGE"`
	Comm      string `json:"_COMM"`
	Exe       string `json:"_EXE"`
	SyslogID  string `json:"SYSLOG_IDENTIFIER"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
	UID       string `json:"_UID"`
	Section   string `json:"_pathfinder_section"` // pathfinder section marker
}

var sensitiveGroups = map[string]bool{
	"sudo": true, "wheel": true, "shadow": true,
	"disk": true, "docker": true, "lxd": true, "adm": true,
}

func analyzeJournal(ctx *ModuleContext, data []byte) {
	w := newSectionWriter(ctx, ctx.Dirs.Journal, "journal_analysis.txt",
		"Journal Analysis — Account Changes / Auth / USB / Log Gaps / Vacuum / Binary Mismatch",
		"journal/journal_filtered.json")
	defer w.Close()

	var entries []journalEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var e journalEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			entries = append(entries, e)
		}
	}

	if len(entries) == 0 {
		w.Write("No journal entries parsed (requires root).\n")
		output.Note("Journal analysis skipped — no entries")
		return
	}

	hits := 0
	hits += journalAnalyzeAccounts(ctx, w, entries)
	hits += journalAnalyzeGroupChanges(ctx, w, entries)
	hits += journalAnalyzeCredentials(ctx, w, entries)
	hits += journalAnalyzeSSHBruteForce(ctx, w, entries)
	hits += journalAnalyzePrivEsc(ctx, w, entries)
	hits += journalAnalyzeCrashLoops(ctx, w, entries)
	hits += journalAnalyzeTimeGaps(ctx, w, entries)
	hits += journalAnalyzeContinuity(ctx, w, entries)
	hits += journalAnalyzeUSB(ctx, w, entries)
	hits += journalAnalyzeVacuum(ctx, w, entries)
	hits += journalAnalyzeBinaryMismatch(ctx, w, entries)

	if hits == 0 {
		output.Ok("Journal analysis: no suspicious events")
	} else {
		output.Warn(fmt.Sprintf("Journal analysis: %d suspicious event(s)", hits))
	}
	ctx.Log.Log("journal", "journal_analysis", fmt.Sprintf("%d hits", hits))
}

func journalAnalyzeAccounts(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Account Creation & Deletion")
	hits := 0
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "new user:") || strings.Contains(msg, "new account added") {
			w.Write("[ACCOUNT-CREATE] %s\n", e.Message)
			ctx.Registry.Add(output.MEDIUM, "journal", "Account creation event",
				fmt.Sprintf("Account creation event: %s", truncate(e.Message, 120)))
			hits++
		}
		if strings.Contains(msg, "delete user") || strings.Contains(msg, "user deleted") ||
			strings.Contains(msg, "userdel") {
			w.Write("[ACCOUNT-DELETE] %s\n", e.Message)
			ctx.Registry.Add(output.HIGH, "journal", "Account deletion event",
				fmt.Sprintf("Account deletion event: %s", truncate(e.Message, 120)))
			hits++
		}
	}
	return hits
}

func journalAnalyzeGroupChanges(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Sensitive Group Membership Changes")
	hits := 0
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		if !strings.Contains(msg, "to group") {
			continue
		}
		flagged := ""
		for _, g := range groupNamesAfter(msg) {
			if sensitiveGroups[g] {
				flagged = g
				break
			}
		}
		if flagged != "" {
			w.Write("[GROUP-CHANGE] %s\n", e.Message)
			ctx.Registry.Add(output.HIGH, "journal", "Sensitive group membership change",
				fmt.Sprintf("User added to sensitive group '%s': %s", flagged, truncate(e.Message, 120)))
			hits++
		}
	}
	return hits
}

// groupNamesAfter returns the candidate group tokens that follow the last word-boundary
// "group"/"groups" marker in a lowercased message. The first whitespace-delimited field
// after the marker is treated as the (possibly comma-separated) group list, e.g.
// "added to groups sudo,wheel" -> ["sudo","wheel"]. Returns nil if no marker is found.
func groupNamesAfter(msg string) []string {
	const marker = "group"
	i := -1
	for j := len(msg) - len(marker); j >= 0; j-- {
		if msg[j:j+len(marker)] == marker && (j == 0 || !isASCIILetter(msg[j-1])) {
			i = j
			break
		}
	}
	if i < 0 {
		return nil
	}
	rest := msg[i+len(marker):]
	rest = strings.TrimPrefix(rest, "s") // tolerate the plural "groups"
	rest = strings.TrimSpace(rest)
	if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
		rest = rest[:sp] // the group list is the first whitespace-delimited field
	}
	return strings.FieldsFunc(rest, func(r rune) bool {
		return r == ',' || r == '\'' || r == '"' || r == '`' ||
			r == '(' || r == ')' || r == '.' || r == ':' || r == ';'
	})
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func journalAnalyzeCredentials(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Password & Shell Tampering")
	hits := 0
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		isPwdChange := e.Comm == "passwd" ||
			strings.Contains(msg, "password changed for") ||
			strings.Contains(msg, "changed password expiry")
		isShellSwap := isShellSwapMsg(e.SyslogID, e.Message)
		if isPwdChange || isShellSwap {
			label := "PASSWORD-CHANGE"
			if isShellSwap {
				label = "SHELL-SWAP"
			}
			w.Write("[%s] %s\n", label, e.Message)
			ctx.Registry.Add(output.HIGH, "journal", "Credential/shell tampering",
				fmt.Sprintf("Credential/shell tampering detected (%s): %s", label, truncate(e.Message, 120)))
			hits++
		}
	}
	return hits
}

func journalAnalyzeSSHBruteForce(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("SSH Brute-Force Detection")
	sshFails := 0
	for _, e := range entries {
		if strings.Contains(e.Message, "Failed password") ||
			strings.Contains(e.Message, "Failed publickey") ||
			strings.Contains(e.Message, "Invalid user") {
			sshFails++
		}
	}
	w.Write("Failed SSH auth attempts: %d\n", sshFails)
	hits := 0
	if sshFails > sshBruteForceHighThreshold {
		ctx.Registry.Add(output.HIGH, "journal", "SSH brute-force attack",
			fmt.Sprintf("%d SSH failed auth events -- brute-force attack likely", sshFails))
		hits++
	} else if sshFails > sshBruteForceMediumThreshold {
		ctx.Registry.Add(output.MEDIUM, "journal", "SSH brute-force attack",
			fmt.Sprintf("%d SSH failed auth events -- elevated failure rate", sshFails))
		hits++
	}
	return hits
}

func journalAnalyzePrivEsc(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Privilege Escalation Events")
	hits := 0
	for _, e := range entries {
		isSudo := e.SyslogID == "sudo" || strings.Contains(e.Message, "pkexec")
		if !isSudo {
			continue
		}
		uid, _ := strconv.Atoi(e.UID)
		if uid != 0 {
			w.Write("[PRIV-ESC] UID=%s %s\n", e.UID, e.Message)
			ctx.Registry.Add(output.MEDIUM, "journal", "Privilege escalation event",
				fmt.Sprintf("Privilege escalation by UID %s: %s", e.UID, truncate(e.Message, 120)))
			hits++
		}
	}
	return hits
}

func journalAnalyzeCrashLoops(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Rapid Service Crash Detection")
	unitCrashes := make(map[string][]int64)
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		if !strings.Contains(msg, "failed") && !strings.Contains(msg, "killed") &&
			!strings.Contains(msg, "segfault") {
			continue
		}
		ts := journalTS(e.Timestamp)
		if ts == 0 {
			continue
		}
		unit := extractUnit(e.Message)
		if unit == "" {
			continue
		}
		unitCrashes[unit] = append(unitCrashes[unit], ts)
	}
	hits := 0
	for unit, times := range unitCrashes {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		for i := 0; i+2 < len(times); i++ {
			window := times[i+2] - times[i]
			if window <= 60 {
				w.Write("[CRASH-LOOP] unit=%s — 3 failures in %ds\n", unit, window)
				ctx.Registry.Add(output.MEDIUM, "journal", "Service crash loop",
					fmt.Sprintf("Service crash loop: %s — 3+ failures in %ds (possible exploit attempt)", unit, window))
				hits++
				break
			}
		}
	}
	return hits
}

func journalAnalyzeTimeGaps(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Log Time Gap Analysis")
	var timestamps []int64
	for _, e := range entries {
		if ts := journalTS(e.Timestamp); ts > 0 {
			timestamps = append(timestamps, ts)
		}
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
	hits := 0
	for i := 1; i < len(timestamps); i++ {
		gap := timestamps[i] - timestamps[i-1]
		if gap > journalGapHighSecs {
			w.Write("[GAP-HIGH] %s -- %s gap -- possible manual log deletion\n",
				time.Unix(timestamps[i-1], 0).UTC().Format(time.RFC3339), formatGapDuration(gap))
			ctx.Registry.Add(output.LOW, "journal", "Journal log gap",
				fmt.Sprintf("Journal gap of %s at %s -- possible log deletion",
					formatGapDuration(gap), time.Unix(timestamps[i-1], 0).UTC().Format(time.RFC3339)))
			hits++
		} else if gap > journalGapMedSecs {
			w.Write("[GAP-MED]  %s -- %s gap\n",
				time.Unix(timestamps[i-1], 0).UTC().Format(time.RFC3339), formatGapDuration(gap))
			ctx.Registry.Add(output.LOW, "journal", "Journal log gap",
				fmt.Sprintf("Journal gap of %s at %s", formatGapDuration(gap),
					time.Unix(timestamps[i-1], 0).UTC().Format(time.RFC3339)))
			hits++
		}
	}
	return hits
}

func journalAnalyzeContinuity(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Journal Continuity Check")

	var rebootTimes, startTimes []int64
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		ts := journalTS(e.Timestamp)
		if ts == 0 {
			continue
		}
		if strings.Contains(msg, "system is rebooting") || strings.Contains(msg, "shutting down") {
			rebootTimes = append(rebootTimes, ts)
		}
		if strings.Contains(msg, "journal started") || strings.Contains(msg, "systemd-journald started") {
			startTimes = append(startTimes, ts)
		}
	}

	sort.Slice(rebootTimes, func(i, j int) bool { return rebootTimes[i] < rebootTimes[j] })

	hits := 0
	for _, start := range startTimes {
		// Find index of first reboot strictly after start.
		// idx-1 is therefore the last reboot at or before start.
		idx := sort.Search(len(rebootTimes), func(i int) bool { return rebootTimes[i] > start })
		hasPrecedingReboot := idx > 0 && (start-rebootTimes[idx-1]) <= 300
		if !hasPrecedingReboot {
			w.Write("[JOURNAL-RESTART] Journal started at %s without preceding reboot\n",
				time.Unix(start, 0).UTC().Format(time.RFC3339))
			ctx.Registry.Add(output.LOW, "journal", "Journal restarted without reboot",
				fmt.Sprintf("Journal restarted at %s without preceding reboot -- possible log tampering",
					time.Unix(start, 0).UTC().Format(time.RFC3339)))
			hits++
		}
	}
	return hits
}

func journalAnalyzeUSB(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("USB / External Storage Events")
	usbCount := 0
	for _, e := range entries {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "usb-storage") || strings.Contains(msg, " uas ") ||
			strings.Contains(msg, "usb mass storage") || strings.Contains(msg, "new usb device") {
			w.Write("[USB] %s\n", e.Message)
			usbCount++
		}
	}
	if usbCount > 0 {
		ctx.Registry.Add(output.LOW, "journal", "USB/mass storage insertion",
			fmt.Sprintf("%d USB/mass storage insertion event(s) detected", usbCount))
		return 1
	}
	w.Write("No USB mass storage events found.\n")
	return 0
}

func journalAnalyzeVacuum(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Journal Vacuum Events")
	vacuumCount := 0
	for _, e := range entries {
		if e.Section != "journald_vacuum" {
			continue
		}
		if isVacuumMessage(e.Message) {
			w.Write("[VACUUM] %s\n", e.Message)
			vacuumCount++
		}
	}
	if vacuumCount > 0 {
		ctx.Registry.Add(output.MEDIUM, "journal", "Journal vacuum event",
			fmt.Sprintf("%d journal vacuum/deletion event(s) detected — possible log purging", vacuumCount))
		return 1
	}
	w.Write("No vacuum events detected.\n")
	return 0
}

func journalAnalyzeBinaryMismatch(ctx *ModuleContext, w *output.Writer, entries []journalEntry) int {
	w.WriteSectionHeader("Binary Mismatch Detection")
	seen := make(map[string]bool)
	mismatchCount := 0
	for _, e := range entries {
		if !isBinaryMismatch(e.Comm, e.Exe) {
			continue
		}
		key := e.Comm + "|" + e.Exe
		if seen[key] {
			continue
		}
		seen[key] = true
		w.Write("[BINARY-MISMATCH] comm=%s exe=%s\n", e.Comm, e.Exe)
		ctx.Registry.Add(output.MEDIUM, "journal", "Process binary mismatch",
			fmt.Sprintf("Process name mismatch: _COMM=%s does not match executable %s", e.Comm, e.Exe))
		mismatchCount++
	}
	if mismatchCount == 0 {
		w.Write("No binary mismatch events detected.\n")
	}
	return mismatchCount
}

func journalTS(raw string) int64 {
	us, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return us / 1_000_000 // microseconds → seconds
}

func extractUnit(msg string) string {
	lower := strings.ToLower(msg)
	idx := strings.Index(lower, "unit ")
	if idx < 0 {
		return ""
	}
	rest := msg[idx+5:]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	// Journal messages render the unit as "unit nginx.service:": strip any
	// trailing punctuation so the same unit is not split by a stray colon.
	unit := strings.TrimRight(fields[0], ":,;")
	if strings.Contains(unit, ".") {
		return unit
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func formatGapDuration(seconds int64) string {
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func isVacuumMessage(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "vacuuming done") ||
		strings.Contains(lower, "deleted archived journal") ||
		(strings.Contains(lower, "freed") && strings.Contains(lower, "journal files"))
}

var knownInterpreterPrefixes = []string{"python", "perl", "ruby"}

var knownInterpreters = map[string]bool{
	"node": true, "nodejs": true,
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"java": true, "php": true,
}

var interactiveShells = []string{
	"/bin/bash", "/usr/bin/bash",
	"/bin/sh", "/usr/bin/sh",
	"/usr/bin/zsh", "/bin/zsh",
	"/usr/bin/fish",
}

func isShellSwapMsg(syslogID, msg string) bool {
	lower := strings.ToLower(msg)
	if syslogID == "chsh" {
		if strings.Contains(lower, "nologin") || strings.Contains(lower, "false") {
			return false
		}
		for _, sh := range interactiveShells {
			if strings.Contains(lower, sh) {
				return true
			}
		}
		return false
	}
	if !strings.Contains(lower, "/sbin/nologin") {
		return false
	}
	for _, sh := range interactiveShells {
		if strings.Contains(lower, sh) {
			return true
		}
	}
	return false
}

func isBinaryMismatch(comm, exe string) bool {
	if exe == "" || comm == "" {
		return false
	}
	base := filepath.Base(exe)
	if base == comm {
		return false
	}
	if len(comm) == 15 && strings.HasPrefix(base, comm) {
		return false
	}
	if knownInterpreters[comm] {
		return false
	}
	for _, prefix := range knownInterpreterPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return false
		}
	}
	return true
}
