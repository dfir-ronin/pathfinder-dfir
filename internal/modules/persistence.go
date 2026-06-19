package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

const persistenceRecentHours = 72.0

// persistenceDotfiles is the canonical set of shell startup/logout files
// checked for malicious commands across all persistence sections.
var persistenceDotfiles = []string{
	".bashrc", ".bash_profile", ".profile",
	".zshrc", ".zprofile", ".bash_logout",
}

// desktopEntry holds fields extracted from a .desktop file relevant to
// autostart security analysis.
type desktopEntry struct {
	Exec      string
	Hidden    bool
	NoDisplay bool
	Type      string
}

// parseDesktopFile extracts Exec, Type, Hidden, and NoDisplay from a .desktop
// file. Only the [Desktop Entry] section is parsed; all others are ignored.
func parseDesktopFile(data []byte) desktopEntry {
	var e desktopEntry
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if osutil.IsCommentOrBlank(line) {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == "[Desktop Entry]"
			continue
		}
		if !inSection {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Exec":
			e.Exec = strings.TrimSpace(val)
		case "Type":
			e.Type = strings.TrimSpace(val)
		case "Hidden":
			e.Hidden = strings.EqualFold(strings.TrimSpace(val), "true")
		case "NoDisplay":
			e.NoDisplay = strings.EqualFold(strings.TrimSpace(val), "true")
		}
	}
	return e
}

// shellInlinePrefixes are patterns that indicate an inline payload in Exec=.
var shellInlinePrefixes = []string{
	"bash -c", "/bin/bash -c", "/usr/bin/bash -c",
	"sh -c", "/bin/sh -c", "/usr/bin/sh -c",
	"python -c", "python3 -c", "/usr/bin/python -c", "/usr/bin/python3 -c",
	"perl -e", "/usr/bin/perl -e",
	"ruby -e", "/usr/bin/ruby -e",
	"node -e", "/usr/bin/node -e", "nodejs -e",
	"php -r", "/usr/bin/php -r",
}

// knownXDGDirs are hidden-prefixed directory names that are standard XDG paths
// and must not be treated as suspicious hidden components.
var knownXDGDirs = map[string]bool{
	".config": true, ".local": true, ".kde": true, ".kde4": true,
	".gnome": true, ".cache": true, ".dbus": true, ".pki": true,
}

// execBinary extracts the first non-env-variable token from an Exec= value.
// Handles "env VAR=val /bin/app ..." by skipping env and its KEY=VALUE pairs.
func execBinary(exec string) string {
	fields := strings.Fields(exec)
	if len(fields) == 0 {
		return ""
	}
	if fields[0] == "env" || fields[0] == "/usr/bin/env" {
		for _, f := range fields[1:] {
			if !strings.Contains(f, "=") {
				return f
			}
		}
		return ""
	}
	return fields[0]
}

// hasHiddenComponent reports whether path contains any component starting with
// "." that is not in knownXDGDirs.
func hasHiddenComponent(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if strings.HasPrefix(part, ".") && !knownXDGDirs[part] {
			return true
		}
	}
	return false
}

// classifyExec analyses an Exec= value and returns (severity, reason).
// Returns ("", "") for system-dir entries with no anomaly.
// Returns (output.INFO, "") for user-dir entries with a clean Exec=.
func classifyExec(exec string, fromUserDir bool) (output.Severity, string) {
	if exec == "" {
		return "", ""
	}
	binary := execBinary(exec)

	// 1. Malware staging path
	if binary != "" && ioc.IsInMalwareDir(binary) {
		return output.HIGH, "Exec= references malware staging path"
	}

	// 2. Shell interpreter with inline payload
	for _, pat := range shellInlinePrefixes {
		if strings.Contains(exec, pat+" ") || strings.HasSuffix(exec, pat) {
			return output.HIGH, "Exec= uses shell interpreter with inline payload"
		}
	}

	// 3. Hidden directory component (absolute paths only)
	if binary != "" && filepath.IsAbs(binary) && hasHiddenComponent(binary) {
		return output.HIGH, "Exec= references hidden directory path"
	}

	// 4. Non-existent binary (absolute paths, user dirs only)
	// Skip for known XDG data dirs (.config, .local); apps legitimately install there.
	if fromUserDir && binary != "" && filepath.IsAbs(binary) &&
		!strings.Contains(binary, "/.config/") && !strings.Contains(binary, "/.local/") {
		if _, err := os.Stat(binary); os.IsNotExist(err) {
			return output.MEDIUM, "Exec= references non-existent binary"
		}
	}

	if fromUserDir {
		return output.INFO, ""
	}
	return "", ""
}

// classifyShellCommand analyses a shell command string and returns (severity, reason)
// for known reverse-shell and payload-execution patterns.
// Returns ("", "") for benign commands.
func classifyShellCommand(cmd string) (output.Severity, string) {
	if cmd == "" {
		return "", ""
	}
	low := strings.ToLower(cmd)

	if strings.Contains(low, "/dev/tcp/") || strings.Contains(low, "/dev/udp/") {
		return output.HIGH, "bash TCP/UDP socket redirection"
	}
	if strings.Contains(low, "mkfifo") {
		return output.HIGH, "named pipe reverse shell"
	}
	if strings.Contains(low, "tcpsocket.new") || strings.Contains(low, "tcpsocket.open") {
		return output.HIGH, "Ruby TCP socket reverse shell"
	}
	if strings.Contains(low, "fsockopen") {
		return output.HIGH, "PHP socket reverse shell"
	}
	if strings.Contains(low, "require") && strings.Contains(low, "socket") && strings.Contains(low, "connect") {
		return output.HIGH, "Lua socket reverse shell"
	}
	if strings.Contains(low, "nc -e") || strings.Contains(low, "ncat -e") || strings.Contains(low, "netcat -e") {
		return output.HIGH, "netcat exec reverse shell"
	}
	if strings.Contains(low, "socat") && (strings.Contains(low, "exec:") || strings.Contains(low, "tcp-connect:")) {
		return output.HIGH, "socat reverse shell"
	}
	if (strings.Contains(low, "bash -i") || strings.Contains(low, "sh -i")) &&
		(strings.Contains(low, ">&") || strings.Contains(low, "0>&1")) {
		return output.HIGH, "interactive reverse shell"
	}
	if (strings.Contains(low, "wget") || strings.Contains(low, "curl")) &&
		strings.Contains(low, "http") && strings.Contains(low, "|") {
		return output.HIGH, "download-and-execute payload"
	}
	if strings.Contains(low, "base64") &&
		(strings.Contains(low, "| bash") || strings.Contains(low, "| sh") ||
			strings.Contains(low, "|bash") || strings.Contains(low, "|sh")) {
		return output.HIGH, "base64-encoded payload execution"
	}
	if strings.Contains(low, "import pty") && strings.Contains(low, "spawn") {
		return output.HIGH, "Python pty reverse shell"
	}
	if strings.Contains(low, "import socket") && strings.Contains(low, "connect") {
		return output.HIGH, "Python socket reverse shell"
	}
	if strings.Contains(low, "use socket") && strings.Contains(low, "connect") {
		return output.HIGH, "Perl socket reverse shell"
	}
	if strings.Contains(low, "/inet/tcp/") {
		return output.HIGH, "awk TCP reverse shell"
	}
	if strings.Contains(low, "openssl") && strings.Contains(low, "s_client") && strings.Contains(low, "-connect") {
		return output.HIGH, "OpenSSL reverse shell"
	}
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.Contains(low, prefix) {
			if stagingPathExecuted(low, prefix) {
				return output.HIGH, "command references staging/volatile path"
			}
			return output.LOW, "staging/volatile path referenced (no execution verb)"
		}
	}
	if strings.Contains(low, "posix::setuid") &&
		(strings.Contains(low, "exec") || strings.Contains(low, "spawn") ||
			strings.Contains(low, "/bin/sh") || strings.Contains(low, "/bin/bash")) {
		return output.HIGH, "Perl capability-abuse setuid escalation"
	}
	if strings.Contains(low, "posix.setuid(0)") {
		return output.HIGH, "Python capability-abuse setuid escalation"
	}
	if strings.Contains(low, "os.setuid(0)") {
		return output.HIGH, "Go/Ruby setuid(0) escalation"
	}
	if strings.Contains(low, "cap_setuid") {
		return output.MEDIUM, "capability string embedded in script"
	}
	if reOctalSUID.MatchString(low) {
		return output.HIGH, "chmod setting SUID/SGID bit (octal notation)"
	}
	if strings.Contains(low, "| sh") || strings.Contains(low, "| bash") ||
		strings.HasSuffix(strings.TrimSpace(low), "|sh") || strings.HasSuffix(strings.TrimSpace(low), "|bash") {
		return output.MEDIUM, "pipe-to-shell execution"
	}
	return "", ""
}

var udevRunRe = regexp.MustCompile(`RUN[+]?="([^"]+)"`)

var udevImportRe = regexp.MustCompile(`IMPORT\{program\}="([^"]+)"`)

// udevImportProgram extracts the program path from a udev IMPORT{program}="..."
// directive. Returns ok=false when the line carries no such directive.
func udevImportProgram(line string) (string, bool) {
	if m := udevImportRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

var soFileRegexp = regexp.MustCompile(`\.so(\.\d+)*$`)

var reOctalSUID = regexp.MustCompile(`(?i)chmod\s+[2-7][0-7]{3}\b`)

// stagingExecVerbs are interpreters, shells, and download/transfer tools whose presence near
// a staging path indicates execution or drop rather than benign data reference.
var stagingExecVerbs = map[string]bool{
	"curl": true, "wget": true, "chmod": true, "bash": true, "sh": true,
	"dash": true, "zsh": true, "ksh": true, "python": true, "python2": true,
	"python3": true, "perl": true, "ruby": true, "php": true, "nc": true,
	"ncat": true, "netcat": true, "scp": true, "exec": true, "source": true, "eval": true,
}

// stagingPathExecuted reports whether the staging path in low (lowercased command) is being
// executed: either a token starting with prefix sits in command position, or an exec/transfer
// verb token appears anywhere in the command.
func stagingPathExecuted(low, prefix string) bool {
	fields := strings.Fields(low)
	for i, raw := range fields {
		tok := strings.Trim(raw, "\"'`();|&<>$")
		// command substitution executes its contents: $(...) or `...`
		cmdSub := strings.Contains(raw, "$(") || strings.Contains(raw, "`")
		if strings.HasPrefix(tok, prefix) && (isCommandPosition(fields, i) || cmdSub) {
			return true
		}
		base := tok
		if j := strings.LastIndex(base, "/"); j >= 0 {
			base = base[j+1:]
		}
		if stagingExecVerbs[base] {
			return true
		}
	}
	return false
}

// isCommandPosition reports whether fields[i] is in command position: first token, or the
// token immediately after a shell separator.
func isCommandPosition(fields []string, i int) bool {
	if i == 0 {
		return true
	}
	switch strings.Trim(fields[i-1], "\"'`") {
	case "|", "||", "&&", ";", "&", ".":
		return true
	}
	return false
}

var knownSystemdGenerators = map[string]bool{
	"snapd-generator":           true,
	"netplan":                   true,
	"openvpn-generator":         true,
	"friendly-recovery":         true,
	"makecon":                   true,
	"lvm2-activation-generator": true,
	"zfs-mount-generator":       true,
	"dracut-emergency-shell":    true,
	"fstab-decode":              true,
}

func isKnownSystemdGenerator(name string) bool {
	return strings.HasPrefix(name, "systemd-") || knownSystemdGenerators[name]
}

func extractCronCommand(line string, hasUser bool) string {
	trimmed := strings.TrimSpace(line)
	if osutil.IsCommentOrBlank(trimmed) {
		return ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 2 {
			return ""
		}
		if hasUser && len(fields) >= 3 {
			return strings.Join(fields[2:], " ")
		}
		return strings.Join(fields[1:], " ")
	}
	minFields := 5
	if hasUser {
		minFields = 6
	}
	if len(fields) <= minFields {
		return ""
	}
	return strings.Join(fields[minFields:], " ")
}

// systemXDGDirs are package-managed autostart directories.
// Entries here are only flagged when Exec= analysis finds a HIGH/MEDIUM anomaly.
var systemXDGDirs = []string{
	"/etc/xdg/autostart",
	"/usr/share/autostart",
}

// userXDGSubdirs are per-user autostart subdirectories relative to HomeDir.
var userXDGSubdirs = []string{
	".config/autostart",
	".local/share/autostart",
	".kde/Autostart",
	".kde4/Autostart",
	".config/autostart-scripts",
}

// scanDirForSharedObjects returns paths to .so files found directly under dir
// and one level of subdirectories (depth-1). Hidden subdirectories are included
// because concealment in a dot-prefixed subdir is a common evasion pattern.
func scanDirForSharedObjects(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var found []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			subs, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, sub := range subs {
				if sub.IsDir() {
					continue
				}
				if soFileRegexp.MatchString(sub.Name()) {
					found = append(found, filepath.Join(p, sub.Name()))
				}
			}
			continue
		}
		if soFileRegexp.MatchString(e.Name()) {
			found = append(found, p)
		}
	}
	return found
}

// RunPersistence executes the daemon (persistence) sections
func RunPersistence(ctx *ModuleContext) {
	output.Chapter("[PERSISTENCE] Sweeping for persistence mechanisms and scheduled tasks...")
	output.Info("Output → " + ctx.Dirs.Persistence)
	persistenceCronJobs(ctx)
	persistenceAtQueue(ctx)
	persistenceSystemd(ctx)
	persistenceLegacyInit(ctx)
	persistenceUdevRules(ctx)
	persistenceXDGAutostart(ctx)
	persistenceInsmodBootPersistence(ctx)
	persistenceSuspiciousSystemdExecStart(ctx)
	persistenceMotdPersistence(ctx)
	persistenceShellProfileAnalysis(ctx)
	persistencePackageManagerHooks(ctx)
	persistenceGitHooks(ctx)
	persistenceStagingSharedObjects(ctx)
	persistenceLDPreload(ctx)
	persistenceKernelModuleAnalysis(ctx)
	persistenceWebShells(ctx)
	persistencePAM(ctx)
	persistenceExternalNetworkIndicators(ctx)
	persistenceSSHAuthorizedKeys(ctx)
	persistenceSudoers(ctx)

	ctx.Log.Log("persistence", "complete", "all sections done")
}

type cronScriptHit struct {
	path  string
	sev   output.Severity
	label string
	msg   string
}

// scanCronScriptDir reads all non-directory entries from dir, classifies their
// content with classifyFileLines, and also flags recently added files.
func scanCronScriptDir(ctx *ModuleContext, dir string) []cronScriptHit {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var hits []cronScriptHit
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		data, err := readEvidenceFile(ctx, p)
		if err != nil {
			continue
		}
		if bestSev, bestReason, bestLine := classifyFileLines(string(data), nil); bestSev != "" {
			hits = append(hits, cronScriptHit{
				path:  p,
				sev:   bestSev,
				label: "Malicious cron script",
				msg:   fmt.Sprintf("%s in %s: %.120s", bestReason, p, bestLine),
			})
		} else if recentlyModified(p, persistenceRecentHours) {
			hits = append(hits, cronScriptHit{
				path:  p,
				sev:   output.MEDIUM,
				label: "Recently added cron script",
				msg:   fmt.Sprintf("Cron script added within 72h: %s", p),
			})
		}
	}
	return hits
}

// extractAnacronCommand parses one line from /etc/anacrontab and returns the
// command portion. anacrontab format: period delay job-identifier command [args...]
func extractAnacronCommand(line string) string {
	trimmed := strings.TrimSpace(line)
	if osutil.IsCommentOrBlank(trimmed) {
		return ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) <= 3 {
		return ""
	}
	return strings.Join(fields[3:], " ")
}

func persistenceCronJobs(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "01_cron_jobs.txt",
		"Scheduled Cron Tasks", "/etc/crontab, /etc/cron.d/, /var/spool/cron/")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	cronFiles := []string{"/etc/crontab"}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			cronFiles = append(cronFiles, filepath.Join("/etc/cron.d", e.Name()))
		}
	}

	for _, f := range cronFiles {
		if data, err := readEvidenceFile(ctx, f); err == nil {
			w.WriteSectionHeader(f)
			w.WriteString(string(data))
			for _, line := range strings.Split(string(data), "\n") {
				cmd := extractCronCommand(line, true)
				if cmd == "" {
					continue
				}
				if sev, reason := classifyShellCommand(cmd); sev != "" {
					ctx.Registry.Add(sev, "persistence", "Malicious cron job",
						fmt.Sprintf("Malicious command in %s: %s — %.120s", f, reason, strings.TrimSpace(line)))
				}
			}
		}
	}

	w.WriteSectionHeader("Per-user crontabs (/var/spool/cron/)")
	for _, spoolDir := range []string{"/var/spool/cron", "/var/spool/cron/crontabs"} {
		if entries, err := os.ReadDir(spoolDir); err == nil {
			for _, e := range entries {
				p := filepath.Join(spoolDir, e.Name())
				if data, err := readEvidenceFile(ctx, p); err == nil {
					w.Write("─── %s ───\n%s\n", e.Name(), string(data))
					ctx.Registry.Add(output.MEDIUM, "persistence", "User crontab found",
						fmt.Sprintf("User crontab found: %s", e.Name()))
					for _, line := range strings.Split(string(data), "\n") {
						cmd := extractCronCommand(line, false)
						if cmd == "" {
							continue
						}
						if sev, reason := classifyShellCommand(cmd); sev != "" {
							ctx.Registry.Add(sev, "persistence", "Malicious cron job",
								fmt.Sprintf("Malicious command in %s/%s: %s — %.120s",
									spoolDir, e.Name(), reason, strings.TrimSpace(line)))
						}
					}
				}
			}
		}
	}

	// Cron script directories (not crontab-format -- executed directly by cron/anacron)
	for _, cronDir := range []string{
		"/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly",
	} {
		for _, h := range scanCronScriptDir(ctx, cronDir) {
			w.WriteSectionHeader(h.path)
			w.Write("  [%s] %s\n", h.sev, h.msg)
			ctx.Registry.Add(h.sev, "persistence", h.label, h.msg)
		}
	}

	// anacrontab
	if data, err := readEvidenceFile(ctx, "/etc/anacrontab"); err == nil {
		w.WriteSectionHeader("/etc/anacrontab")
		w.WriteString(string(data))
		for _, line := range strings.Split(string(data), "\n") {
			cmd := extractAnacronCommand(line)
			if cmd == "" {
				continue
			}
			if sev, reason := classifyShellCommand(cmd); sev != "" {
				ctx.Registry.Add(sev, "persistence", "Malicious anacron job",
					fmt.Sprintf("Malicious command in /etc/anacrontab: %s — %.120s",
						reason, strings.TrimSpace(line)))
			}
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Suspicious cron jobs: %d hit(s)", delta))
	} else {
		output.Ok("Cron jobs collected")
	}
}

func persistenceAtQueue(ctx *ModuleContext) {
	persistenceAtQueueDirs(ctx, []string{"/var/spool/at", "/var/spool/cron/atjobs"})
}

func persistenceAtQueueDirs(ctx *ModuleContext, atDirs []string) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "02_at_queue.txt",
		"at/batch Job Queue", "/var/spool/at/")
	defer w.Close()

	total := 0
	for _, d := range atDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(d, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			w.Write("─── %s ───\n%s\n\n", p, string(data))
			total++
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if osutil.IsCommentOrBlank(trimmed) {
					continue
				}
				if sev, reason := classifyShellCommand(trimmed); sev != "" {
					ctx.Registry.Add(sev, "persistence", "Malicious at/batch job",
						fmt.Sprintf("at job %s contains [%s]: %.120s", p, reason, trimmed))
				}
			}
		}
	}

	if total == 0 {
		w.Write("No at jobs found.\n")
	} else {
		ctx.Registry.Add(output.MEDIUM, "persistence", "at/batch job queued",
			fmt.Sprintf("%d at/batch job(s) queued — see 02_at_queue.txt", total))
	}
	if total > 0 {
		output.Warn(fmt.Sprintf("Suspicious at/batch jobs: %d hit(s)", total))
	} else {
		output.Ok("at queue entries: 0")
	}
}

func persistenceSystemd(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "03_systemd_services.txt",
		"Systemd Services, Timers, Path Units & Generators",
		"/etc/systemd/system/, /lib/systemd/system/, generators/, user units")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	systemdDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
		"/run/systemd/system",
		"/usr/local/lib/systemd/system",
	}

	// Deduplicate realpath: on modern Fedora/RHEL /lib is a symlink to /usr/lib,
	// so /lib/systemd/system and /usr/lib/systemd/system are the same directory.
	seenDir := make(map[string]bool)
	for _, d := range systemdDirs {
		real, err := filepath.EvalSymlinks(d)
		if err != nil {
			real = d
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(d)
		for _, e := range entries {
			w.Write("  %s\n", e.Name())
		}
		// Only flag units in /etc/systemd/system (admin-added). Units shipped by
		// packages land in /lib or /usr/lib and are expected to be "non-standard".
		if d != "/etc/systemd/system" || seenDir[real] {
			continue
		}
		seenDir[real] = true
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".service") &&
				!strings.HasPrefix(e.Name(), "systemd-") {
				ctx.Registry.Add(output.LOW, "persistence", "Non-standard systemd unit",
					fmt.Sprintf("Non-standard systemd unit: %s in %s", e.Name(), d))
			}
		}
	}

	w.WriteSectionHeader("Systemd .timer units")
	for _, d := range systemdDirs {
		walkFiles(ctx, d, func(path string, info os.FileInfo) {
			if strings.HasSuffix(path, ".timer") {
				if data, err := readEvidenceFile(ctx, path); err == nil {
					w.Write("─── %s ───\n%s\n", path, string(data))
				}
			}
		})
	}

	w.WriteSectionHeader("Systemd .path units (triggered on filesystem events)")
	for _, d := range systemdDirs {
		walkFiles(ctx, d, func(path string, info os.FileInfo) {
			if strings.HasSuffix(path, ".path") {
				if data, err := readEvidenceFile(ctx, path); err == nil {
					w.Write("─── %s ───\n%s\n", path, string(data))
					// Only flag .path units in /etc/systemd/system (admin-added).
					// Package-shipped .path units (/lib, /usr/lib) are expected.
					if strings.HasPrefix(path, "/etc/systemd/system") {
						ctx.Registry.Add(output.MEDIUM, "persistence", "Systemd .path unit found",
							fmt.Sprintf("Systemd .path unit found: %s — filesystem-triggered persistence", path))
					}
				}
			}
		})
	}

	generatorDirs := []string{
		"/etc/systemd/system-generators",
		"/usr/lib/systemd/system-generators",
		"/run/systemd/system-generators",
	}
	w.WriteSectionHeader("Systemd Generator Directories (run before mounts)")
	for _, d := range generatorDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		w.Write("  [%s]\n", d)
		for _, e := range entries {
			w.Write("    %s\n", e.Name())
			if !isKnownSystemdGenerator(e.Name()) {
				ctx.Registry.Add(output.HIGH, "persistence", "Non-standard systemd generator",
					fmt.Sprintf("Non-standard systemd generator in %s: %s", d, e.Name()))
			}
		}
	}

	w.WriteSectionHeader("User Systemd Units (~/.config/systemd/user/)")
	passwdEntries, _ := procfs.ReadPasswd()
	for _, pe := range passwdEntries {
		if pe.HomeDir == "" || pe.HomeDir == "/" {
			continue
		}
		userUnitDir := filepath.Join(pe.HomeDir, ".config", "systemd", "user")
		unitEntries, err := os.ReadDir(userUnitDir)
		if err != nil {
			continue
		}
		for _, ue := range unitEntries {
			p := filepath.Join(userUnitDir, ue.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			w.Write("  ─── %s ───\n%s\n", p, string(data))
			if strings.HasSuffix(ue.Name(), ".timer") || strings.HasSuffix(ue.Name(), ".path") ||
				strings.HasSuffix(ue.Name(), ".service") {
				ctx.Registry.Add(output.MEDIUM, "persistence", "User-level systemd persistence unit",
					fmt.Sprintf("User-level systemd persistence unit: %s", p))
			}
			// Analyse ExecStart= in service files for malicious commands.
			if strings.HasSuffix(ue.Name(), ".service") {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "ExecStart=") {
						continue
					}
					execVal := strings.TrimPrefix(line, "ExecStart=")
					execVal = strings.TrimLeft(execVal, "-+!@:")
					sev, reason := classifyShellCommand(execVal)
					if sev == "" {
						sev, reason = classifyExec(execVal, true)
					}
					if sev == output.HIGH {
						ctx.Registry.Add(output.HIGH, "persistence", "Malicious systemd ExecStart",
							fmt.Sprintf("User unit %s: ExecStart= contains %s", p, reason))
						break
					}
				}
			}
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Suspicious systemd units: %d hit(s)", delta))
	} else {
		output.Ok("Systemd services, timers, path units and generators collected")
	}
}

func persistenceLegacyInit(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "04_legacy_init.txt",
		"Legacy Init Persistence", "/etc/rc.local, /etc/inittab, /etc/init.d/, /etc/rc.common")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	rcFiles := []string{
		"/etc/rc.local", "/etc/rc.d/rc.local", "/etc/rc.common", "/etc/inittab",
	}
	for _, f := range rcFiles {
		data, err := readEvidenceFile(ctx, f)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(f)
		w.WriteString(string(data))

		bestSev, bestReason, bestLine := classifyFileLines(string(data), nil)
		if bestSev != "" {
			ctx.Registry.Add(bestSev, "persistence", "Malicious legacy init script",
				fmt.Sprintf("%s in %s: %.120s", bestReason, f, bestLine))
		}
		if recentlyModified(f, persistenceRecentHours) {
			sev := output.MEDIUM
			if bestSev == output.HIGH {
				sev = output.HIGH
			}
			ctx.Registry.Add(sev, "persistence", "Recently modified legacy init file",
				fmt.Sprintf("Legacy init file modified within 72h: %s", f))
		}
	}

	entries, err := os.ReadDir("/etc/init.d")
	if err != nil {
		h1, m1, l1, _ := ctx.Registry.Counts()
		delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
		if delta > 0 {
			output.Warn(fmt.Sprintf("Suspicious legacy init scripts: %d hit(s)", delta))
		} else {
			output.Ok("Legacy init files collected")
		}
		return
	}
	w.WriteSectionHeader("/etc/init.d/")
	for _, e := range entries {
		p := filepath.Join("/etc/init.d", e.Name())
		info, _ := e.Info()
		if info != nil {
			w.Write("  %s  %s\n", info.Mode().String(), e.Name())
		}
		data, err := readEvidenceFile(ctx, p)
		if err != nil {
			continue
		}
		bestSev, bestReason, bestLine := classifyFileLines(string(data), nil)
		if bestSev != "" {
			ctx.Registry.Add(bestSev, "persistence", "Malicious init.d script",
				fmt.Sprintf("%s in %s: %.120s", bestReason, p, bestLine))
		}
		if recentlyModified(p, persistenceRecentHours) && bestSev == "" {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added init.d script",
				fmt.Sprintf("init.d script added within 72h: %s", p))
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Suspicious legacy init scripts: %d hit(s)", delta))
	} else {
		output.Ok("Legacy init files collected")
	}
}

func persistenceUdevRules(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "05_udev_rules.txt",
		"Udev Persistence Rules",
		"/etc/udev/rules.d/, /lib/udev/rules.d/, /run/udev/rules.d/")
	defer w.Close()

	// Only scan admin-controlled dirs. /lib/udev/rules.d contains package-shipped
	// rules that legitimately use RUN+= and IMPORT{program}: flagging them is
	// the primary source of udev false-positives.
	scanDirs := []string{
		"/etc/udev/rules.d",
		"/run/udev/rules.d",
	}

	hits := 0
	for _, d := range scanDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(d)
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			sc.Buffer(make([]byte, 0, 64*1024), 8<<20) // 8 MiB: long udev rule lines must not silently truncate
			lineNum := 0
			for sc.Scan() {
				lineNum++
				line := sc.Text()
				trimmed := strings.TrimSpace(line)
				if osutil.IsCommentOrBlank(trimmed) {
					continue
				}
				suspicious := strings.Contains(trimmed, "RUN+=") ||
					strings.Contains(trimmed, "RUN=") ||
					strings.Contains(trimmed, "IMPORT{program}")
				if !suspicious {
					continue
				}
				w.Write("  %s:%d  %s\n", e.Name(), lineNum, trimmed)
				hits++
				if m := udevRunRe.FindStringSubmatch(trimmed); m != nil {
					cmd := m[1]
					if sev, reason := classifyShellCommand(cmd); sev != "" {
						ctx.Registry.Add(sev, "persistence", "Malicious udev RUN command",
							fmt.Sprintf("udev rule %s (line %d) executes malicious command [%s]: %s",
								p, lineNum, reason, cmd))
					} else if ioc.IsInMalwareDir(cmd) {
						ctx.Registry.Add(output.HIGH, "persistence", "Malicious udev RUN command",
							fmt.Sprintf("udev rule %s (line %d) references staging path: %s", p, lineNum, cmd))
					} else {
						ctx.Registry.Add(output.MEDIUM, "persistence", "Suspicious udev rule",
							fmt.Sprintf("Suspicious udev directive in %s (line %d): %s", p, lineNum, trimmed))
					}
				} else if cmd, ok := udevImportProgram(trimmed); ok {
					if sev, reason := classifyShellCommand(cmd); sev != "" {
						ctx.Registry.Add(sev, "persistence", "Malicious udev RUN command",
							fmt.Sprintf("udev rule %s (line %d) IMPORT{program} runs malicious command [%s]: %s",
								p, lineNum, reason, cmd))
					} else if ioc.IsInMalwareDir(cmd) {
						ctx.Registry.Add(output.HIGH, "persistence", "Malicious udev RUN command",
							fmt.Sprintf("udev rule %s (line %d) IMPORT{program} references staging path: %s", p, lineNum, cmd))
					} else {
						ctx.Registry.Add(output.MEDIUM, "persistence", "Suspicious udev rule",
							fmt.Sprintf("Suspicious udev IMPORT{program} in %s (line %d): %s", p, lineNum, trimmed))
					}
				} else {
					ctx.Registry.Add(output.MEDIUM, "persistence", "Suspicious udev rule",
						fmt.Sprintf("Suspicious udev directive in %s (line %d): %s", p, lineNum, trimmed))
				}
			}
			if recentlyModified(p, persistenceRecentHours) {
				ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added udev rule",
					fmt.Sprintf("udev rule file added within 72h: %s", p))
			}
		}
	}

	if hits == 0 {
		w.Write("No suspicious udev RUN+= or IMPORT{program} directives found.\n")
		output.Ok("Udev rules: no suspicious directives")
	} else {
		output.Warn(fmt.Sprintf("Suspicious udev directives: %d hit(s)", hits))
	}
}

func persistenceXDGAutostart(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "06_xdg_autostart.txt",
		"XDG Autostart Entries",
		"/etc/xdg/autostart/, /usr/share/autostart/, ~/.config/autostart/, ~/.local/share/autostart/, KDE")
	defer w.Close()

	type scanDir struct {
		path     string
		fromUser bool
	}
	var dirs []scanDir
	for _, d := range systemXDGDirs {
		dirs = append(dirs, scanDir{d, false})
	}
	if pwEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range pwEntries {
			if pe.HomeDir == "" {
				continue
			}
			for _, sub := range userXDGSubdirs {
				dirs = append(dirs, scanDir{filepath.Join(pe.HomeDir, sub), true})
			}
		}
	}

	highCount := 0
	for _, sd := range dirs {
		entries, err := os.ReadDir(sd.path)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(sd.path)

		cleanCount := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			p := filepath.Join(sd.path, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			w.Write("  [%s]\n%s\n", e.Name(), string(data))

			parsed := parseDesktopFile(data)
			if parsed.Type != "" && parsed.Type != "Application" {
				continue
			}
			sev, reason := classifyExec(parsed.Exec, sd.fromUser)

			if sd.fromUser && (parsed.Hidden || parsed.NoDisplay) && sev == output.MEDIUM {
				sev = output.HIGH
				reason += " (Hidden=true or NoDisplay=true)"
			}

			switch sev {
			case output.HIGH:
				highCount++
				ctx.Registry.Add(output.HIGH, "persistence", "Malicious XDG autostart entry",
					fmt.Sprintf("%s: %s", e.Name(), reason))
			case output.MEDIUM:
				ctx.Registry.Add(output.MEDIUM, "persistence", "Suspicious XDG autostart entry",
					fmt.Sprintf("%s: %s", e.Name(), reason))
			case output.INFO:
				cleanCount++
			}
		}
		if sd.fromUser && cleanCount > 0 {
			ctx.Registry.Add(output.INFO, "persistence", "XDG autostart entries",
				fmt.Sprintf("XDG autostart entries in %s (%d clean file(s))", sd.path, cleanCount))
		}
	}

	if highCount > 0 {
		output.Warn(fmt.Sprintf("XDG autostart: %d suspicious entry(ies)", highCount))
	} else {
		output.Ok("XDG autostart checked")
	}
}

func persistenceInsmodBootPersistence(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "07_insmod_boot_persistence.txt",
		"insmod / modprobe in Boot & Persistence Scripts",
		"/etc/rc.local, init.d, cron, profile.d, user homes, staging dirs, /usr/local/bin|sbin")
	defer w.Close()

	scanPaths := []string{"/etc/rc.local", "/etc/inittab"}
	addGlob(&scanPaths, "/etc/init.d")
	for _, f := range []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"} {
		scanPaths = append(scanPaths, f)
	}
	addGlob(&scanPaths, "/etc/profile.d")
	scanPaths = append(scanPaths, "/etc/crontab")
	addGlob(&scanPaths, "/etc/cron.d")
	addGlob(&scanPaths, "/var/spool/cron/crontabs")
	addGlob(&scanPaths, "/var/spool/cron")
	addGlob(&scanPaths, "/usr/local/bin")
	addGlob(&scanPaths, "/usr/local/sbin")

	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if entries, err := os.ReadDir(d); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				info, _ := e.Info()
				if info == nil {
					continue
				}
				if (info.Mode()&0111) != 0 || isScriptExtension(e.Name()) {
					scanPaths = append(scanPaths, filepath.Join(d, e.Name()))
				}
			}
		}
	}

	if passwdEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range passwdEntries {
			if pe.HomeDir == "" || pe.HomeDir == "/" {
				continue
			}
			for _, f := range persistenceDotfiles {
				scanPaths = append(scanPaths, filepath.Join(pe.HomeDir, f))
			}
		}
	}

	hits := 0
	seen := make(map[string]bool)
	for _, path := range scanPaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if ctx.SelfPath != "" && path == ctx.SelfPath {
			continue
		}

		data, err := readEvidenceFile(ctx, path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		fileHits := 0
		for i, line := range lines {
			if !ioc.InsmodLoose.MatchString(line) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if fileHits == 0 {
				w.WriteSectionHeader(path)
			}
			w.Write("  Line %-5d → %s\n", i+1, trimmed)
			fileHits++
			hits++

			sev := output.HIGH
			isHighPath := strings.HasPrefix(path, "/tmp") ||
				strings.HasPrefix(path, "/var/tmp") ||
				strings.HasPrefix(path, "/dev/shm") ||
				strings.HasPrefix(path, "/etc/cron") ||
				strings.HasPrefix(path, "/var/spool/cron")
			if !isHighPath {
				sev = output.MEDIUM
			}
			ctx.Registry.Add(sev, "persistence", "insmod/modprobe in persistence script",
				fmt.Sprintf("insmod/modprobe call in persistence script %s (line %d): %s",
					path, i+1, trimmed))
		}
	}

	if hits == 0 {
		w.Write("No insmod/modprobe calls found in persistence or staging locations.\n")
		output.Ok("No insmod in boot/persistence scripts")
	} else {
		output.Warn(fmt.Sprintf("insmod/modprobe in persistence scripts: %d hit(s)", hits))
	}
}

var unitSearchDirs = []string{
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/usr/local/lib/systemd/system",
}

func persistenceSuspiciousSystemdExecStart(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "08_suspicious_systemd_execstart.txt",
		"Systemd Services with Suspicious Exec Directive Paths",
		"/etc/systemd/system, /lib/systemd/system, /run/systemd/system, /usr/lib/systemd/system")
	defer w.Close()

	// execDirectives covers ExecStart and lifecycle hooks abused by malware
	// (e.g. ExecStartPost=/var/tmp/.222/top).
	execDirectives := []string{"ExecStart", "ExecStartPost", "ExecStartPre", "ExecStop", "ExecReload"}

	// collectUnitPaths gathers .service paths from a directory, including one
	// level of subdirectories (.wants, .requires, etc.) following symlinks.
	// seenReal deduplicates by resolved path so a symlinked unit is not
	// scanned twice when it appears in both the parent dir and a .wants/ subdir.
	seenReal := make(map[string]bool)
	collectUnitPaths := func(dir string) []string {
		var paths []string
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				// Descend one level (covers .wants/, .requires/).
				subs, _ := os.ReadDir(p)
				for _, se := range subs {
					if se.IsDir() || !strings.HasSuffix(se.Name(), ".service") {
						continue
					}
					sp := filepath.Join(p, se.Name())
					real, err := filepath.EvalSymlinks(sp)
					if err != nil {
						real = sp
					}
					if !seenReal[real] {
						seenReal[real] = true
						paths = append(paths, sp)
					}
				}
				continue
			}
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				real = p
			}
			if !seenReal[real] {
				seenReal[real] = true
				paths = append(paths, p)
			}
		}
		return paths
	}

	hits := 0
	for _, dir := range unitSearchDirs {
		for _, unitPath := range collectUnitPaths(dir) {
			data, err := readEvidenceFile(ctx, unitPath)
			if err != nil {
				continue
			}

			unitName := filepath.Base(unitPath)
			for lineNum, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)

				var directive string
				for _, d := range execDirectives {
					if strings.HasPrefix(trimmed, d+"=") {
						directive = d
						break
					}
				}
				if directive == "" {
					continue
				}

				val := strings.TrimPrefix(trimmed, directive+"=")
				val = strings.TrimLeft(val, "-+!@:")
				val = strings.TrimSpace(val)
				if val == "" {
					continue
				}

				// classifyShellCommand catches reverse-shell payloads in
				// ExecStart=/bin/bash -c '...' where the binary is safe but the
				// argument is malicious.
				if sev, reason := classifyShellCommand(val); sev != "" {
					hits++
					w.Write("  [%s] Unit      : %s\n", sev, unitPath)
					w.Write("          Line      : %d\n", lineNum+1)
					w.Write("          Directive : %s=%s\n", directive, val)
					w.Write("          Reason    : %s\n\n", reason)
					ctx.Registry.Add(output.HIGH, "persistence", "Malicious systemd ExecStart",
						fmt.Sprintf("System unit %s: %s= contains %s", unitName, directive, reason))
					continue
				}

				fields := strings.Fields(val)
				if len(fields) == 0 {
					continue
				}
				binPath := fields[0]

				// Bare name (no path separator) is a standard system utility
				// invoked via PATH, not suspicious.
				if !strings.Contains(binPath, "/") {
					continue
				}

				inMalware := ioc.IsInMalwareDir(binPath)
				inSafe := ioc.IsInSafeDir(binPath)

				if !inMalware && inSafe {
					continue
				}

				sev := output.MEDIUM
				if inMalware {
					sev = output.HIGH
				}

				hits++
				w.Write("  [%s] Unit      : %s\n", sev, unitPath)
				w.Write("          Line      : %d\n", lineNum+1)
				w.Write("          Directive : %s=%s\n", directive, val)
				w.Write("          Binary    : %s\n\n", binPath)

				ctx.Registry.Add(sev, "persistence", "Suspicious systemd exec path",
					fmt.Sprintf("Systemd unit %s %s= points to suspicious path: %s",
						unitName, directive, binPath))
			}
		}
	}

	if hits == 0 {
		w.Write("No suspicious systemd exec directive paths found.\n")
		output.Ok("No suspicious systemd exec directive paths")
	} else {
		output.Warn(fmt.Sprintf("Suspicious systemd exec directive paths: %d hit(s)", hits))
	}
}

func persistenceMotdPersistence(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "09_motd_persistence.txt",
		"MotD / Profile Script Persistence",
		"/etc/update-motd.d/, /etc/motd, /etc/motd.d/, /etc/profile.d/")
	defer w.Close()

	hits := 0

	// Static MOTD file
	if data, err := readEvidenceFile(ctx, "/etc/motd"); err == nil {
		bestSev, bestReason, bestLine := classifyFileLines(string(data), nil)
		if bestSev != "" {
			w.WriteSectionHeader("/etc/motd")
			w.Write("  [%s] %s — %s\n", bestSev, bestReason, bestLine)
			ctx.Registry.Add(bestSev, "persistence", "Suspicious MotD/profile script command",
				fmt.Sprintf("%s in /etc/motd: %.120s", bestReason, bestLine))
			hits++
		}
	}

	for _, dir := range []string{"/etc/update-motd.d", "/etc/motd.d", "/etc/profile.d"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			info, _ := e.Info()
			isExec := info != nil && info.Mode()&0111 != 0

			bestSev, bestReason, bestLine := classifyFileLines(string(data), nil)
			if bestSev != "" {
				w.WriteSectionHeader(p)
				w.Write("  [%s] %s — %s\n", bestSev, bestReason, bestLine)
				ctx.Registry.Add(bestSev, "persistence", "Suspicious MotD/profile script command",
					fmt.Sprintf("%s in %s: %.120s", bestReason, p, bestLine))
				hits++
			}
			if isExec && recentlyModified(p, persistenceRecentHours) && bestSev == "" {
				ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added executable MOTD script",
					fmt.Sprintf("Executable MOTD script added within 72h: %s", p))
				hits++
			}
		}
	}

	if hits == 0 {
		w.Write("No suspicious commands in MotD or profile scripts.\n")
		output.Ok("MotD/profile persistence: clean")
	} else {
		output.Warn(fmt.Sprintf("Suspicious MotD/profile script commands: %d hit(s)", hits))
	}
}

func persistenceShellProfileAnalysis(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "10_shell_profile_analysis.txt",
		"Shell Profile Malicious Command Analysis",
		"/etc/profile, /etc/bashrc, /etc/bash.bashrc, ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc, ~/.zprofile, ~/.bash_logout")
	defer w.Close()

	paths := []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"}

	roots := []string{"/root"}
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range entries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				roots = append(roots, pe.HomeDir)
			}
		}
	}
	dotfiles := persistenceDotfiles
	for _, home := range roots {
		for _, df := range dotfiles {
			paths = append(paths, filepath.Join(home, df))
		}
	}

	seen := make(map[string]bool)
	hits := 0
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		if ctx.SelfPath != "" && path == ctx.SelfPath {
			continue
		}
		data, err := readEvidenceFile(ctx, path)
		if err != nil {
			continue
		}
		bestSev := output.Severity("")
		bestReason := ""
		bestLine := ""
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if osutil.IsCommentOrBlank(trimmed) {
				continue
			}
			if sev, reason := classifyShellCommand(trimmed); sev != "" {
				if bestSev == "" || (sev == output.HIGH && bestSev != output.HIGH) {
					bestSev = sev
					bestReason = reason
					bestLine = trimmed
				}
				if bestSev == output.HIGH {
					break
				}
			}
		}
		if bestSev != "" {
			w.Write("  [%s] %s — %s: %.120s\n", bestSev, bestReason, path, bestLine)
			ctx.Registry.Add(bestSev, "persistence", "Malicious shell profile command",
				fmt.Sprintf("%s in %s: %.120s", bestReason, path, bestLine))
			hits++
		}
	}
	if hits == 0 {
		w.Write("No suspicious commands found in shell profile files.\n")
		output.Ok("Shell profile analysis: clean")
	} else {
		output.Warn(fmt.Sprintf("Malicious shell profile commands: %d hit(s)", hits))
	}
}

type dpkgLifecycleHit struct {
	path  string
	sev   output.Severity
	label string
	msg   string
}

// scanDpkgLifecycleScripts walks infoDir for DPKG lifecycle script files
// (.postinst, .preinst, .prerm, .postrm), skipping dpkg.* self-files,
// and returns findings for malicious content or recently modified scripts.
func scanDpkgLifecycleScripts(ctx *ModuleContext, infoDir string) []dpkgLifecycleHit {
	lifecycleExts := map[string]bool{
		".postinst": true, ".preinst": true, ".prerm": true, ".postrm": true,
	}
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil
	}
	var hits []dpkgLifecycleHit
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "dpkg.") {
			continue
		}
		if !lifecycleExts[filepath.Ext(name)] {
			continue
		}
		p := filepath.Join(infoDir, name)
		data, err := readEvidenceFile(ctx, p)
		if err != nil {
			continue
		}
		if bestSev, bestReason, bestLine := classifyFileLines(string(data), map[string]bool{"chmod setting SUID/SGID bit (octal notation)": true}); bestSev != "" {
			hits = append(hits, dpkgLifecycleHit{
				path:  p,
				sev:   bestSev,
				label: "Malicious DPKG lifecycle script",
				msg:   fmt.Sprintf("DPKG lifecycle script %s contains [%s]: %.120s", p, bestReason, bestLine),
			})
		} else if recentlyModified(p, persistenceRecentHours) {
			hits = append(hits, dpkgLifecycleHit{
				path:  p,
				sev:   output.MEDIUM,
				label: "Recently modified DPKG lifecycle script",
				msg:   fmt.Sprintf("DPKG lifecycle script modified within 72h: %s", p),
			})
		}
	}
	return hits
}

func persistencePackageManagerHooks(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "11_pkg_manager_hooks.txt",
		"Package Manager Hook Persistence",
		"/etc/apt/apt.conf.d/, /usr/lib/yum-plugins/, dnf plugin dirs")
	defer w.Close()

	hits := 0

	// APT hooks
	aptFiles := []string{"/etc/apt/apt.conf"}
	if entries, err := os.ReadDir("/etc/apt/apt.conf.d"); err == nil {
		for _, e := range entries {
			aptFiles = append(aptFiles, filepath.Join("/etc/apt/apt.conf.d", e.Name()))
		}
	}
	for _, f := range aptFiles {
		data, err := readEvidenceFile(ctx, f)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(f)
		w.WriteString(string(data))
		for _, cmd := range extractAPTHookCommands(string(data)) {
			if sev, reason := classifyShellCommand(cmd); sev != "" {
				ctx.Registry.Add(sev, "persistence", "Malicious APT hook command",
					fmt.Sprintf("APT hook in %s executes [%s]: %.120s", f, reason, cmd))
				hits++
			}
		}
		if recentlyModified(f, persistenceRecentHours) {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added APT hook config",
				fmt.Sprintf("APT hook config modified within 72h: %s", f))
			hits++
		}
	}

	// yum plugin .py files
	for _, d := range []string{"/usr/lib/yum-plugins"} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".py") {
				continue
			}
			p := filepath.Join(d, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			w.WriteSectionHeader(p)
			if bestSev, bestReason, bestLine := classifyFileLines(string(data), nil); bestSev != "" {
				ctx.Registry.Add(bestSev, "persistence", "Malicious yum plugin",
					fmt.Sprintf("yum plugin %s contains [%s]: %.120s", p, bestReason, bestLine))
				hits++
			}
		}
	}

	// dnf plugin .py files under /usr/lib/python3*/site-packages/dnf-plugins/
	dnfDirs, _ := filepath.Glob("/usr/lib/python3*/site-packages/dnf-plugins")
	dnfDirs = append(dnfDirs, "/usr/lib/python3/site-packages/dnf-plugins")
	for _, d := range dnfDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".py") {
				continue
			}
			p := filepath.Join(d, e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			w.WriteSectionHeader(p)
			if bestSev, bestReason, bestLine := classifyFileLines(string(data), nil); bestSev != "" {
				ctx.Registry.Add(bestSev, "persistence", "Malicious dnf plugin",
					fmt.Sprintf("dnf plugin %s contains [%s]: %.120s", p, bestReason, bestLine))
				hits++
			}
		}
	}

	// DPKG lifecycle scripts
	for _, h := range scanDpkgLifecycleScripts(ctx, "/var/lib/dpkg/info") {
		w.Write("  [%s] %s\n", h.sev, h.msg)
		ctx.Registry.Add(h.sev, "persistence", h.label, h.msg)
		hits++
	}

	if hits == 0 {
		w.Write("No suspicious package manager hooks found.\n")
		output.Ok("Package manager hooks: clean")
	} else {
		output.Warn(fmt.Sprintf("Suspicious package manager hooks: %d hit(s)", hits))
	}
}

func persistenceGitHooks(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "12_git_hooks.txt",
		"Git Hook Persistence",
		"~/.git/hooks/, /var/www, /srv, /opt — depth 5; ~/.gitconfig, /etc/gitconfig")
	defer w.Close()

	roots := []string{"/var/www", "/srv", "/opt"}
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range entries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				roots = append(roots, pe.HomeDir)
			}
		}
	}

	hits := 0

	for _, root := range roots {
		for _, hooksDir := range findGitHooksDirs(root, 5) {
			entries, err := os.ReadDir(hooksDir)
			if err != nil {
				continue
			}
			w.WriteSectionHeader(hooksDir)
			for _, e := range entries {
				if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
					continue
				}
				p := filepath.Join(hooksDir, e.Name())
				info, _ := e.Info()
				if info == nil || info.Mode()&0111 == 0 {
					w.Write("  [not-exec] %s\n", e.Name())
					continue
				}
				data, err := readEvidenceFile(ctx, p)
				if err != nil {
					continue
				}
				w.Write("  [exec] %s\n%s\n", e.Name(), string(data))

				bestSev, bestReason, bestLine := classifyFileLines(string(data), nil)
				if bestSev != "" {
					ctx.Registry.Add(bestSev, "persistence", "Malicious git hook",
						fmt.Sprintf("Git hook %s contains [%s]: %.120s", p, bestReason, bestLine))
					hits++
				} else if recentlyModified(p, persistenceRecentHours) {
					ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added git hook",
						fmt.Sprintf("Executable git hook added within 72h: %s", p))
					hits++
				}
			}
		}
	}

	// Scan gitconfig core.pager / core.editor
	gitConfigs := []string{"/etc/gitconfig"}
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range entries {
			if pe.HomeDir != "" {
				gitConfigs = append(gitConfigs, filepath.Join(pe.HomeDir, ".gitconfig"))
			}
		}
	}
	for _, gc := range gitConfigs {
		data, err := readEvidenceFile(ctx, gc)
		if err != nil {
			continue
		}
		vals := parseGitConfigValues(string(data), "pager", "editor", "hooksPath")
		pagerVal, editorVal, hookPathVal := vals[0], vals[1], vals[2]
		for _, val := range []string{pagerVal, editorVal} {
			if val == "" {
				continue
			}
			if sev, reason := classifyShellCommand(val); sev != "" {
				ctx.Registry.Add(sev, "persistence", "Malicious gitconfig hook",
					fmt.Sprintf("gitconfig %s core.pager/editor [%s]: %.120s", gc, reason, val))
				hits++
			}
		}
		if hookPath := hookPathVal; hookPath != "" {
			w.Write("  [hooksPath] %s → %s\n", gc, hookPath)
			if sev, reason := classifyGitHooksPath(hookPath); sev != "" {
				label := "Suspicious gitconfig hooksPath"
				if sev == output.HIGH {
					label = "Malicious gitconfig hooksPath"
				}
				ctx.Registry.Add(sev, "persistence", label,
					fmt.Sprintf("gitconfig %s: %s: %s", gc, reason, hookPath))
				hits++
			}
		}
	}

	if hits == 0 {
		w.Write("No suspicious git hooks found.\n")
		output.Ok("Git hooks: clean")
	} else {
		output.Warn(fmt.Sprintf("Suspicious git hooks: %d hit(s)", hits))
	}
}

func persistenceStagingSharedObjects(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "13_staging_shared_objects.txt",
		"Shared Objects in Staging Directories",
		"/tmp, /var/tmp, /dev/shm — LD_PRELOAD backdoor indicators")
	defer w.Close()

	stagingDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	hits := 0
	for _, d := range stagingDirs {
		for _, p := range scanDirForSharedObjects(d) {
			if ctx.SelfPath != "" && p == ctx.SelfPath {
				continue
			}
			w.Write("  [HIGH] .so in staging dir: %s\n", p)
			ctx.Registry.Add(output.HIGH, "persistence", "Shared object in staging directory",
				fmt.Sprintf("Shared object in staging directory: %s — LD_PRELOAD backdoor indicator", p))
			hits++
		}
	}
	if hits == 0 {
		w.Write("No shared objects found in staging directories.\n")
		output.Ok("Staging shared objects: clean")
	} else {
		output.Warn(fmt.Sprintf("Staging shared objects: %d hit(s)", hits))
	}
}

type ldPreloadResult struct {
	sev   output.Severity
	label string
	msg   string
}

// classifyLDPreloadEntries analyses parsed lines from /etc/ld.so.preload.
func classifyLDPreloadEntries(lines []string) []ldPreloadResult {
	var results []ldPreloadResult
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if osutil.IsCommentOrBlank(line) {
			continue
		}
		if ioc.IsInMalwareDir(line) {
			results = append(results, ldPreloadResult{
				sev:   output.HIGH,
				label: "Malicious LD_PRELOAD entry",
				msg:   fmt.Sprintf("ld.so.preload entry in staging path: %s", line),
			})
			continue
		}
		if _, err := os.Stat(line); os.IsNotExist(err) {
			results = append(results, ldPreloadResult{
				sev:   output.MEDIUM,
				label: "Missing LD_PRELOAD library",
				msg:   fmt.Sprintf("ld.so.preload references missing file: %s", line),
			})
		}
	}
	return results
}

func classifyLDSoConfEntries(filePath string, lines []string) []ldPreloadResult {
	var results []ldPreloadResult
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// "include " with trailing space to avoid matching paths like /usr/include/...
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "include ") {
			continue
		}
		if ioc.IsInMalwareDir(line) {
			results = append(results, ldPreloadResult{
				sev:   output.HIGH,
				label: "Malicious ld.so.conf entry",
				msg:   fmt.Sprintf("%s references staging path: %s", filePath, line),
			})
		}
	}
	return results
}

func persistenceLDPreload(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "14_ld_preload.txt",
		"LD_PRELOAD Hijack Vectors", "/etc/ld.so.preload")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	data, err := readEvidenceFile(ctx, "/etc/ld.so.preload")
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		w.Write("/etc/ld.so.preload is empty or absent.\n")
	} else {
		w.Write("/etc/ld.so.preload contents:\n%s\n", string(data))
		ctx.Registry.Add(output.HIGH, "persistence", "LD_PRELOAD rootkit indicator",
			"/etc/ld.so.preload is populated — likely LD_PRELOAD rootkit")

		lines := strings.Split(string(data), "\n")
		for _, r := range classifyLDPreloadEntries(lines) {
			w.Write("  [%s] %s\n", r.sev, r.msg)
			ctx.Registry.Add(r.sev, "persistence", r.label, r.msg)
		}

		if recentlyModified("/etc/ld.so.preload", persistenceRecentHours) {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently modified LD_PRELOAD config",
				"/etc/ld.so.preload modified within 72h")
		}
	}

	// ld.so.conf and ld.so.conf.d/ -- directory-based library preloading
	w.WriteSectionHeader("/etc/ld.so.conf and /etc/ld.so.conf.d/")
	var confPaths []string
	confPaths = append(confPaths, "/etc/ld.so.conf")
	if entries, err := os.ReadDir("/etc/ld.so.conf.d"); err == nil {
		for _, e := range entries {
			confPaths = append(confPaths, filepath.Join("/etc/ld.so.conf.d", e.Name()))
		}
	}
	for _, confPath := range confPaths {
		data, err := readEvidenceFile(ctx, confPath)
		if err != nil {
			continue
		}
		w.Write("─── %s ───\n%s\n", confPath, string(data))
		lines := strings.Split(string(data), "\n")
		for _, r := range classifyLDSoConfEntries(confPath, lines) {
			w.Write("  [%s] %s\n", r.sev, r.msg)
			ctx.Registry.Add(r.sev, "persistence", r.label, r.msg)
		}
		if recentlyModified(confPath, persistenceRecentHours) {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently modified ld.so.conf",
				fmt.Sprintf("ld.so.conf file modified within 72h: %s", confPath))
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("LD_PRELOAD vectors: %d hit(s)", delta))
	} else {
		output.Ok("ld.so.preload / ld.so.conf.d: clean")
	}
}

var dkmsTaintAllowlist = map[string]bool{
	"nvidia": true, "nvidia_modeset": true, "nvidia_uvm": true, "nvidia_drm": true,
	"vboxdrv": true, "vboxnetflt": true, "vboxnetadp": true, "vboxsf": true,
	"vmw_vmci": true, "vmwgfx": true, "vmw_balloon": true, "vmw_vsock_vmci_transport": true,
	"fglrx": true,
}

// normalizeModName canonicalizes a kernel module name for cross-correlation.
// /proc/modules reports names with '_', while .ko filenames may use '-';
// modprobe treats the two as equivalent, so we fold '-' to '_'.
func normalizeModName(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

// classifyKernelModuleTaint returns severity and label if the module's taint string
// contains O (out-of-tree) or E (unsigned), and the module is not in the DKMS allowlist.
func classifyKernelModuleTaint(name, taint string, allowlist map[string]bool) (output.Severity, string, bool) {
	if allowlist[name] {
		return "", "", false
	}
	if !strings.ContainsAny(taint, "OE") {
		return "", "", false
	}
	// E (unsigned / force-loaded) is a stronger rootkit signal than O (out-of-tree).
	// Persistence is now the single owner of this finding (baseline no longer reports
	// unsigned modules), so it carries the higher severity for E. The title stays the
	// same so detections.go enrichment and universal.yaml suppressions keep matching.
	if strings.ContainsRune(taint, 'E') {
		return output.HIGH, "Out-of-tree or unsigned kernel module", true
	}
	return output.MEDIUM, "Out-of-tree or unsigned kernel module", true
}

// isDKMSPath returns true if the .ko path is under a DKMS-managed directory
// (updates/ or extra/) where out-of-tree modules legitimately reside.
func isDKMSPath(p string) bool {
	return strings.Contains(p, "/updates/") || strings.Contains(p, "/extra/")
}

func persistenceKernelModuleAnalysis(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "15_kernel_module_analysis.txt",
		"Kernel Module Taint & Recency Analysis",
		"/proc/modules taint flags; /lib/modules/<version>/ .ko recency")
	defer w.Close()

	mods, err := procfs.ReadModules()
	if err != nil {
		w.Write("ERROR reading /proc/modules: %v\n", err)
	}

	// Build a set of tainted module names for cross-correlation
	taintedNames := make(map[string]bool)
	for _, m := range mods {
		sev, label, flagged := classifyKernelModuleTaint(m.Name, m.Taint, dkmsTaintAllowlist)
		if !flagged {
			continue
		}
		taintedNames[normalizeModName(m.Name)] = true
		w.Write("  [%s] %s — taint: %s\n", sev, m.Name, m.Taint)
		ctx.Registry.Add(sev, "persistence", label,
			fmt.Sprintf("Loaded kernel module '%s' has taint flags %q — out-of-tree or unsigned",
				m.Name, m.Taint))
	}

	kernelVer, err := procfs.ReadKernelVersion()
	if err != nil {
		w.Write("Cannot determine kernel version: %v\n", err)
		if len(taintedNames) == 0 {
			w.Write("No suspicious kernel modules detected.\n")
		}
		return
	}

	modDir := filepath.Join("/lib/modules", kernelVer)
	recentKOs := make(map[string]string) // base name → full path

	err = filepath.WalkDir(modDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if ctx.SelfPath != "" && p == ctx.SelfPath {
			return nil
		}
		if !strings.HasSuffix(p, ".ko") && !strings.HasSuffix(p, ".ko.xz") && !strings.HasSuffix(p, ".ko.zst") {
			return nil
		}
		if isDKMSPath(p) {
			return nil
		}
		if !recentlyModified(p, persistenceRecentHours) {
			return nil
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(
			filepath.Base(p), ".zst"), ".xz"), ".ko")
		recentKOs[normalizeModName(base)] = p
		return nil
	})
	if err != nil {
		w.Write("ERROR walking %s: %v\n", modDir, err)
	}

	for base, koPath := range recentKOs {
		if taintedNames[base] {
			w.Write("  [HIGH] recently added .ko (tainted): %s\n", koPath)
		} else {
			w.Write("  [MEDIUM] recently added .ko: %s\n", koPath)
		}
		if taintedNames[base] {
			// Cross-correlation: both taint + recency → HIGH
			ctx.Registry.Add(output.HIGH, "persistence", "Suspicious kernel module",
				fmt.Sprintf("Kernel module '%s' is both recently added and tainted (OE) — LKM backdoor: %s",
					base, koPath))
		} else {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently added kernel module",
				fmt.Sprintf("Kernel module .ko added within 72h outside DKMS directories: %s", koPath))
		}
	}

	if len(taintedNames) == 0 && len(recentKOs) == 0 {
		w.Write("No suspicious kernel modules detected.\n")
		output.Ok("Kernel modules: clean")
	}
}

var webShellExtensions = map[string]bool{
	".php": true, ".py": true, ".pl": true, ".rb": true,
	".lua": true, ".jsp": true, ".asp": true, ".aspx": true, ".cgi": true,
	".sh": true,
}

var webServerComms = map[string]bool{
	"apache2": true, "httpd": true, "nginx": true, "lighttpd": true, "caddy": true,
	"php-fpm": true, "php": true, "gunicorn": true, "uwsgi": true,
	"python3": true, "python": true, "ruby": true, "node": true,
}

const webShellFileSizeCap = 1 * 1024 * 1024 // 1 MB

func isWebShellExtension(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return webShellExtensions[ext]
}

type webShellHit struct {
	path  string
	sev   output.Severity
	label string
	msg   string
}

// discoverWebRoots returns deduplicated web root directories from running
// web server process cwds (read via /proc/<pid>/cwd) plus static known paths.
func discoverWebRoots(procs []*procfs.Process) []string {
	seen := make(map[string]bool)
	var roots []string

	add := func(p string) {
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			roots = append(roots, p)
		}
	}

	// Process cwds via /proc/<pid>/cwd symlink
	for _, p := range procs {
		if !webServerComms[p.Name] {
			continue
		}
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.PID))
		if err == nil && cwd != "" {
			add(cwd)
		}
	}

	// Static fallbacks
	for _, r := range []string{
		"/var/www", "/srv", "/usr/share/nginx/html",
		"/usr/share/apache2/default-site", "/var/www/html",
	} {
		add(r)
	}

	return roots
}

// scanWebRootForShells walks root and returns hits for malicious or recently added web scripts.
// selfPath is excluded from scanning. ownedFiles, if non-nil, skips dpkg-owned files.
// deadline, if non-zero, aborts the walk after the deadline passes and returns timedOut=true.
func scanWebRootForShells(root, selfPath string, ownedFiles map[string]bool, deadline time.Time) ([]webShellHit, bool) {
	var hits []webShellHit
	timedOut := false
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			timedOut = true
			return filepath.SkipAll
		}
		if selfPath != "" && p == selfPath {
			return nil
		}
		if ownedFiles != nil && ownedFiles[p] {
			return nil
		}
		if !isWebShellExtension(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > webShellFileSizeCap {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}

		bestSev, bestReason, _ := classifyFileLines(string(data), nil)
		if bestSev != "" {
			hits = append(hits, webShellHit{
				path:  p,
				sev:   bestSev,
				label: "Malicious web shell",
				msg:   fmt.Sprintf("Web shell in %s: %s", p, bestReason),
			})
			return nil
		}

		inCGI := strings.Contains(p, "/cgi-bin/") || strings.Contains(p, "/cgi/")
		isExec := (info.Mode() & 0111) != 0
		if (inCGI || isExec) && recentlyModified(p, persistenceRecentHours) {
			hits = append(hits, webShellHit{
				path:  p,
				sev:   output.MEDIUM,
				label: "Recently added web script",
				msg:   fmt.Sprintf("Web script added within 72h: %s", p),
			})
		}
		return nil
	})
	return hits, timedOut
}

func persistenceWebShells(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "16_web_shells.txt",
		"Web Shell Detection",
		"/proc/*/cwd (web server roots) + /var/www, /srv — script file content analysis")
	defer w.Close()

	procs := ctx.Processes()
	roots := discoverWebRoots(procs)
	ownedFiles := buildDpkgOwnedFiles(ctx)

	const findingCap = 20
	totalHits := 0
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		deadline := time.Now().Add(30 * time.Second)
		hits, timedOut := scanWebRootForShells(root, ctx.SelfPath, ownedFiles, deadline)
		if timedOut {
			w.Write("  [WARN] Web shell scan of %s timed out after 30s; results may be incomplete\n", root)
			ctx.Log.Log("persistence", "web-shell-timeout", root)
		}
		for i, h := range hits {
			w.Write("  [%s] %s\n", h.sev, h.msg)
			if i < findingCap {
				ctx.Registry.Add(h.sev, "persistence", h.label, h.msg)
			} else {
				ctx.Registry.AddSilent(h.sev, "persistence", h.label, h.msg)
			}
		}
		totalHits += len(hits)
	}

	if totalHits == 0 {
		w.Write("No web shells detected.\n")
		output.Ok("Web shells: none detected")
	} else {
		output.Warn(fmt.Sprintf("Web shells detected: %d hit(s)", totalHits))
	}
}

func persistencePAM(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "17_pam.txt",
		"PAM Persistence",
		"/lib/security/, /lib64/security/, /lib/x86_64-linux-gnu/security/, /usr/lib/security/, /usr/lib64/security/, /etc/pam.d/")
	defer w.Close()

	hits := 0
	ownedFiles := buildDpkgOwnedFiles(ctx)

	for _, dir := range pamLibDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".so") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			lookupPath := p
			if resolved, err := filepath.EvalSymlinks(p); err == nil {
				lookupPath = resolved
			}
			// If the resolved path isn't in ownedFiles but the original is, use the
			// original: Ubuntu records /lib/... paths in DPKG while Debian 13+ records
			// the canonical /usr/lib/... form after the /lib→/usr/lib symlink migration.
			if ownedFiles != nil && !ownedFiles[lookupPath] && ownedFiles[p] {
				lookupPath = p
			}
			sev, label := classifyPAMModule(lookupPath, ownedFiles, recentlyModified(p, persistenceRecentHours))
			if sev == "" {
				continue
			}
			w.Write("  [%s] %s — %s\n", sev, p, label)
			ctx.Registry.Add(sev, "persistence", label,
				fmt.Sprintf("%s: %s", label, p))
			hits++
		}
	}

	w.WriteSectionHeader("/etc/pam.d")
	pamdEntries, err := os.ReadDir("/etc/pam.d")
	if err != nil {
		w.Write("  /etc/pam.d not readable: %v\n", err)
	} else {
		for _, e := range pamdEntries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join("/etc/pam.d", e.Name())
			data, err := readEvidenceFile(ctx, p)
			if err != nil {
				continue
			}
			if recentlyModified(p, persistenceRecentHours) {
				w.Write("  [MEDIUM] recently modified: %s\n", p)
				ctx.Registry.Add(output.MEDIUM, "persistence", "Recently modified PAM config",
					fmt.Sprintf("PAM config modified within 72h: %s", p))
				hits++
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if osutil.IsCommentOrBlank(line) {
					continue
				}
				if !strings.Contains(line, "pam_exec.so") {
					continue
				}
				scriptPath := extractPamExecPath(line)
				if scriptPath == "" {
					continue
				}
				w.Write("  [pam_exec] %s → %s\n", p, scriptPath)
				if ioc.IsInMalwareDir(scriptPath) {
					ctx.Registry.Add(output.HIGH, "persistence", "Malicious pam_exec.so script",
						fmt.Sprintf("pam_exec.so in %s references staging path: %s", p, scriptPath))
					hits++
					continue
				}
				scriptData, err := readEvidenceFile(ctx, scriptPath)
				if err != nil {
					ctx.Registry.Add(output.MEDIUM, "persistence", "Missing pam_exec.so script",
						fmt.Sprintf("pam_exec.so in %s references missing script: %s", p, scriptPath))
					hits++
					continue
				}
				if sev, reason, _ := classifyFileLines(string(scriptData), nil); sev != "" {
					ctx.Registry.Add(sev, "persistence", "Malicious pam_exec.so script",
						fmt.Sprintf("pam_exec.so script %s contains [%s]", scriptPath, reason))
					hits++
				}
			}
		}
	}

	if hits == 0 {
		w.Write("No PAM anomalies detected.\n")
		output.Ok("PAM: clean")
	} else {
		output.Warn(fmt.Sprintf("PAM anomalies: %d hit(s)", hits))
	}
}

func persistenceExternalNetworkIndicators(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "18_external_network_indicators.txt",
		"External IP and Domain Indicators in Persistence Mechanisms",
		"/etc/crontab, cron.d, spool/cron, /etc/systemd/system/*.service, /etc/init.d/, /etc/rc.local, profiles, dotfiles")
	defer w.Close()

	paths := []string{
		"/etc/crontab",
		"/etc/rc.local",
		"/etc/profile",
		"/etc/bashrc",
		"/etc/bash.bashrc",
	}
	paths = append(paths, globPaths("/etc/cron.d/*")...)
	paths = append(paths, globPaths("/var/spool/cron/crontabs/*")...)
	paths = append(paths, globPaths("/etc/systemd/system/*.service")...)
	paths = append(paths, globPaths("/etc/profile.d/*.sh")...)

	if entries, err := os.ReadDir("/etc/init.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join("/etc/init.d", e.Name()))
		}
	}

	dotfiles := persistenceDotfiles
	homes := []string{"/root"}
	if pwEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range pwEntries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				homes = append(homes, pe.HomeDir)
			}
		}
	}
	for _, home := range homes {
		for _, df := range dotfiles {
			paths = append(paths, filepath.Join(home, df))
		}
	}

	seen := make(map[string]bool)
	headerWritten := make(map[string]bool)
	ipHits, domHits := 0, 0

	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true

		data, err := readEvidenceFile(ctx, path)
		if err != nil {
			continue
		}
		text := string(data)

		for _, ip := range ioc.ExtractExternalIPs(text) {
			if !headerWritten[path] {
				w.WriteSectionHeader(path)
				headerWritten[path] = true
			}
			w.Write("  [HIGH] External IP: %s\n", ip)
			ctx.Registry.Add(output.HIGH, "persistence", "External IP in persistence mechanism",
				fmt.Sprintf("%s: %s", path, ip))
			ipHits++
		}

		for _, domain := range ioc.ExtractDomains(text) {
			if !headerWritten[path] {
				w.WriteSectionHeader(path)
				headerWritten[path] = true
			}
			w.Write("  [MEDIUM] External domain: %s\n", domain)
			ctx.Registry.Add(output.MEDIUM, "persistence", "External domain in persistence mechanism",
				fmt.Sprintf("%s: %s", path, domain))
			domHits++
		}
	}

	if ipHits == 0 && domHits == 0 {
		w.Write("None found.\n")
		output.Ok("Persistence external network indicators: clean")
	} else {
		output.Warn(fmt.Sprintf("External indicators in persistence: %d IP(s), %d domain(s)", ipHits, domHits))
	}
}

func persistenceSSHAuthorizedKeys(ctx *ModuleContext) {
	var homes []string
	homes = append(homes, "/root")
	if pwEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range pwEntries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				homes = append(homes, pe.HomeDir)
			}
		}
	}
	persistenceSSHAuthorizedKeysRoots(ctx, homes)
}

func persistenceSSHAuthorizedKeysRoots(ctx *ModuleContext, homes []string) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "19_ssh_authorized_keys.txt",
		"SSH Authorized Keys",
		"~/.ssh/authorized_keys for all users — backdoor key indicator")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	total := 0
	for _, home := range homes {
		keyFile := filepath.Join(home, ".ssh", "authorized_keys")
		data, err := readEvidenceFile(ctx, keyFile)
		if err != nil {
			continue
		}
		keyCount := 0
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				keyCount++
			}
		}
		if keyCount == 0 {
			continue
		}
		w.Write("  %s: %d key(s)\n%s\n", keyFile, keyCount, string(data))
		total++
		if recentlyModified(keyFile, persistenceRecentHours) {
			ctx.Registry.Add(output.MEDIUM, "persistence", "Recently modified SSH authorized_keys",
				fmt.Sprintf("authorized_keys modified within 72h (%d key(s)): %s", keyCount, keyFile))
		} else {
			ctx.Registry.Add(output.INFO, "persistence", "SSH authorized_keys found",
				fmt.Sprintf("authorized_keys with %d key(s): %s", keyCount, keyFile))
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if total == 0 {
		w.Write("No authorized_keys files found.\n")
		output.Ok("SSH authorized_keys: none found")
	} else if delta > 0 {
		output.Warn(fmt.Sprintf("SSH authorized_keys: %d finding(s)", delta))
	} else {
		output.Ok(fmt.Sprintf("SSH authorized_keys: %d file(s)", total))
	}
}

func addGlob(paths *[]string, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			*paths = append(*paths, filepath.Join(dir, e.Name()))
		}
	}
}

func isScriptExtension(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sh", ".bash", ".py", ".pl", ".rb", ".lua", ".php":
		return true
	}
	return false
}

func recentlyModified(path string, hours float64) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()).Hours() < hours
}

// buildDpkgOwnedFilesFrom reads all *.list files from infoDir and returns the
// set of file paths they contain. Used to detect files not owned by any package.
func buildDpkgOwnedFilesFrom(ctx *ModuleContext, infoDir string) map[string]bool {
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil
	}
	owned := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".list") {
			continue
		}
		data, err := readEvidenceFile(ctx, filepath.Join(infoDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				owned[line] = true
			}
		}
	}
	return owned
}

// buildDpkgOwnedFiles returns the set of all paths owned by installed DPKG packages.
func buildDpkgOwnedFiles(ctx *ModuleContext) map[string]bool {
	return buildDpkgOwnedFilesFrom(ctx, "/var/lib/dpkg/info")
}

// extractPamExecPath parses a pam.d config line and returns the first token
// beginning with '/' that appears after the pam_exec.so token, skipping
// option flags like seteuid, quiet, log=. Returns "" if none is found.
func extractPamExecPath(line string) string {
	fields := strings.Fields(line)
	found := false
	for _, f := range fields {
		if strings.Contains(f, "pam_exec.so") {
			found = true
			continue
		}
		if found && strings.HasPrefix(f, "/") {
			return f
		}
	}
	return ""
}

// pamLibDirs lists all standard PAM module library directories.
var pamLibDirs = []string{
	"/lib/security",
	"/lib64/security",
	"/lib/x86_64-linux-gnu/security",
	"/usr/lib/security",
	"/usr/lib64/security",
	"/usr/lib/aarch64-linux-gnu/security",
	"/usr/lib/arm-linux-gnueabihf/security",
}

// classifyPAMModule returns severity and label for a PAM .so file based on
// package ownership and recency. Returns ("", "") for clean packaged modules.
func classifyPAMModule(path string, ownedFiles map[string]bool, recentlyMod bool) (output.Severity, string) {
	if ownedFiles == nil {
		if recentlyMod {
			return output.MEDIUM, "Recently modified PAM module"
		}
		return "", ""
	}
	unpackaged := !ownedFiles[path]
	switch {
	case unpackaged && recentlyMod:
		return output.HIGH, "Suspicious PAM module"
	case unpackaged:
		return output.HIGH, "Unpackaged PAM module"
	case recentlyMod:
		return output.MEDIUM, "Recently modified PAM module"
	}
	return "", ""
}

// classifyFileLines scans content line-by-line with classifyShellCommand and
// returns the best (highest) severity match found.
func classifyFileLines(content string, skip map[string]bool) (sev output.Severity, reason, line string) {
	for _, l := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(l)
		if osutil.IsCommentOrBlank(trimmed) {
			continue
		}
		s, r := classifyShellCommand(trimmed)
		if s == "" || skip[r] {
			continue
		}
		if sev == "" || (s == output.HIGH && sev != output.HIGH) {
			sev, reason, line = s, r, trimmed
		}
		if sev == output.HIGH {
			break
		}
	}
	return
}

func extractAPTHookCommands(content string) []string {
	var cmds []string
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20) // 8 MiB: long APT config lines must not silently truncate
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, "Pre-Invoke") && !strings.Contains(line, "Post-Invoke") &&
			!strings.Contains(line, "DPkg::Pre-Install-Pkgs") {
			continue
		}
		start := strings.Index(line, `"`)
		end := strings.LastIndex(line, `"`)
		if start >= 0 && end > start {
			cmds = append(cmds, line[start+1:end])
		}
	}
	return cmds
}

func findGitHooksDirs(root string, maxDepth int) []string {
	var result []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		hooksDir := filepath.Join(dir, ".git", "hooks")
		if info, err := os.Stat(hooksDir); err == nil && info.IsDir() {
			result = append(result, hooksDir)
			return
		}
		if depth >= maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				walk(filepath.Join(dir, e.Name()), depth+1)
			}
		}
	}
	walk(root, 0)
	return result
}

// classifyGitHooksPath returns severity and label for a core.hooksPath value.
// Staging/malware dirs are HIGH; system paths are clean; any other custom path is MEDIUM.
func classifyGitHooksPath(path string) (output.Severity, string) {
	if path == "" {
		return "", ""
	}
	if ioc.IsInMalwareDir(path) {
		return output.HIGH, "core.hooksPath points to staging/malware path"
	}
	if ioc.IsInSafeDir(path) {
		return "", ""
	}
	return output.MEDIUM, "core.hooksPath redirects git hooks to non-standard directory"
}

func parseGitConfigValues(content string, keys ...string) []string {
	vals := make([]string, len(keys))
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		for i, key := range keys {
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					vals[i] = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return vals
}

// scanSudoersFile scans path for NOPASSWD grants and, when isDropin is true,
// also flags recently modified drop-in files. w may be nil (used in tests).
// Returns the number of findings added to ctx.Registry.
func scanSudoersFile(ctx *ModuleContext, w *output.Writer, path string, isDropin bool) int {
	data, err := readEvidenceFile(ctx, path)
	if err != nil {
		return 0
	}
	hits := 0
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if osutil.IsCommentOrBlank(trimmed) {
			continue
		}
		upper := strings.ToUpper(trimmed)
		if !strings.Contains(upper, "NOPASSWD") {
			continue
		}
		var sev output.Severity
		var label string
		normalized := strings.NewReplacer(" ", "", "\t", "").Replace(upper)
		if strings.Contains(normalized, "NOPASSWD:ALL") {
			sev = output.HIGH
			label = "Sudoers NOPASSWD:ALL grant"
		} else {
			sev = output.MEDIUM
			label = "Sudoers NOPASSWD grant"
		}
		msg := fmt.Sprintf("NOPASSWD grant in %s: %s", path, trimmed)
		if w != nil {
			w.Write("  [%s] %s\n", sev, msg)
		}
		ctx.Registry.Add(sev, "persistence", label, msg)
		hits++
	}
	if isDropin && recentlyModified(path, persistenceRecentHours) {
		msg := fmt.Sprintf("Sudoers drop-in modified within %.0fh: %s", persistenceRecentHours, path)
		if w != nil {
			w.Write("  [MEDIUM] %s\n", msg)
		}
		ctx.Registry.Add(output.MEDIUM, "persistence", "Recently modified sudoers drop-in", msg)
		hits++
	}
	return hits
}

func persistenceSudoers(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Persistence, "20_sudoers.txt",
		"Sudoers Privilege Grants",
		"/etc/sudoers, /etc/sudoers.d/ -- NOPASSWD grant analysis")
	defer w.Close()

	hits := scanSudoersFile(ctx, w, "/etc/sudoers", false)

	entries, err := os.ReadDir("/etc/sudoers.d")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// sudoers ignores files whose names contain '.' or '~'
			if strings.ContainsAny(name, ".~") {
				continue
			}
			hits += scanSudoersFile(ctx, w, filepath.Join("/etc/sudoers.d", name), true)
		}
	}

	if hits == 0 {
		w.Write("No suspicious sudoers entries found.\n")
		output.Ok("Sudoers: no NOPASSWD grants")
	} else {
		output.Warn(fmt.Sprintf("Suspicious sudoers entries: %d NOPASSWD grant(s) found", hits))
	}
}
