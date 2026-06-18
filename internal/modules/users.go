package modules

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

const authorizedKeysRecencyWindow = 72 * time.Hour

func formatAge(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// RunUsers executes the -users module (user artifacts)
func RunUsers(ctx *ModuleContext) {
	output.Chapter("[USERS] Pulling user artifacts...")
	output.Info("Output → " + ctx.Dirs.Users)

	usersAccounts(ctx)
	usersSuspiciousSystemUserShells(ctx)
	usersEtcShellsIntegrity(ctx)
	usersShellHistory(ctx)
	usersSSHKeys(ctx)
	usersCredentialFiles(ctx)
	usersStartupFiles(ctx)
	usersStagingDirs(ctx)
	usersRecentlyModified(ctx)
	usersBashHistorySuspicious(ctx)
	usersPasswdGroupDiff(ctx)
	usersSSHDConfigAnalysis(ctx)

	ctx.Log.Log("users", "complete", "all sections done")
}

func countBtmpFailures(records []procfs.UtmpRecord) int {
	n := 0
	for _, r := range records {
		if r.Type == 7 {
			n++
		}
	}
	return n
}

func usersAccounts(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "01_users_sessions.txt",
		"Users & Sessions", "/etc/passwd, /var/run/utmp, /var/log/wtmp, /var/log/btmp")
	defer w.Close()
	h0, m0, l0, _ := ctx.Registry.Counts()

	entries, err := procfs.ReadPasswd()
	if err != nil {
		w.Write("ERROR reading /etc/passwd: %v\n", err)
	} else {
		w.WriteSectionHeader("/etc/passwd")
		w.Write("%-20s %-6s %-6s %-30s %s\n", "USERNAME", "UID", "GID", "HOME", "SHELL")
		w.Write("%s\n", strings.Repeat("─", 80))
		for _, e := range entries {
			w.Write("%-20s %-6d %-6d %-30s %s\n", e.Username, e.UID, e.GID, e.HomeDir, e.Shell)
			if e.UID == 0 && e.Username != "root" {
				ctx.Registry.Add(output.HIGH, "users", "Non-root UID-0 account",
					fmt.Sprintf("Non-root UID-0 account: %s — backdoor account likely", e.Username))
			}
		}
	}

	w.WriteSectionHeader("Active Sessions (/var/run/utmp)")
	active, err := procfs.ReadUtmp()
	if err != nil {
		w.Write("Could not read utmp: %v\n", err)
	} else {
		w.Write("%-16s %-12s %-20s %s\n", "USER", "TTY", "HOST", "TIME")
		w.Write("%s\n", strings.Repeat("─", 70))
		for _, r := range active {
			w.Write("%-16s %-12s %-20s %s\n",
				r.User, r.Line, r.Host, r.Time().Format(time.RFC3339))
		}
	}

	w.WriteSectionHeader("Login History (/var/log/wtmp, last 40)")
	wtmp, err := procfs.ReadWtmp()
	if err != nil {
		w.Write("Could not read wtmp: %v\n", err)
	} else {
		count := 0
		w.Write("%-16s %-12s %-20s %s\n", "USER", "TTY", "HOST", "TIME")
		w.Write("%s\n", strings.Repeat("─", 70))
		for i := len(wtmp) - 1; i >= 0 && count < 40; i-- {
			r := wtmp[i]
			if r.Type != 7 {
				continue
			}
			w.Write("%-16s %-12s %-20s %s\n",
				r.User, r.Line, r.Host, r.Time().Format(time.RFC3339))
			count++
		}
	}

	w.WriteSectionHeader("Failed Logins (/var/log/btmp, last 30)")
	btmp, err := procfs.ReadBtmp()
	if err != nil {
		w.Write("Could not read btmp (may not exist): %v\n", err)
	} else {
		failCount := countBtmpFailures(btmp)
		count := 0
		w.Write("%-16s %-12s %-20s %s\n", "USER", "TTY", "HOST", "TIME")
		w.Write("%s\n", strings.Repeat("─", 70))
		for i := len(btmp) - 1; i >= 0; i-- {
			r := btmp[i]
			if r.Type != 7 {
				continue
			}
			if count >= 30 {
				break
			}
			w.Write("%-16s %-12s %-20s %s\n",
				r.User, r.Line, r.Host, r.Time().Format(time.RFC3339))
			count++
		}
		if failCount > 100 {
			ctx.Registry.Add(output.HIGH, "users", "Failed login attempts in btmp",
				fmt.Sprintf("%d failed login attempts in btmp — possible brute force", failCount))
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Users and sessions: %d finding(s)", delta))
	} else {
		output.Ok("Users and sessions collected")
	}
}

func usersShellHistory(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "02_shell_history.txt",
		"Shell History — All Users", "~/.bash_history, ~/.zsh_history, ~/.dash_history")
	defer w.Close()

	patterns := []string{"/root/.bash_history", "/root/.zsh_history", "/root/.dash_history"}
	entries, _ := procfs.ReadPasswd()
	for _, e := range entries {
		if e.HomeDir == "" || e.HomeDir == "/" {
			continue
		}
		patterns = append(patterns,
			filepath.Join(e.HomeDir, ".bash_history"),
			filepath.Join(e.HomeDir, ".zsh_history"),
			filepath.Join(e.HomeDir, ".dash_history"),
		)
	}

	found := 0
	for _, p := range patterns {
		data, err := readEvidenceFile(ctx, p)
		if err != nil {
			continue
		}
		found++
		w.WriteSectionHeader(p)
		w.WriteString(string(data))
		w.Write("\n")
	}
	if found == 0 {
		w.Write("No shell history files found.\n")
	}
	output.Ok(fmt.Sprintf("Shell history files collected: %d", found))
}

func usersSSHKeys(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "03_ssh_keys_config.txt",
		"SSH Authorized Keys & Client Config", "~/.ssh/authorized_keys, ~/.ssh/config")
	defer w.Close()
	h0, m0, l0, _ := ctx.Registry.Counts()

	seen := make(map[string]bool)
	var searchRoots []string
	addRoot := func(p string) {
		if p != "" && p != "/" && !seen[p] {
			seen[p] = true
			searchRoots = append(searchRoots, p)
		}
	}
	addRoot("/root")
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			addRoot(e.HomeDir)
		}
	}

	tunnelUsers := []string{}
	for _, home := range searchRoots {
		for _, akFile := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(home, ".ssh", akFile)
			if data, err := readEvidenceFile(ctx, p); err == nil {
				w.WriteSectionHeader(p)
				w.WriteString(string(data))
				w.Write("\n")
				if info, err := os.Stat(p); err == nil {
					age := time.Since(info.ModTime())
					if age < authorizedKeysRecencyWindow {
						ctx.Registry.Add(output.HIGH, "users", "Recently modified authorized_keys",
							fmt.Sprintf("authorized_keys modified %s ago: %s", formatAge(age), p))
					}
				}
			}
		}
		sshConf := filepath.Join(home, ".ssh", "config")
		if data, err := readEvidenceFile(ctx, sshConf); err == nil {
			w.WriteSectionHeader(sshConf)
			w.WriteString(string(data))
			w.Write("\n")
			content := string(data)
			if containsAny(content, []string{"ProxyJump", "ProxyCommand", "DynamicForward",
				"LocalForward", "RemoteForward"}) {
				tunnelUsers = append(tunnelUsers, sshConf)
			}
		}
	}

	if len(tunnelUsers) > 0 {
		ctx.Registry.Add(output.MEDIUM, "users", "SSH tunnel/proxy directive",
			fmt.Sprintf("SSH tunnel/proxy directives in: %s", strings.Join(tunnelUsers, ", ")))
	}
	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("SSH keys: %d finding(s)", delta))
	} else {
		output.Ok("SSH keys and configs collected")
	}
}

func usersCredentialFiles(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "04_credential_files.txt",
		"Plaintext Credential Files", ".netrc, .pgpass, .aws/credentials")
	defer w.Close()

	type credEntry struct{ glob, label string }
	var credFiles []credEntry
	seenPaths := make(map[string]bool)
	addCred := func(home string) {
		for _, pair := range []struct{ rel, label string }{
			{".netrc", ".netrc"},
			{".pgpass", ".pgpass"},
			{filepath.Join(".aws", "credentials"), "AWS credentials"},
		} {
			p := filepath.Join(home, pair.rel)
			if !seenPaths[p] {
				seenPaths[p] = true
				credFiles = append(credFiles, credEntry{p, pair.label})
			}
		}
	}
	addCred("/root")
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir == "" || e.HomeDir == "/" {
				continue
			}
			addCred(e.HomeDir)
		}
	}

	hits := 0
	for _, cf := range credFiles {
		data, err := readEvidenceFile(ctx, cf.glob)
		if err != nil {
			continue
		}
		hits++
		w.WriteSectionHeader(fmt.Sprintf("[%s] %s", cf.label, cf.glob))
		w.WriteString(string(data))
		w.Write("\n")
	}
	if hits > 0 {
		ctx.Registry.Add(output.HIGH, "users", "Plaintext credential file",
			fmt.Sprintf("%d plaintext credential file(s) found — see 04_credential_files.txt", hits))
	} else {
		w.Write("No plaintext credential files found.\n")
	}
	if hits > 0 {
		output.Warn(fmt.Sprintf("Plaintext credential files: %d found", hits))
	} else {
		output.Ok("Credential files scanned: none found")
	}
}

func usersStartupFiles(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "05_shell_startup_files.txt",
		"Shell Startup & Profile Files", "/etc/profile, ~/.bashrc, ~/.zshrc, etc.")
	defer w.Close()

	global := []string{
		"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/environment",
	}
	for _, f := range global {
		if data, err := readEvidenceFile(ctx, f); err == nil {
			w.WriteSectionHeader(f)
			w.WriteString(string(data))
			w.Write("\n")
		}
	}

	dotfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_logout"}
	homes := []string{"/root"}
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir != "" && e.HomeDir != "/" {
				homes = append(homes, e.HomeDir)
			}
		}
	}
	for _, home := range homes {
		for _, df := range dotfiles {
			p := filepath.Join(home, df)
			if data, err := readEvidenceFile(ctx, p); err == nil {
				w.WriteSectionHeader(p)
				w.WriteString(string(data))
				w.Write("\n")
			}
		}
	}
	output.Ok("Shell startup files collected")
}

func usersStagingDirs(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "06_staging_dirs.txt",
		"Files in Staging Dirs — with SHA-256", "/tmp, /var/tmp, /dev/shm")
	defer w.Close()
	h0, m0, l0, _ := ctx.Registry.Counts()

	stagingDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, d := range stagingDirs {
		w.WriteSectionHeader(d)
		entries, err := os.ReadDir(d)
		if err != nil {
			w.Write("  Cannot read: %v\n", err)
			continue
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			if ctx.SelfPath != "" && p == ctx.SelfPath {
				continue
			}
			if ctx.OutputPrefix != "" && strings.HasPrefix(p, ctx.OutputPrefix) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			mode := info.Mode()
			executable := mode&0111 != 0

			marker := ""
			if executable {
				marker = " [EXECUTABLE]"
			}
			w.Write("  %s  %-8s  %s  %s%s\n",
				mode.String(), osutil.FormatFileSize(info.Size()),
				info.ModTime().UTC().Format("2006-01-02 15:04:05"),
				e.Name(), marker)

			if !e.IsDir() {
				hash := hashFileSafe(p)
				w.Write("    SHA-256: %s\n", hash)

				if executable {
					ctx.Registry.Add(output.HIGH, "users", "Executable in staging directory",
						fmt.Sprintf("Executable file in staging dir: %s [sha256:%s]", p, hash))
				}

				ext := strings.ToLower(filepath.Ext(e.Name()))
				if ext != "" && ext != ".elf" && ioc.IsMagicELF(p) {
					w.Write("    → [HIDDEN ELF] magic bytes match ELF but extension is '%s'\n", ext)
					ctx.Registry.Add(output.HIGH, "users", "Executable in staging directory",
						fmt.Sprintf("ELF binary disguised as '%s' in staging dir: %s [sha256:%s]", ext, p, hash))
				}
				if ioc.IsCompressedFile(e.Name()) {
					w.Write("    → [COMPRESSED] archive file\n")
					ctx.Registry.Add(output.MEDIUM, "users", "Compressed file in staging directory",
						fmt.Sprintf("Compressed file in staging dir: %s (%s)", p, osutil.FormatFileSize(info.Size())))
				}
			}
		}
	}
	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Staging directories: %d finding(s)", delta))
	} else {
		output.Ok("Staging directories enumerated: clean")
	}
}

func usersRecentlyModified(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "07_recently_modified_files.txt",
		"Files Modified in Last 24h", "filepath.WalkDir /")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("recently modified files scan requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	output.Info("Walking filesystem for files modified in last 24h (may take a moment)…")
	cutoff := time.Now().Add(-24 * time.Hour)
	count := 0

	w.Write("%-10s %-8s %-20s %s\n", "MODE", "SIZE", "MODIFIED", "PATH")
	w.Write("%s\n", strings.Repeat("─", 80))

	walkFiles(ctx, "/", func(path string, info os.FileInfo) {
		if info.ModTime().After(cutoff) {
			w.Write("%-10s %-8s %-20s %s\n",
				info.Mode().String(),
				osutil.FormatFileSize(info.Size()),
				info.ModTime().UTC().Format("2006-01-02 15:04:05"),
				path)
			count++
		}
	})

	output.Ok(fmt.Sprintf("Recently modified files: %d", count))
}

func usersBashHistorySuspicious(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "08_bash_history_suspicious.txt",
		"Suspicious Commands in Shell History", "~/.bash_history, ~/.zsh_history, ~/.dash_history")
	defer w.Close()

	histFiles := []string{"/root/.bash_history", "/root/.zsh_history", "/root/.dash_history"}
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir != "" && e.HomeDir != "/" {
				histFiles = append(histFiles,
					filepath.Join(e.HomeDir, ".bash_history"),
					filepath.Join(e.HomeDir, ".zsh_history"),
					filepath.Join(e.HomeDir, ".dash_history"),
				)
			}
		}
	}

	totalHits := 0
	for _, hf := range histFiles {
		data, err := readEvidenceFile(ctx, hf)
		if err != nil {
			continue
		}
		hits := ioc.ScanLines(string(data), ioc.BashHistorySignatures)
		if len(hits) == 0 {
			continue
		}
		w.WriteSectionHeader(hf)
		for _, h := range hits {
			w.Write("  Line %-5d [%s] %s\n    → %s\n",
				h.LineNum, h.Sig.Severity, h.Sig.Description, h.Line)
			totalHits++
			ctx.Registry.Add(output.Severity(h.Sig.Severity), "users", "Suspicious shell history match",
				fmt.Sprintf("Suspicious history in %s (line %d) — %s: %s",
					hf, h.LineNum, h.Sig.ID, h.Sig.Description))
		}
	}

	if totalHits == 0 {
		w.Write("No suspicious history patterns detected.\n")
		output.Ok("No suspicious shell history patterns")
	} else {
		output.Warn(fmt.Sprintf("Suspicious history hits: %d", totalHits))
	}
}

func diffContainsAdditions(diff string) bool {
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			return true
		}
	}
	return false
}

func diffContainsRemovals(diff string) bool {
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			return true
		}
	}
	return false
}

func usersPasswdGroupDiff(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "09_passwd_group_diff.txt",
		"passwd / group Diff Against Backup",
		"diff /etc/passwd- vs /etc/passwd, /etc/group- vs /etc/group")
	defer w.Close()
	h0, m0, l0, _ := ctx.Registry.Counts()

	for _, pair := range []struct{ old, cur, label string }{
		{"/etc/passwd-", "/etc/passwd", "passwd"},
		{"/etc/group-", "/etc/group", "group"},
	} {
		w.WriteSectionHeader(fmt.Sprintf("diff %s → %s", pair.old, pair.cur))
		diff, err := procfs.DiffFiles(pair.old, pair.cur)
		if err != nil {
			w.Write("  Cannot diff: %v\n", err)
			continue
		}
		w.WriteString(diff)
		if diffContainsAdditions(diff) {
			ctx.Registry.Add(output.HIGH, "users", "passwd/group file modified",
				fmt.Sprintf("New lines added to %s since last backup — possible account manipulation", pair.cur))
		}
		if diffContainsRemovals(diff) {
			ctx.Registry.Add(output.MEDIUM, "users", "passwd/group file modified",
				fmt.Sprintf("Lines removed from %s since last backup", pair.cur))
		}
	}

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("passwd/group diff: %d finding(s)", delta))
	} else {
		output.Ok("passwd/group diff: clean")
	}
}

var safeSystemUserShells = map[string]bool{
	"/sbin/nologin":     true,
	"/usr/sbin/nologin": true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"/dev/null":         true,
	"":                  true,
}

var systemUserShellAllowlist = map[string]string{
	"sync":     "/bin/sync",
	"halt":     "/sbin/halt",
	"shutdown": "/sbin/shutdown",
	"operator": "/bin/bash",
}

func isSuspiciousSystemUserShell(e procfs.PasswdEntry) bool {
	if e.UID == 0 || e.UID >= 1000 {
		return false
	}
	if safeSystemUserShells[e.Shell] {
		return false
	}
	if allowed, ok := systemUserShellAllowlist[e.Username]; ok && allowed == e.Shell {
		return false
	}
	return true
}

func usersSuspiciousSystemUserShells(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "11_system_user_shells.txt",
		"System User Shell Anomalies", "/etc/passwd — system users (UID 1-999) with non-standard shells")
	defer w.Close()

	entries, err := procfs.ReadPasswd()
	if err != nil {
		w.Write("ERROR reading /etc/passwd: %v\n", err)
		return
	}

	hits := 0
	for _, e := range entries {
		if !isSuspiciousSystemUserShell(e) {
			continue
		}
		w.Write("  [HIGH] %-20s UID=%-5d shell=%s\n", e.Username, e.UID, e.Shell)
		ctx.Registry.Add(output.HIGH, "users", "Suspicious system user shell",
			fmt.Sprintf("System user '%s' (UID %d) has unusual shell: %s",
				e.Username, e.UID, e.Shell))
		hits++
	}

	if hits == 0 {
		w.Write("No suspicious system user shells detected.\n")
	}
	if hits > 0 {
		output.Warn(fmt.Sprintf("Suspicious system user shells: %d", hits))
	} else {
		output.Ok("System user shells: clean")
	}
}

func classifyShellsEntry(line string) (output.Severity, string, bool) {
	if osutil.IsCommentOrBlank(line) {
		return "", "", false
	}
	// Trailing whitespace is the PANIX trick
	if line != strings.TrimRight(line, " \t") {
		return output.HIGH, "Malformed /etc/shells entry", true
	}
	trimmed := strings.TrimSpace(line)
	if ioc.IsInMalwareDir(trimmed) {
		return output.HIGH, "Staging-path shell in /etc/shells", true
	}
	if _, err := os.Stat(trimmed); err != nil {
		return output.MEDIUM, "Non-existent shell in /etc/shells", true
	}
	return "", "", false
}

func usersEtcShellsIntegrity(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "12_etc_shells_integrity.txt",
		"/etc/shells Integrity Check", "/etc/shells — valid shell paths; trailing whitespace tampering")
	defer w.Close()
	h0, m0, l0, _ := ctx.Registry.Counts()

	data, err := readEvidenceFile(ctx, "/etc/shells")
	if err != nil {
		w.Write("/etc/shells not found or unreadable: %v\n", err)
		return
	}

	wasRecentlyModified := recentlyModified("/etc/shells", persistenceRecentHours)
	if wasRecentlyModified {
		ctx.Registry.Add(output.MEDIUM, "users", "Recently modified /etc/shells",
			fmt.Sprintf("/etc/shells modified within %.0fh — unexpected on a stable system", persistenceRecentHours))
	}

	flaggedCount := 0
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		sev, label, flagged := classifyShellsEntry(line)
		if !flagged {
			continue
		}
		w.Write("  [%s] %q\n", sev, line)
		ctx.Registry.Add(sev, "users", label,
			fmt.Sprintf("/etc/shells suspicious entry: %q", line))
		flaggedCount++
	}

	if flaggedCount == 0 && !wasRecentlyModified {
		w.Write("/etc/shells entries look clean.\n")
	}
	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("/etc/shells: %d finding(s)", delta))
	} else {
		output.Ok("/etc/shells: clean")
	}
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// hashFileSafe returns the SHA-256 hex digest of a file, or a placeholder on error.
func hashFileSafe(path string) string {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return "(unreadable)"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "(read error)"
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func usersSSHDConfigAnalysis(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Users, "10_sshd_config_analysis.txt",
		"SSH Daemon Config & Injection Analysis",
		"/etc/ssh/sshd_config, /etc/ssh/sshd_config.d/, /proc/<sshd-pid>/maps+environ, /etc/.../")
	defer w.Close()

	w.WriteSectionHeader("Triple-Dot Directory Check (/etc/...)")
	if fi, err := os.Stat("/etc/..."); err == nil && fi.IsDir() {
		w.Write("  [CRITICAL] Hidden triple-dot directory /etc/... detected\n\n")
		ctx.Registry.Add(output.HIGH, "users", "Triple-dot hidden persistence directory",
			"Hidden triple-dot directory /etc/... detected")
		_ = filepath.WalkDir("/etc/...", func(p string, d os.DirEntry, err error) error {
			if err != nil || p == "/etc/..." {
				return nil
			}
			w.Write("  [HIGH] Hidden file: %s\n", p)
			ctx.Registry.Add(output.HIGH, "users", "Triple-dot hidden persistence directory",
				"Hidden file inside triple-dot directory: "+p)
			return nil
		})
	} else {
		w.Write("  /etc/... does not exist — clean.\n")
	}

	w.WriteSectionHeader("sshd LD_PRELOAD Injection (/proc/<pid>/maps + environ)")
	procs := ctx.Processes()
	if len(procs) == 0 {
		w.Write("  ERROR listing processes: /proc snapshot unavailable\n")
	} else {
		sshdHits := 0
		for _, p := range procs {
			if p.Name != "sshd" && !strings.Contains(p.Exe, "sshd") {
				continue
			}
			// Check environ LD_PRELOAD
			if ldp, ok := p.Environ["LD_PRELOAD"]; ok && ioc.IsInMalwareDir(ldp) {
				sshdHits++
				w.Write("  [CRITICAL] sshd PID %d has LD_PRELOAD from staging dir: %s\n", p.PID, ldp)
				ctx.Registry.Add(output.HIGH, "users", "sshd LD_PRELOAD injection",
					fmt.Sprintf("sshd PID %d has LD_PRELOAD library from staging dir: %s", p.PID, ldp))
			}
			// Check memory maps for staging-dir paths
			if data, err := procfs.ReadMaps(p.PID); err == nil {
				for _, line := range strings.Split(data, "\n") {
					fields := strings.Fields(line)
					if len(fields) < 6 {
						continue
					}
					mapPath := fields[len(fields)-1]
					if ioc.IsInMalwareDir(mapPath) {
						sshdHits++
						w.Write("  [CRITICAL] sshd PID %d maps staging library: %s\n", p.PID, mapPath)
						ctx.Registry.Add(output.HIGH, "users", "sshd LD_PRELOAD injection",
							fmt.Sprintf("sshd PID %d has staging-dir library mapped: %s", p.PID, mapPath))
						break
					}
				}
			}
		}
		if sshdHits == 0 {
			w.Write("  No sshd LD_PRELOAD injection detected.\n")
		}
	}

	w.WriteSectionHeader("sshd_config Directive Analysis")

	configFiles := []string{"/etc/ssh/sshd_config"}
	if entries, err := os.ReadDir("/etc/ssh/sshd_config.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				configFiles = append(configFiles, filepath.Join("/etc/ssh/sshd_config.d", e.Name()))
			}
		}
	}

	// Follow Include directives up to depth 2 to catch drop-in config files.
	seen := make(map[string]bool)
	var expandIncludes func(files []string, depth int) []string
	expandIncludes = func(files []string, depth int) []string {
		if depth > 2 {
			return files
		}
		var expanded []string
		for _, f := range files {
			if seen[f] {
				continue
			}
			seen[f] = true
			expanded = append(expanded, f)
			data, err := readEvidenceFile(ctx, f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if !strings.HasPrefix(strings.ToLower(trimmed), "include ") {
					continue
				}
				incPath := strings.TrimSpace(trimmed[len("include "):])
				incPath = filepath.Clean(incPath)
				if !strings.HasPrefix(incPath, "/etc/ssh/") {
					w.Write("  [MEDIUM] sshd_config Include outside /etc/ssh/: %s\n", incPath)
					ctx.Registry.Add(output.MEDIUM, "users", "Suspicious sshd_config directive",
						"sshd_config Include outside /etc/ssh/: "+incPath)
					continue
				}
				matches, _ := filepath.Glob(incPath)
				expanded = expandIncludes(append(expanded, matches...), depth+1)
			}
		}
		return expanded
	}
	configFiles = expandIncludes(configFiles, 0)

	configHits := 0
	for _, cfgPath := range configFiles {
		data, err := readEvidenceFile(ctx, cfgPath)
		if err != nil {
			continue
		}
		fi, _ := os.Stat(cfgPath)
		if fi != nil && time.Since(fi.ModTime()) < 30*24*time.Hour {
			w.Write("  [LOW] %s recently modified (mtime: %s)\n", cfgPath, fi.ModTime().Format("2006-01-02"))
			ctx.Registry.Add(output.LOW, "users", "sshd_config recently modified",
				fmt.Sprintf("sshd_config recently modified: %s (mtime: %s)", cfgPath, fi.ModTime().Format("2006-01-02")))
		}

		lines := strings.Split(string(data), "\n")
		inMatch := false
		matchLineStart := 0
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			lower := strings.ToLower(trimmed)

			// Track Match blocks.
			// inMatch is never reset by design. sshd_config Match blocks have no end
			// keyword: they extend to the next Match or EOF, and there is no syntax to
			// return to global scope. Resetting on the next directive (review 2026-06-04
			// item 4) would WRONGLY drop ForceCommand-inside-Match detections, so that
			// item is rejected as a misreading of sshd semantics.
			if strings.HasPrefix(lower, "match ") {
				inMatch = true
				matchLineStart = i
			}

			if strings.HasPrefix(lower, "permitrootlogin yes") {
				configHits++
				w.Write("  [HIGH] %s:%d PermitRootLogin yes — dangerous sshd directive\n", cfgPath, i+1)
				ctx.Registry.Add(output.HIGH, "users", "Suspicious sshd_config directive",
					fmt.Sprintf("sshd_config PermitRootLogin yes in %s:%d — dangerous sshd directive", cfgPath, i+1))
			}

			if strings.HasPrefix(lower, "forcecommand ") {
				cmd := strings.TrimSpace(trimmed[len("forcecommand "):])
				if !ioc.IsInSafeDir(cmd) {
					configHits++
					w.Write("  [HIGH] %s:%d ForceCommand outside safe dirs: %s\n", cfgPath, i+1, cmd)
					ctx.Registry.Add(output.HIGH, "users", "Suspicious sshd_config directive",
						fmt.Sprintf("sshd ForceCommand outside safe dirs in %s:%d: %s — suspicious hook", cfgPath, i+1, cmd))
					if inMatch {
						w.Write("  [MEDIUM] %s:%d — ForceCommand inside Match block (Match at line %d)\n", cfgPath, i+1, matchLineStart+1)
						ctx.Registry.Add(output.MEDIUM, "users", "Suspicious sshd_config directive",
							fmt.Sprintf("ForceCommand inside Match block in %s:%d (Match at line %d)", cfgPath, i+1, matchLineStart+1))
					}
				}
			}

			if strings.HasPrefix(lower, "authorizedkeysfile ") {
				path := strings.TrimSpace(trimmed[len("authorizedkeysfile "):])
				if ioc.IsInMalwareDir(path) {
					configHits++
					w.Write("  [HIGH] %s:%d AuthorizedKeysFile in staging dir: %s\n", cfgPath, i+1, path)
					ctx.Registry.Add(output.HIGH, "users", "Suspicious sshd_config directive",
						fmt.Sprintf("sshd AuthorizedKeysFile in staging dir in %s:%d: %s — suspicious directive", cfgPath, i+1, path))
				}
			}
		}
	}

	if configHits == 0 {
		w.Write("  No suspicious sshd_config directives detected.\n")
		output.Ok("sshd_config: clean")
	} else {
		output.Warn(fmt.Sprintf("sshd_config suspicious directives: %d", configHits))
	}
}
