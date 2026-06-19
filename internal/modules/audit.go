package modules

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pathfinder/internal/logutil"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
	"github.com/pathfinder/internal/sysfs"
)

var gtfobinsSUIDAbused = map[string]bool{
	// shell interpreters
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"fish": true, "ash": true, "csh": true, "tcsh": true,
	// languages
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "node": true, "nodejs": true, "lua": true, "tclsh": true,
	// file manipulation
	"find": true, "vim": true, "vi": true, "nano": true, "emacs": true,
	"ed": true, "less": true, "more": true, "man": true,
	"awk": true, "gawk": true, "nawk": true, "mawk": true,
	"cp": true, "mv": true, "dd": true, "tee": true, "tar": true, "zip": true,
	"base64": true, "xxd": true, "cut": true, "head": true, "tail": true, "sort": true,
	// network / download
	"curl": true, "wget": true, "nc": true, "ncat": true, "openssl": true, "socat": true,
	// system control
	"env": true, "make": true, "git": true, "systemctl": true, "journalctl": true,
	"xargs": true, "strace": true, "gdb": true, "nohup": true,
}

var expectedSUIDBinaries = map[string]bool{
	"passwd": true, "sudo": true, "su": true, "chsh": true, "chfn": true,
	"newgrp": true, "gpasswd": true, "ping": true, "ping6": true,
	"mount": true, "umount": true, "fusermount": true, "fusermount3": true,
	"at": true, "crontab": true, "write": true, "wall": true, "chage": true,
	"ssh-keysign": true, "newuidmap": true, "newgidmap": true,
	"traceroute": true, "traceroute6": true, "arping": true, "pkexec": true, "Xorg": true,
}

var dangerousFileCaps = map[string]output.Severity{
	"cap_setuid":       output.HIGH,
	"cap_setgid":       output.HIGH,
	"cap_sys_ptrace":   output.HIGH,
	"cap_sys_admin":    output.HIGH,
	"cap_dac_override": output.MEDIUM,
	"cap_net_raw":      output.MEDIUM,
}

var capAllowlist = map[string]map[string]bool{
	"/usr/bin/ping":      {"cap_net_raw": true},
	"/usr/bin/newuidmap": {"cap_setuid": true},
	"/usr/bin/newgidmap": {"cap_setgid": true},
	"/usr/sbin/tcpdump":  {"cap_net_raw": true},
	"/usr/bin/tcpdump":   {"cap_net_raw": true},
	"/usr/bin/dumpcap":   {"cap_net_raw": true},
}

var capInterpreters = map[string]bool{
	"perl": true, "python": true, "python2": true, "python3": true, "ruby": true,
}

// extractNOPASSWDPaths parses sudoers content and returns absolute binary paths
// from NOPASSWD rules.
func extractNOPASSWDPaths(content string) []string {
	var paths []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		idx := strings.Index(line, "NOPASSWD:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+9:])
		for _, part := range strings.Split(rest, ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 && filepath.IsAbs(fields[0]) {
				paths = append(paths, fields[0])
			}
		}
	}
	return paths
}

// hasActiveNOPASSWD reports whether content contains a non-commented NOPASSWD rule.
func hasActiveNOPASSWD(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "NOPASSWD:") {
			return true
		}
	}
	return false
}

// parseGetcapLine parses a line from getcap output into path and capability names.
// Format: "<path> <cap>=<flags> [<cap>=<flags>...]"
func parseGetcapLine(line string) (path string, caps []string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, false
	}
	var names []string
	for _, f := range fields[1:] {
		name := f
		if i := strings.IndexAny(f, "=+"); i >= 0 {
			name = f[:i]
		}
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil, false
	}
	return fields[0], names, true
}

// RunAudit executes the audit (security config & logs) sections
func RunAudit(ctx *ModuleContext) {
	output.Chapter("[AUDIT] Inspecting security config and authentication logs...")
	output.Info("Output → " + ctx.Dirs.Audit)
	auditPAM(ctx)
	auditSudoers(ctx)
	auditSUIDSGID(ctx)
	auditImmutableFiles(ctx)
	auditAuthLogs(ctx)
	auditShadowHashes(ctx)
	auditBinaryHijacking(ctx)
	auditProcessCapabilities(ctx)
	auditFileIntegrity(ctx)

	ctx.Log.Log("audit", "complete", "all sections done")
}

func auditPAM(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "01_pam_config.txt",
		"PAM Configuration", "/etc/pam.d/")
	defer w.Close()

	entries, err := os.ReadDir("/etc/pam.d")
	if err != nil {
		w.Write("Cannot read /etc/pam.d: %v\n", err)
		return
	}

	hits := 0

	for _, e := range entries {
		p := filepath.Join("/etc/pam.d", e.Name())
		data, err := osutil.ReadFileNoAtime(p)
		if err != nil {
			continue
		}
		content := string(data)
		w.Write("─── %s ───\n%s\n", e.Name(), content)
		fileHit := false
		for _, raw := range strings.Split(content, "\n") {
			line := strings.TrimSpace(raw)
			if osutil.IsCommentOrBlank(line) {
				continue
			}
			if susp, ok := pamLineSuspicious(line); ok {
				if !fileHit {
					hits++
					fileHit = true
				}
				ctx.Registry.Add(output.HIGH, "audit", "Suspicious PAM entry",
					fmt.Sprintf("Suspicious PAM entry in %s — contains '%s'", p, susp))
			}
		}
	}

	if hits == 0 {
		output.Ok("PAM configuration appears clean")
	} else {
		output.Warn(fmt.Sprintf("PAM suspicious entries: %d hit(s)", hits))
	}
}

// pamLineSuspicious reports the first suspicious token in a non-comment PAM config line.
// Matches the pam_exec / pam_prelude module and /tmp,/dev/shm path tokens by field boundary,
// so pam_tmpdir and substrings inside comments do not trigger.
func pamLineSuspicious(line string) (string, bool) {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	for _, f := range fields {
		switch {
		case f == "pam_exec.so" || f == "pam_exec":
			return "pam_exec", true
		case f == "pam_prelude.so" || f == "pam_prelude":
			return "pam_prelude", true
		case f == "/tmp" || strings.HasPrefix(f, "/tmp/"):
			return "/tmp", true
		case f == "/dev/shm" || strings.HasPrefix(f, "/dev/shm/"):
			return "/dev/shm", true
		}
	}
	return "", false
}

func auditSudoers(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "02_sudoers.txt",
		"Sudoers Configuration", "/etc/sudoers, /etc/sudoers.d/")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("sudoers requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	hits := 0

	shadowDirs := []string{"/usr/local/bin", "/tmp", "/var/tmp", "/dev/shm"}
	if passwdEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range passwdEntries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				shadowDirs = append(shadowDirs, filepath.Join(pe.HomeDir, "bin"))
			}
		}
	}

	checkSudoHijack := func(content, source string) {
		for _, binPath := range extractNOPASSWDPaths(content) {
			for _, vdir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
				if strings.HasPrefix(binPath, vdir) {
					hits++
					ctx.Registry.Add(output.HIGH, "audit", "NOPASSWD binary in volatile path",
						fmt.Sprintf("Sudoers %s: NOPASSWD binary is in volatile path: %s", source, binPath))
				}
			}
			binName := filepath.Base(binPath)
			for _, sd := range shadowDirs {
				shadow := filepath.Join(sd, binName)
				info, err := os.Stat(shadow)
				if err != nil || info.IsDir() {
					continue
				}
				if resolved, err := filepath.EvalSymlinks(shadow); err == nil && resolved == binPath {
					continue
				}
				hits++
				ctx.Registry.Add(output.HIGH, "audit", "Sudo binary hijacking",
					fmt.Sprintf("NOPASSWD binary %s shadowed by %s", binPath, shadow))
			}
		}
	}

	if data, err := osutil.ReadFileNoAtime("/etc/sudoers"); err == nil {
		content := string(data)
		w.WriteSectionHeader("/etc/sudoers")
		w.WriteString(content)
		if hasActiveNOPASSWD(content) {
			hits++
			ctx.Registry.Add(output.HIGH, "audit", "NOPASSWD sudo entry",
				"NOPASSWD entry in /etc/sudoers — privilege escalation path exists")
		}
		checkSudoHijack(content, "/etc/sudoers")
	}

	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			p := filepath.Join("/etc/sudoers.d", e.Name())
			if data, err := osutil.ReadFileNoAtime(p); err == nil {
				content := string(data)
				w.WriteSectionHeader(p)
				w.WriteString(content)
				if hasActiveNOPASSWD(content) {
					hits++
					ctx.Registry.Add(output.HIGH, "audit", "NOPASSWD sudo entry",
						fmt.Sprintf("NOPASSWD entry in %s", p))
				}
				checkSudoHijack(content, p)
			}
		}
	}

	if hits > 0 {
		output.Warn(fmt.Sprintf("Suspicious sudoers entries: %d hit(s)", hits))
	} else {
		output.Ok("Sudoers: clean")
	}
}

func auditSUIDSGID(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "03_suid_sgid.txt",
		"SUID/SGID Binaries — with SHA-256", "filepath.WalkDir /")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("SUID/SGID scan requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	output.Info("Scanning for SUID/SGID binaries…")
	w.Write("%-10s %-8s %-64s %s\n", "MODE", "SIZE", "SHA-256", "PATH")
	w.Write("%s\n", strings.Repeat("─", 100))

	count := 0
	wwSUID := 0
	hits := 0

	walkFiles(ctx, "/", func(path string, info os.FileInfo) {
		mode := info.Mode()
		hasSUID := mode&os.ModeSetuid != 0
		hasSGID := mode&os.ModeSetgid != 0
		worldWritable := mode&0002 != 0

		if !hasSUID && !hasSGID {
			return
		}
		count++

		hash := suidHash(path)
		w.Write("%-10s %-8s %-64s %s\n", mode.String(), osutil.FormatFileSize(info.Size()), hash, path)

		if hasSUID && worldWritable {
			wwSUID++
			hits++
			ctx.Registry.Add(output.HIGH, "audit", "World-writable SUID binary",
				fmt.Sprintf("World-writable SUID binary: %s [sha256:%s]", path, hash))
		}
		name := filepath.Base(path)
		if hasSUID && gtfobinsSUIDAbused[name] && !expectedSUIDBinaries[name] {
			hits++
			ctx.Registry.Add(output.HIGH, "audit", "Suspicious SUID binary",
				fmt.Sprintf("SUID set on GTFOBins-listed binary: %s [sha256:%s]", path, hash))
		}
	})

	if hits > 0 {
		output.Warn(fmt.Sprintf("Suspicious SUID/SGID binaries: %d hit(s) (world-writable: %d)", hits, wwSUID))
	} else {
		output.Ok(fmt.Sprintf("SUID/SGID binaries found: %d (world-writable: %d)", count, wwSUID))
	}
}

func suidHash(path string) string {
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

func auditImmutableFiles(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "04_immutable_files.txt",
		"Immutable Files (FS_IOC_GETFLAGS)", "/etc, /bin, /usr/bin, /sbin, /usr/sbin")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("immutable file scan requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	output.Info("Scanning for immutable files…")
	roots := []string{"/etc", "/bin", "/usr/bin", "/sbin", "/usr/sbin"}
	results := sysfs.ScanImmutable(roots)

	if len(results) == 0 {
		w.Write("No immutable files detected in system paths.\n")
		output.Ok("No immutable system files found")
	} else {
		for _, r := range results {
			w.Write("  [IMMUTABLE] %s\n", r.Path)
		}
		ctx.Registry.Add(output.MEDIUM, "audit", "Immutable files detected",
			fmt.Sprintf("%d immutable file(s) set — attacker may be preventing modification", len(results)))
		output.Warn(fmt.Sprintf("Immutable files detected: %d", len(results)))
	}
}

func isAuthFailureLine(line string) bool {
	return strings.Contains(line, "Failed password") ||
		strings.Contains(line, "Failed publickey") ||
		strings.Contains(line, "Invalid user") ||
		strings.Contains(line, "authentication failure") ||
		strings.Contains(line, "Too many authentication failures") ||
		strings.Contains(line, "maximum authentication attempts exceeded") ||
		strings.Contains(line, "Connection closed by invalid user")
}

func auditAuthLogs(ctx *ModuleContext) {
	wf := newSectionWriter(ctx, ctx.Dirs.Audit, "05_auth_log_failures.txt",
		"Auth Log — Failed Logins", "/var/log/auth.log (+rotations), /var/log/secure (+rotations)")
	defer wf.Close()

	ws := newSectionWriter(ctx, ctx.Dirs.Audit, "06_auth_log_successes.txt",
		"Auth Log — Successful Logins", "/var/log/auth.log (+rotations), /var/log/secure (+rotations)")
	defer ws.Close()

	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	failCount := 0
	successCount := 0

	for _, lf := range logFiles {
		combined, statuses := logutil.ReadWithRotations(lf)
		for _, s := range statuses {
			if s.State == "error" {
				ctx.Log.Log("audit", "log_read_error", fmt.Sprintf("%s: %s", s.Path, s.Err))
			}
		}
		if combined == "" {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(combined))
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20) // 8 MiB: long auth.log lines must not silently truncate
		for sc.Scan() {
			line := sc.Text()
			if isAuthFailureLine(line) {
				wf.Write("%s\n", line)
				failCount++
			} else if strings.Contains(line, "Accepted") {
				ws.Write("%s\n", line)
				successCount++
			}
		}
	}

	if failCount > sshBruteForceHighThreshold {
		ctx.Registry.Add(output.HIGH, "audit", "Auth log brute-force",
			fmt.Sprintf("%d failed auth events — possible brute-force attack", failCount))
		output.Warn(fmt.Sprintf("Suspicious auth log: %d failures, %d successes", failCount, successCount))
	} else if failCount > sshBruteForceMediumThreshold {
		ctx.Registry.Add(output.MEDIUM, "audit", "Auth log brute-force",
			fmt.Sprintf("%d failed auth events — elevated authentication failures", failCount))
		output.Warn(fmt.Sprintf("Suspicious auth log: %d failures, %d successes", failCount, successCount))
	} else {
		output.Ok(fmt.Sprintf("Auth log: %d failures, %d successes", failCount, successCount))
	}
}

func auditShadowHashes(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "07_shadow_hashes.txt",
		"Users with Password Hashes", "/etc/shadow")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("shadow hash extraction requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	entries, err := procfs.ReadShadow()
	if err != nil {
		w.Write("ERROR reading /etc/shadow: %v\n", err)
		ctx.Registry.Add(output.LOW, "audit", "Shadow file access attempt", "Could not read /etc/shadow")
		return
	}

	w.Write("%-25s %-8s %s\n", "USERNAME", "HAS_HASH", "HASH_PREFIX")
	w.Write("%s\n", strings.Repeat("─", 70))

	hashCount := 0
	for _, e := range entries {
		status := "no"
		prefix := e.PasswordHash
		if e.HasHash {
			status = "yes"
			hashCount++
			if len(e.PasswordHash) > 20 {
				prefix = e.PasswordHash[:20] + "…"
			}
		}
		w.Write("%-25s %-8s %s\n", e.Username, status, prefix)
	}

	w.Write("\n%d account(s) with active password hashes.\n", hashCount)
	output.Ok(fmt.Sprintf("Shadow entries: %d with hashes", hashCount))
}

func auditBinaryHijacking(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "08_binary_hijacking.txt",
		"Binary Hijacking — PATH-shadowing",
		"/usr/local/bin, /usr/local/sbin, ~/bin, ~/.local/bin vs /usr/bin, /bin, /usr/sbin, /sbin")
	defer w.Close()

	if !ctx.Cfg.IsRoot {
		output.Skip("binary hijacking scan requires root")
		w.Write("SKIPPED — requires root.\n")
		return
	}

	systemBins := make(map[string]string)
	for _, d := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				systemBins[e.Name()] = filepath.Join(d, e.Name())
			}
		}
	}

	overrideDirs := []string{"/usr/local/bin", "/usr/local/sbin"}
	homeOverrideDirs := map[string]bool{}
	if passwdEntries, err := procfs.ReadPasswd(); err == nil {
		for _, pe := range passwdEntries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				binDir := filepath.Join(pe.HomeDir, "bin")
				localBinDir := filepath.Join(pe.HomeDir, ".local", "bin")
				overrideDirs = append(overrideDirs, binDir, localBinDir)
				homeOverrideDirs[binDir] = true
				homeOverrideDirs[localBinDir] = true
			}
		}
	}

	hits := 0
	for _, od := range overrideDirs {
		entries, err := os.ReadDir(od)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			canonicalPath, shadows := systemBins[e.Name()]
			if !shadows {
				continue
			}
			p := filepath.Join(od, e.Name())
			if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved == canonicalPath {
				continue
			}
			w.Write("  SHADOW: %s → (system: %s)\n", p, canonicalPath)
			hits++

			if homeOverrideDirs[od] || recentlyModified(p, persistenceRecentHours) {
				ctx.Registry.Add(output.HIGH, "audit", "Binary PATH hijacking",
					fmt.Sprintf("System binary '%s' shadowed in early-PATH: %s", e.Name(), p))
			} else {
				ctx.Registry.Add(output.MEDIUM, "audit", "Binary PATH hijacking",
					fmt.Sprintf("System binary '%s' shadowed in override dir: %s", e.Name(), p))
			}
		}
	}

	if hits == 0 {
		w.Write("No PATH-shadowing detected.\n")
		output.Ok("Binary PATH hijacking: clean")
	} else {
		output.Warn(fmt.Sprintf("Binary PATH hijacking: %d shadow(s) detected", hits))
	}
}

func auditProcessCapabilities(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "09_process_capabilities.txt",
		"Process Capabilities (getcap)", "getcap -r /usr /bin /sbin /usr/local /opt /home")
	defer w.Close()

	out, _ := execFallback(ctx, "getcap", "-r", "/usr", "/bin", "/sbin", "/usr/local", "/opt", "/home")
	if strings.TrimSpace(out) == "" {
		w.Write("getcap not available or no capabilities set.\n")
		output.Note("Process capabilities: getcap not available")
		return
	}

	w.WriteString(out)
	hits := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		binPath, capNames, ok := parseGetcapLine(line)
		if !ok {
			continue
		}
		baseName := filepath.Base(binPath)

		for _, capName := range capNames {
			sev, dangerous := dangerousFileCaps[capName]
			if !dangerous {
				continue
			}
			if allowed, listed := capAllowlist[binPath]; listed && allowed[capName] {
				continue
			}
			if capInterpreters[baseName] && (capName == "cap_setuid" || capName == "cap_setgid") {
				sev = output.HIGH
			}
			ctx.Registry.Add(sev, "audit", "Dangerous process capability",
				fmt.Sprintf("%s has dangerous capability %s", binPath, capName))
			hits++
		}
	}

	if hits == 0 {
		output.Ok("Process capabilities: no dangerous capabilities detected")
	} else {
		output.Warn(fmt.Sprintf("Dangerous process capabilities: %d binary(ies)", hits))
	}
}

func auditFileIntegrity(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Audit, "10_file_integrity.txt",
		"File Integrity Check", "debsums -s / rpm -Va (exec fallback)")
	defer w.Close()

	if out, err := execFallback(ctx, "debsums", "-s"); err == nil {
		w.WriteSectionHeader("debsums -s output (failures only)")
		if strings.TrimSpace(out) == "" {
			w.Write("No integrity failures reported by debsums.\n")
			output.Ok("debsums: no failures")
		} else {
			w.WriteString(out)
			var lines []string
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				if !strings.HasPrefix(l, "[exit") {
					lines = append(lines, l)
				}
			}
			ctx.Registry.Add(output.HIGH, "audit", "Package integrity failure",
				fmt.Sprintf("debsums reports %d package file integrity failure(s)", len(lines)))
			output.Warn(fmt.Sprintf("debsums failures: %d", len(lines)))
		}
		return
	}

	if out, err := execFallback(ctx, "rpm", "-Va"); err == nil {
		w.WriteSectionHeader("rpm -Va — MD5 mismatches (lines matching ^..5.)")
		hits := 0
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			line := sc.Text()
			if len(line) >= 4 && line[2] == '5' {
				w.Write("%s\n", line)
				hits++
			}
		}
		if hits == 0 {
			w.Write("No MD5 mismatches reported.\n")
			output.Ok("rpm -Va: no MD5 mismatches")
		} else {
			ctx.Registry.Add(output.HIGH, "audit", "Package integrity failure",
				fmt.Sprintf("rpm -Va reports %d binary MD5 mismatch(es) — possible trojan", hits))
			output.Warn(fmt.Sprintf("rpm -Va MD5 mismatches: %d", hits))
		}
		return
	}

	w.Write("Neither debsums nor rpm available — skipping file integrity check.\n")
	ctx.Registry.Add(output.LOW, "audit", "File integrity check skipped",
		"File integrity tools (debsums/rpm) not available — check skipped")
	output.Note("File integrity check skipped — no tool available")
}
