package modules

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

// RunIOC checks all custom IOC indicators loaded from the operator's IOC file
// against DFIR-relevant log sources, live processes, and file hashes.
// It is a no-op when no IOC file was provided.
func RunIOC(ctx *ModuleContext) {
	if ctx.IOC == nil {
		return
	}
	sh := ctx.IOC

	// Copy the IOC file into the output dir so it is included in the archive.
	if ctx.Cfg.IOCFile != "" {
		dst := filepath.Join(ctx.Dirs.IOC, "00_ioc_file"+filepath.Ext(ctx.Cfg.IOCFile))
		if err := copyFileNoAtime(ctx.Cfg.IOCFile, dst); err != nil {
			ctx.Log.Log("ioc", "warn", fmt.Sprintf("could not archive IOC file: %v", err))
		}
	}

	output.Chapter("[IOC] Custom IOC scan...")
	output.Info("Output → " + ctx.Dirs.IOC)

	w := newSectionWriter(ctx, ctx.Dirs.IOC, "01_ioc_hits.txt",
		"IOC — Custom IOC Matches", ctx.Cfg.IOCFile)
	defer w.Close()

	procs := ctx.Processes()

	total := 0

	if len(sh.Commands) > 0 {
		w.WriteSectionHeader("Commands")
		total += iocScanPaths(ctx, w, sh.Commands, "command", output.MEDIUM, commandSources(ctx))
		total += iocScanLiveCmdlines(ctx, w, sh, procs)
	}

	if len(sh.IPs) > 0 {
		w.WriteSectionHeader("IPs")
		total += iocScanIPPaths(ctx, w, sh, ipSources(ctx))
		total += iocScanLiveNetIPs(ctx, w, sh)
	}

	if len(sh.Processes) > 0 {
		w.WriteSectionHeader("Processes")
		total += iocScanPaths(ctx, w, sh.Processes, "process", output.HIGH, procFileSources(ctx))
		total += iocScanLiveProcesses(ctx, w, sh, procs)
	}

	if len(sh.Filenames) > 0 {
		w.WriteSectionHeader("Filenames")
		total += iocScanPaths(ctx, w, sh.Filenames, "filename", output.MEDIUM, procFileSources(ctx))
		total += iocWalkStagingForFilenames(ctx, w, sh)
	}

	if len(sh.Domains) > 0 {
		w.WriteSectionHeader("Domains")
		total += iocScanPaths(ctx, w, sh.Domains, "domain", output.HIGH, domainSources(ctx))
	}

	if len(sh.IPs) > 0 || len(sh.Domains) > 0 {
		w.WriteSectionHeader("Staging Dirs (IPs + Domains)")
		total += iocWalkStagingForNetworkIndicators(ctx, w, sh)
	}

	if len(sh.Hashes) > 0 {
		w.WriteSectionHeader("Hashes")
		if ctx.Cfg.Mode != "full" {
			w.Write("  Hash computation skipped in quick mode (use -mode full).\n")
		} else {
			total += iocCheckHashes(ctx, w, sh, procs)
		}
	}

	ctx.Log.Log("ioc", "complete", fmt.Sprintf("%d custom IOC hits", total))
	if total == 0 {
		output.Ok("IOC: no custom IOC matches")
	} else {
		output.Warn(fmt.Sprintf("IOC: %d custom IOC hit(s)", total))
	}
}

func commandSources(ctx *ModuleContext) []string {
	paths := []string{
		"/var/log/audit/audit.log",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/var/log/dpkg.log",
		"/var/log/yum.log",
		"/var/log/dnf.log",
		"/etc/rc.local",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/ld.so.preload",
		"/etc/ssh/sshd_config",
		"/etc/crontab",
	}
	paths = append(paths, globPaths("/etc/cron.d/*")...)
	paths = append(paths, globPaths("/var/spool/cron/crontabs/*")...)
	paths = append(paths, globPaths("/etc/systemd/system/*.service")...)
	paths = append(paths, userHistoryFiles()...)
	paths = append(paths, userDotFiles()...)
	return paths
}

func ipSources(_ *ModuleContext) []string {
	paths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/audit/audit.log",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/var/log/mail.log",
		"/var/log/ufw.log",
		"/var/log/firewalld",
		"/var/log/exim4/mainlog",
		"/etc/hosts.allow",
		"/etc/hosts.deny",
		"/proc/net/arp",
		"/etc/crontab",
		"/etc/rc.local",
		"/etc/profile",
		"/etc/bashrc",
		"/etc/bash.bashrc",
	}
	paths = append(paths, userSSHFiles()...)
	paths = append(paths, globPaths("/etc/cron.d/*")...)
	paths = append(paths, globPaths("/var/spool/cron/crontabs/*")...)
	paths = append(paths, globPaths("/etc/systemd/system/*.service")...)
	paths = append(paths, globPaths("/etc/init.d/*")...)
	paths = append(paths, globPaths("/etc/profile.d/*.sh")...)
	paths = append(paths, userDotFiles()...)
	return paths
}

func procFileSources(_ *ModuleContext) []string {
	paths := []string{
		"/var/log/audit/audit.log",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/dpkg.log",
		"/var/log/yum.log",
		"/var/log/dnf.log",
		"/etc/crontab",
		"/etc/ld.so.preload",
	}
	paths = append(paths, globPaths("/etc/cron.d/*")...)
	paths = append(paths, globPaths("/var/spool/cron/crontabs/*")...)
	paths = append(paths, globPaths("/etc/systemd/system/*.service")...)
	paths = append(paths, userHistoryFiles()...)
	return paths
}

func domainSources(_ *ModuleContext) []string {
	paths := []string{
		"/etc/hosts",
		"/etc/resolv.conf",
		"/var/log/auth.log",
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/audit/audit.log",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/var/log/squid/access.log",
		"/var/lib/unbound/unbound.log",
		"/var/log/named/named.log",
		"/etc/crontab",
		"/etc/rc.local",
		"/etc/profile",
		"/etc/bashrc",
		"/etc/bash.bashrc",
	}
	paths = append(paths, userSSHKnownHosts()...)
	paths = append(paths, globPaths("/etc/cron.d/*")...)
	paths = append(paths, globPaths("/var/spool/cron/crontabs/*")...)
	paths = append(paths, globPaths("/etc/systemd/system/*.service")...)
	paths = append(paths, globPaths("/etc/init.d/*")...)
	paths = append(paths, globPaths("/etc/profile.d/*.sh")...)
	paths = append(paths, userDotFiles()...)
	return paths
}

// iocScanPaths scans each file path against matchers and registers hits.
func iocScanPaths(ctx *ModuleContext, w *output.Writer, matchers []ioc.Matcher,
	iocType string, sev output.Severity, paths []string) int {

	count := 0
	for _, path := range paths {
		hits := ioc.IOCScanFile(path, matchers)
		for _, h := range hits {
			w.Write("  [%s] %s  line %d: %s\n", h.Indicator, path, h.LineNum, h.Line)
			ctx.Registry.Add(sev, "ioc", "Custom IOC match",
				fmt.Sprintf("Custom IOC (%s) in %s line %d: %s", iocType, path, h.LineNum, h.Indicator))
			count++
		}
	}
	return count
}

// iocScanIPPaths scans each file for IPv4 addresses and checks against IP matchers.
func iocScanIPPaths(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, paths []string) int {
	count := 0
	for _, path := range paths {
		hits := ioc.IOCScanFileForIPs(path, sh)
		for _, h := range hits {
			w.Write("  [%s] %s  line %d: %s\n", h.Indicator, path, h.LineNum, h.Line)
			ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC IP match",
				fmt.Sprintf("Custom IOC (ip) in %s line %d: %s", path, h.LineNum, h.Indicator))
			count++
		}
	}
	return count
}

// iocScanLiveCmdlines checks all running process cmdlines against command matchers.
func iocScanLiveCmdlines(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, procs []*procfs.Process) int {
	count := 0
	for _, p := range procs {
		if p.Cmdline == "" {
			continue
		}
		if ind, ok := sh.MatchCommand(p.Cmdline); ok {
			w.Write("  [%s] PID %d cmdline: %s\n", ind, p.PID, p.Cmdline)
			ctx.Registry.Add(output.MEDIUM, "ioc", "Custom IOC command match",
				fmt.Sprintf("Custom IOC (command) PID %d: %s", p.PID, ind))
			count++
		}
	}
	return count
}

// iocScanLiveNetIPs checks /proc/net/{tcp,udp}{,6} for custom IP matches.
// Addresses there are little-endian hex, so they are decoded via
// ioc.ScanProcNetForIPs rather than the dotted-decimal text scanner.
func iocScanLiveNetIPs(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet) int {
	count := 0
	for _, src := range []string{"/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"} {
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		for _, h := range ioc.ScanProcNetForIPs(string(data), sh) {
			w.Write("  [%s] %s  line %d: %s\n", h.Indicator, src, h.LineNum, h.Line)
			ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC IP match",
				fmt.Sprintf("Custom IOC (ip) active connection in %s: %s", src, h.Indicator))
			count++
		}
	}
	return count
}

// iocScanLiveProcesses checks running processes against process name matchers.
func iocScanLiveProcesses(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, procs []*procfs.Process) int {
	count := 0
	for _, p := range procs {
		for _, candidate := range []string{p.Name, filepath.Base(p.Exe)} {
			if candidate == "" {
				continue
			}
			if ind, ok := sh.MatchProcess(candidate); ok {
				w.Write("  [%s] PID %d name=%s exe=%s\n", ind, p.PID, p.Name, p.Exe)
				ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC process match",
					fmt.Sprintf("Custom IOC (process) PID %d (%s): %s", p.PID, p.Name, ind))
				count++
				break
			}
		}
	}
	return count
}

// iocWalkStagingForFilenames checks files in staging dirs against filename matchers.
func iocWalkStagingForFilenames(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet) int {
	stagingDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	count := 0
	for _, d := range stagingDirs {
		filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			name := de.Name()
			if ind, ok := sh.MatchFilename(name); ok {
				w.Write("  [%s] %s\n", ind, path)
				ctx.Registry.Add(output.MEDIUM, "ioc", "Custom IOC filename match",
					fmt.Sprintf("Custom IOC (filename) in staging dir: %s matched %s", path, ind))
				count++
			} else if ind, ok := sh.MatchFilename(path); ok {
				w.Write("  [%s] %s\n", ind, path)
				ctx.Registry.Add(output.MEDIUM, "ioc", "Custom IOC filename match",
					fmt.Sprintf("Custom IOC (filename) in staging dir: %s matched %s", path, ind))
				count++
			}
			return nil
		})
	}
	return count
}

// iocWalkStagingForNetworkIndicators scans staging dir text files for custom IP
// and domain IOC matches. A single walk covers both to avoid reading each file twice.
// Files larger than 1 MB are skipped.
func iocWalkStagingForNetworkIndicators(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet) int {
	const maxBytes = 1024 * 1024
	count := 0
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(d, e.Name())
			if ctx.SelfPath != "" && path == ctx.SelfPath {
				continue
			}
			fi, err := os.Lstat(path)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if fi.Size() == 0 || fi.Size() > maxBytes {
				continue
			}
			data, err := osutil.ReadFileNoAtime(path)
			if err != nil {
				continue
			}
			text := string(data)

			if len(sh.IPs) > 0 {
				for _, h := range ioc.IOCScanTextForIPs(text, sh) {
					w.Write("  [%s] %s  line %d: %s\n", h.Indicator, path, h.LineNum, h.Line)
					ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC IP match",
						fmt.Sprintf("Custom IOC (ip) in staging %s line %d: %s", path, h.LineNum, h.Indicator))
					count++
				}
			}
			if len(sh.Domains) > 0 {
				for _, h := range ioc.IOCScanText(text, sh.Domains) {
					w.Write("  [%s] %s  line %d: %s\n", h.Indicator, path, h.LineNum, h.Line)
					ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC domain match",
						fmt.Sprintf("Custom IOC (domain) in staging %s line %d: %s", path, h.LineNum, h.Indicator))
					count++
				}
			}
		}
	}
	return count
}

// iocCheckHashes hashes running process executables (outside safe dirs) and all
// staging dir files under IOCMaxHashMB, comparing each against the IOC hash set.
func iocCheckHashes(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, procs []*procfs.Process) int {
	maxBytes := int64(ctx.Cfg.IOCMaxHashMB) * 1024 * 1024
	wMD5, wSHA1, wSHA256 := sh.HashLengths()
	count := 0

	// matchAnyDigest returns the first non-empty digest that hits the IOC set.
	matchAnyDigest := func(md5h, sha1h, sha256h string) (string, string, bool) {
		for _, d := range []struct{ algo, hex string }{
			{"sha256", sha256h}, {"sha1", sha1h}, {"md5", md5h},
		} {
			if d.hex != "" && sh.MatchHash(d.hex) {
				return d.algo, d.hex, true
			}
		}
		return "", "", false
	}

	// Running process executables (non-system paths)
	{
		seen := make(map[string]bool)
		for _, p := range procs {
			if p.Exe == "" || seen[p.Exe] || ioc.IsInSafeDir(p.Exe) {
				continue
			}
			seen[p.Exe] = true
			md5h, sha1h, sha256h, herr := hashFileDigests(p.Exe, maxBytes, wMD5, wSHA1, wSHA256)
			if herr == nil {
				if algo, hx, ok := matchAnyDigest(md5h, sha1h, sha256h); ok {
					w.Write("  [HASH MATCH] PID %d exe=%s %s=%s\n", p.PID, p.Exe, algo, hx)
					ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC hash match",
						fmt.Sprintf("Custom IOC (hash) PID %d exe %s: %s=%s", p.PID, p.Exe, algo, hx))
					count++
				}
			} else if herr == errFileTooLarge {
				w.Write("  [SKIP] %s exceeds %dMB hash limit\n", p.Exe, ctx.Cfg.IOCMaxHashMB)
				ctx.Registry.Add(output.MEDIUM, "ioc", "Custom IOC hash match",
					fmt.Sprintf("Custom IOC (hash) skipped — file too large (>%dMB): %s", ctx.Cfg.IOCMaxHashMB, p.Exe))
			}
		}
	}

	// Staging dir files
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if walkErr := filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
			// Skip non-regular entries. de.Type() is from lstat, so a symlink is
			// not followed: hashing it would os.Stat/OpenNoAtime the TARGET, which
			// blocks forever on a FIFO planted in /tmp and reads /etc/shadow if the
			// link points there. Only hash real files. Dirs return nil and WalkDir
			// keeps descending.
			if err != nil || !de.Type().IsRegular() {
				return nil
			}
			md5h, sha1h, sha256h, herr := hashFileDigests(path, maxBytes, wMD5, wSHA1, wSHA256)
			if herr == errFileTooLarge {
				w.Write("  [SKIP] %s exceeds %dMB hash limit\n", path, ctx.Cfg.IOCMaxHashMB)
				return nil
			}
			if herr != nil {
				return nil
			}
			if algo, hx, ok := matchAnyDigest(md5h, sha1h, sha256h); ok {
				w.Write("  [HASH MATCH] %s  %s=%s\n", path, algo, hx)
				ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC hash match",
					fmt.Sprintf("Custom IOC (hash) staging file %s: %s=%s", path, algo, hx))
				count++
			}
			return nil
		}); walkErr != nil {
			ctx.Log.Log("ioc", "warn", fmt.Sprintf("hash walk error in %s: %v", d, walkErr))
		}
	}

	// dpkg md5sum files: compare stored checksums without re-hashing
	iocCheckDpkgHashes(ctx, w, sh, &count)

	return count
}

// hashFileDigests computes the requested digests of a file in a single pass.
// Unrequested digests are returned as "". Returns errFileTooLarge when the file
// exceeds maxBytes. Uses O_NOATIME to preserve forensic timestamps.
func hashFileDigests(path string, maxBytes int64, wantMD5, wantSHA1, wantSHA256 bool) (md5hex, sha1hex, sha256hex string, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", "", err
	}
	if maxBytes > 0 && fi.Size() > maxBytes {
		return "", "", "", errFileTooLarge
	}
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()

	var writers []io.Writer
	var hMD5, hSHA1, hSHA256 hash.Hash
	if wantMD5 {
		hMD5 = md5.New()
		writers = append(writers, hMD5)
	}
	if wantSHA1 {
		hSHA1 = sha1.New()
		writers = append(writers, hSHA1)
	}
	if wantSHA256 {
		hSHA256 = sha256.New()
		writers = append(writers, hSHA256)
	}
	if len(writers) == 0 {
		return "", "", "", nil
	}
	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return "", "", "", err
	}
	if hMD5 != nil {
		md5hex = fmt.Sprintf("%x", hMD5.Sum(nil))
	}
	if hSHA1 != nil {
		sha1hex = fmt.Sprintf("%x", hSHA1.Sum(nil))
	}
	if hSHA256 != nil {
		sha256hex = fmt.Sprintf("%x", hSHA256.Sum(nil))
	}
	return md5hex, sha1hex, sha256hex, nil
}

// iocCheckDpkgHashes reads /var/lib/dpkg/info/*.md5sums and checks stored checksums.
func iocCheckDpkgHashes(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, count *int) {
	iocCheckDpkgHashesDir(ctx, w, sh, count, "/var/lib/dpkg/info")
}

// iocCheckDpkgHashesDir is the testable core of iocCheckDpkgHashes. The stored
// md5 is the checksum dpkg recorded at install time, not a live file hash, so
// the finding is labelled accordingly. Hits are written to both the section
// file and the Registry so the text count reconciles with the analyst report.
func iocCheckDpkgHashesDir(ctx *ModuleContext, w *output.Writer, sh *ioc.IOCSet, count *int, md5sumsDir string) {
	entries, err := os.ReadDir(md5sumsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md5sums") {
			continue
		}
		data, err := osutil.ReadFileNoAtime(filepath.Join(md5sumsDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			hash := strings.ToLower(fields[0])
			if sh.MatchHash(hash) {
				pkg := strings.TrimSuffix(e.Name(), ".md5sums")
				w.Write("  [HASH MATCH] dpkg package %s file %s: md5=%s\n", pkg, fields[1], hash)
				ctx.Registry.Add(output.HIGH, "ioc", "Custom IOC hash match",
					fmt.Sprintf("Custom IOC (hash) dpkg-recorded checksum, package %s file %s: md5=%s", pkg, fields[1], hash))
				*count++
			}
		}
	}
}

func userHistoryFiles() []string {
	histNames := []string{".bash_history", ".zsh_history", ".sh_history", ".python_history"}
	var paths []string
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir == "" || e.HomeDir == "/" {
				continue
			}
			for _, h := range histNames {
				paths = append(paths, filepath.Join(e.HomeDir, h))
			}
		}
	}
	for _, h := range histNames {
		paths = append(paths, filepath.Join("/root", h))
	}
	return paths
}

func userDotFiles() []string {
	dotFiles := []string{".bashrc", ".bash_profile", ".profile"}
	var paths []string
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir == "" || e.HomeDir == "/" {
				continue
			}
			for _, d := range dotFiles {
				paths = append(paths, filepath.Join(e.HomeDir, d))
			}
		}
	}
	for _, d := range dotFiles {
		paths = append(paths, filepath.Join("/root", d))
	}
	return paths
}

func userSSHFiles() []string {
	sshFiles := []string{".ssh/known_hosts", ".ssh/authorized_keys", ".ssh/authorized_keys2"}
	var paths []string
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir == "" || e.HomeDir == "/" {
				continue
			}
			for _, sf := range sshFiles {
				paths = append(paths, filepath.Join(e.HomeDir, sf))
			}
		}
	}
	for _, sf := range sshFiles {
		paths = append(paths, filepath.Join("/root", sf))
	}
	return paths
}

func userSSHKnownHosts() []string {
	var paths []string
	if entries, err := procfs.ReadPasswd(); err == nil {
		for _, e := range entries {
			if e.HomeDir == "" || e.HomeDir == "/" {
				continue
			}
			paths = append(paths, filepath.Join(e.HomeDir, ".ssh", "known_hosts"))
		}
	}
	paths = append(paths, "/root/.ssh/known_hosts")
	return paths
}

// globPaths expands a glob pattern into matching file paths.
func globPaths(pattern string) []string {
	matches, _ := filepath.Glob(pattern)
	return matches
}

var errFileTooLarge = fmt.Errorf("file too large")
