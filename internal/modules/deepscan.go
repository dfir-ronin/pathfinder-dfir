package modules

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/logutil"
	"github.com/pathfinder/internal/netfs"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

type scanJob struct {
	path   string
	phase  int // 1 = config/script root, 2 = staging dir
	size   int64
	data   []byte // non-nil = pre-read; worker skips file read
	ipOnly bool   // skip string-hunt (used for pre-read log files)
}

type hitResult struct {
	category string
	path     string
	lineNum  int
	sig      ioc.Signature
	line     string
}

type fileResult struct {
	path    string
	ips     []string
	domains []string
	hits    []hitResult
}

const (
	ipDomainMaxBytes = 1 << 20   // 1 MB: per-file cap for IP/domain extraction
	stagingMaxBytes  = 100 << 20 // 100 MB: phase-2 enqueue cap
	phase2IOTimeout  = 5 * time.Second
	stagingDeadline  = 30 * time.Second
)

// scanContent applies category pre-filters against data and returns all hits.
// Lines longer than lineScanWindow are scanned in overlapping windows so
// per-window regex cost is bounded while tokens near window boundaries are
// still caught. Duplicate hits from overlapping windows are removed before
// returning (keyed on lineNum + sig.ID).
func scanContent(path string, data []byte, preFilters []ioc.CategoryPreFilter) []hitResult {
	const (
		lineScanWindow  = 64 << 10 // 64 KiB regex window
		lineScanOverlap = 1 << 10  // 1 KiB overlap, longer than any signature literal
	)
	var hits []hitResult
	// seen deduplicates hits that may fire in two adjacent windows for a token
	// that sits on a window boundary. Key: "lineNum:sigID".
	seen := make(map[string]bool)
	matchLine := func(s string, lineNum int) {
		for _, pf := range preFilters {
			if !pf.Re.MatchString(s) {
				continue
			}
			for _, sig := range ioc.StringHuntSignatures {
				if sig.Category != pf.Category {
					continue
				}
				if sig.Pattern.MatchString(s) {
					key := fmt.Sprintf("%d:%s", lineNum, sig.ID)
					if seen[key] {
						break
					}
					seen[key] = true
					hits = append(hits, hitResult{
						category: pf.Category,
						path:     path,
						lineNum:  lineNum,
						sig:      sig,
						line:     strings.TrimSpace(s),
					})
					break
				}
			}
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		if len(line) <= lineScanWindow {
			matchLine(line, lineNum)
			continue
		}
		for start := 0; start < len(line); start += lineScanWindow - lineScanOverlap {
			end := start + lineScanWindow
			if end > len(line) {
				end = len(line)
			}
			matchLine(line[start:end], lineNum)
			if end == len(line) {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		hits = append(hits, hitResult{
			category: "scan_error",
			path:     path,
			lineNum:  lineNum,
			line:     "scanner error: " + err.Error(),
		})
	}
	return hits
}

// scanProcSources collects external IPs and domains from live process data.
// Returns two maps: IP -> sources, domain -> sources.
func scanProcSources(ctx *ModuleContext) (map[string][]string, map[string][]string) {
	ipSet := make(map[string][]string)
	domainSet := make(map[string][]string)

	add := func(source, text string) {
		for _, ip := range ioc.ExtractExternalIPs(text) {
			ipSet[ip] = append(ipSet[ip], source)
		}
		for _, d := range ioc.ExtractDomains(text) {
			domainSet[d] = append(domainSet[d], source)
		}
	}

	procs := ctx.Processes()
	for _, p := range procs {
		raw, _ := procfs.ReadEnvironRaw(p.PID)
		if raw != "" {
			add(fmt.Sprintf("proc/%d/environ", p.PID), raw)
		}
		if p.Cmdline != "" {
			add(fmt.Sprintf("proc/%d/cmdline", p.PID), p.Cmdline)
		}
	}

	sockets, _ := netfs.ReadSockets()
	for _, s := range sockets {
		if s.State == "ESTABLISHED" {
			add("proc/net/tcp", s.RemoteAddr)
		}
	}

	return ipSet, domainSet
}

// RunDeepScan executes the deep-scan behavioural analysis engine.
func RunDeepScan(ctx *ModuleContext) {
	output.Chapter("[DEEPSCAN] Running Pathfinder threat-hunt engine...")
	output.Info("Output → " + ctx.Dirs.DeepScan)

	seedIPs, seedDomains := scanProcSources(ctx)
	unifiedFileScan(ctx, seedIPs, seedDomains)

	ctx.Log.Log("deepscan", "complete", "all sections done")
}

// unifiedFileScan runs one worker-pool pass over all file targets, writing
// section 01 (external IPs/domains, informational) and sections 02-05
// (string hunt, scored). seedIPs and seedDomains are pre-populated from
// scanProcSources before any file is read.
func unifiedFileScan(ctx *ModuleContext, seedIPs, seedDomains map[string][]string) {
	unifiedFileScanRoots(ctx, seedIPs, seedDomains, []string{"/tmp", "/var/tmp", "/dev/shm"})
}

func unifiedFileScanRoots(ctx *ModuleContext, seedIPs, seedDomains map[string][]string, stagingRoots []string) {
	type catWriter struct {
		w         *output.Writer
		hits      int
		fileCount int
		maxSev    output.Severity
		seenFiles map[string]bool
	}
	sevRank := map[output.Severity]int{output.HIGH: 3, output.MEDIUM: 2, output.LOW: 1}

	w01 := newSectionWriter(ctx, ctx.Dirs.DeepScan, "01_external_ip_domain.txt",
		"External IP & Domain Indicators",
		"proc/environ, proc/*/cmdline, /proc/net/*, /etc/hosts, /etc/resolv.conf, auth.log (+rotations), syslog (+rotations), access.log, crontabs, /etc/init.d/, /etc/profile.d/, systemd units, shell profiles, staging dirs (/tmp, /var/tmp, /dev/shm)")
	defer w01.Close()

	cws := make(map[string]*catWriter)
	for cat, fname := range ioc.StringHuntCategoryFiles {
		label := ioc.StringHuntCategoryLabels[cat]
		cws[cat] = &catWriter{
			w: newSectionWriter(ctx, ctx.Dirs.DeepScan, fname,
				"String Hunt — "+label,
				"targeted /etc paths, /usr/local/bin, /usr/local/sbin, /var/www, /tmp, /var/tmp, /dev/shm"),
			seenFiles: make(map[string]bool),
		}
	}
	defer func() {
		for _, cw := range cws {
			cw.w.Close()
		}
	}()

	preFilters := ioc.BuildCategoryPreFilters()

	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	workCh := make(chan scanJob, 2*n)
	resultsCh := make(chan fileResult, 256)

	go func() {
		defer close(workCh)

		scriptExts := map[string]bool{
			".sh": true, ".py": true, ".pl": true, ".rb": true,
			".php": true, ".asp": true, ".aspx": true, ".jsp": true,
			".conf": true, ".cfg": true,
		}

		userFiles := map[string]bool{}
		if ctx.Cfg != nil {
			for _, p := range []string{ctx.Cfg.SuppressFile, ctx.Cfg.ManifestPath, ctx.Cfg.IOCFile} {
				if p != "" {
					if abs, err := filepath.Abs(p); err == nil {
						userFiles[abs] = true
					}
				}
			}
		}

		seen := map[string]bool{}

		enqueueFile := func(p string) {
			if ctx.SelfPath != "" && p == ctx.SelfPath {
				return
			}
			if ctx.OutputPrefix != "" && strings.HasPrefix(p, ctx.OutputPrefix) {
				return
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				return
			}
			if userFiles[abs] || seen[abs] {
				return
			}
			seen[abs] = true
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				return
			}
			ext := strings.ToLower(filepath.Ext(p))
			if !scriptExts[ext] && fi.Size() > 1024*1024 {
				return
			}
			workCh <- scanJob{path: p, phase: 1, size: fi.Size()}
		}

		// enqueueDir delegates to walkFiles, which handles ctx.Cfg userFiles exclusion internally.
		enqueueDir := func(dir string) {
			walkFiles(ctx, dir, func(path string, info os.FileInfo) {
				abs, _ := filepath.Abs(path)
				if seen[abs] {
					return
				}
				seen[abs] = true
				ext := strings.ToLower(filepath.Ext(path))
				if !scriptExts[ext] && info.Size() > 1024*1024 {
					return
				}
				workCh <- scanJob{path: path, phase: 1, size: info.Size()}
			})
		}

		// Specific /etc files
		for _, p := range []string{
			"/etc/crontab", "/etc/at.allow", "/etc/at.deny",
			"/etc/rc.local", "/etc/profile", "/etc/bash.bashrc",
			"/etc/environment", "/etc/hosts", "/etc/resolv.conf",
			"/etc/ssh/sshd_config", "/etc/ld.so.preload",
		} {
			enqueueFile(p)
		}

		// /etc/cron.* dirs
		if cronDirs, _ := filepath.Glob("/etc/cron.*"); cronDirs != nil {
			for _, d := range cronDirs {
				enqueueDir(d)
			}
		}

		// Targeted /etc subdirs
		for _, d := range []string{
			"/etc/systemd/system", "/etc/systemd/system-generators",
			"/etc/init.d", "/etc/profile.d", "/etc/update-motd.d",
			"/etc/apt/apt.conf.d", "/etc/yum.repos.d",
			"/etc/nginx", "/etc/apache2",
			"/etc/sudoers.d", "/etc/logrotate.d",
			"/etc/ld.so.conf.d", "/etc/network",
		} {
			enqueueDir(d)
		}

		// Vendor systemd units
		enqueueDir("/usr/lib/systemd/system")

		// Web and local binary dirs
		for _, root := range []string{"/usr/local/bin", "/usr/local/sbin", "/var/www"} {
			enqueueDir(root)
		}

		// Log files: pre-read (IP/domain only, no string hunt)
		for _, lf := range []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/syslog",
			"/var/log/messages",
			"/var/log/apache2/access.log",
			"/var/log/nginx/access.log",
			"/var/log/httpd/access_log",
		} {
			combined, statuses := logutil.ReadWithRotations(lf)
			for _, s := range statuses {
				if s.State == "error" {
					ctx.Log.Log("deepscan", "log_read_error", fmt.Sprintf("%s: %s", s.Path, s.Err))
				}
			}
			if combined == "" {
				continue
			}
			workCh <- scanJob{path: lf, phase: 1, data: []byte(combined), ipOnly: true}
		}

		// Per-user dotfiles and systemd user units
		dotfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_logout"}
		homes := []string{"/root"}
		pwEntries, _ := procfs.ReadPasswd()
		for _, pe := range pwEntries {
			if pe.HomeDir != "" && pe.HomeDir != "/" {
				homes = append(homes, pe.HomeDir)
			}
		}
		for _, home := range homes {
			for _, df := range dotfiles {
				enqueueFile(filepath.Join(home, df))
			}
			enqueueDir(filepath.Join(home, ".config/systemd/user"))
		}

		// Phase 2: staging dirs with 30s deadline per root
		for _, root := range stagingRoots {
			deadline := time.Now().Add(stagingDeadline)
			timedOut := false
			_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if time.Now().After(deadline) {
					timedOut = true
					return filepath.SkipAll
				}
				if ctx.SelfPath != "" && path == ctx.SelfPath {
					return nil
				}
				if ctx.OutputPrefix != "" && strings.HasPrefix(path, ctx.OutputPrefix) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					return nil
				}
				abs, _ := filepath.Abs(path)
				if userFiles[abs] {
					return nil
				}
				fi, err := os.Lstat(path)
				if err != nil || !fi.Mode().IsRegular() {
					return nil
				}
				if fi.Size() == 0 || fi.Size() > stagingMaxBytes {
					return nil
				}
				select {
				case workCh <- scanJob{path: path, phase: 2, size: fi.Size()}:
					return nil
				case <-time.After(time.Until(deadline)):
					timedOut = true
					return filepath.SkipAll
				}
			})
			if timedOut {
				ctx.Log.Log("deepscan", "staging-walk-timeout", root)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range workCh {
				var data []byte
				if job.data != nil {
					data = job.data
				} else if job.phase == 2 {
					type res struct {
						b []byte
						e error
					}
					ch := make(chan res, 1)
					go func(p string) {
						b, e := osutil.ReadFileRegularNoBlock(p)
						ch <- res{b, e}
					}(job.path)
					select {
					case r := <-ch:
						if r.e != nil {
							ctx.Log.Log("deepscan", "staging-read-error", job.path)
							continue
						}
						data = r.b
						ctx.Log.Log("deepscan", "staging-scan", job.path)
					case <-time.After(phase2IOTimeout):
						ctx.Log.Log("deepscan", "staging-read-timeout", job.path)
						continue
					}
				} else {
					var err error
					data, err = osutil.ReadFileNoAtime(job.path)
					if err != nil {
						continue
					}
				}

				fr := fileResult{path: job.path}
				if len(data) <= ipDomainMaxBytes {
					s := string(data)
					fr.ips = ioc.ExtractExternalIPs(s)
					fr.domains = ioc.ExtractDomains(s)
				}
				if !job.ipOnly {
					fr.hits = scanContent(job.path, data, preFilters)
				}
				resultsCh <- fr
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Accumulate into the caller-provided seed maps (intentional mutation;
	// callers pass maps they want populated with combined proc + file results).
	ipSet := seedIPs
	domainSet := seedDomains
	var allHits []hitResult
	var scanErrors []hitResult

	for fr := range resultsCh {
		for _, ip := range fr.ips {
			ipSet[ip] = append(ipSet[ip], fr.path)
		}
		for _, d := range fr.domains {
			domainSet[d] = append(domainSet[d], fr.path)
		}
		for _, h := range fr.hits {
			if h.category == "scan_error" {
				scanErrors = append(scanErrors, h)
			} else {
				allHits = append(allHits, h)
			}
		}
	}

	// section 01: external IPs
	w01.WriteSectionHeader("External IP Addresses")
	if len(ipSet) == 0 {
		w01.Write("  None found.\n")
	} else {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		w01.Write("%-20s  %s\n", "IP ADDRESS", "SOURCES")
		w01.Write("%s\n", strings.Repeat("─", 60))
		for _, ip := range ips {
			w01.Write("  %-20s  %s\n", ip, strings.Join(uniqueStrings(ipSet[ip]), ", "))
		}
	}

	// section 01: external domains
	w01.WriteSectionHeader("External Domains")
	if len(domainSet) == 0 {
		w01.Write("  None found.\n")
	} else {
		domains := make([]string, 0, len(domainSet))
		for d := range domainSet {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		w01.Write("%-45s  %s\n", "DOMAIN", "SOURCES")
		w01.Write("%s\n", strings.Repeat("─", 70))
		for _, d := range domains {
			w01.Write("  %-45s  %s\n", d, strings.Join(uniqueStrings(domainSet[d]), ", "))
		}
	}

	// section 01: scan errors
	if len(scanErrors) > 0 {
		w01.WriteSectionHeader("Scan Errors")
		for _, e := range scanErrors {
			w01.Write("  %s: %s\n", e.path, e.line)
			ctx.Log.Log("deepscan", "scan-error", e.path+": "+e.line)
		}
	}

	if len(ipSet) == 0 && len(domainSet) == 0 {
		output.Ok("External indicators: none found (informational)")
	} else {
		output.Ok(fmt.Sprintf("External indicators: %d IPs, %d domains (informational)", len(ipSet), len(domainSet)))
	}

	// sections 02-05: string hunt
	sort.Slice(allHits, func(i, j int) bool {
		if allHits[i].path != allHits[j].path {
			return allHits[i].path < allHits[j].path
		}
		return allHits[i].lineNum < allHits[j].lineNum
	})

	lastPathByCat := make(map[string]string)
	totalHits := 0
	for _, h := range allHits {
		cw, ok := cws[h.category]
		if !ok {
			continue
		}
		if lastPathByCat[h.category] != h.path {
			cw.w.WriteSectionHeader(h.path)
			lastPathByCat[h.category] = h.path
		}
		sev := output.Severity(h.sig.Severity)
		cw.w.Write("  Line %-5d [%s] %s\n    → %s\n",
			h.lineNum, sev, h.sig.Description, h.line)
		cw.hits++
		totalHits++
		if !cw.seenFiles[h.path] {
			cw.seenFiles[h.path] = true
			cw.fileCount++
		}
		if sevRank[sev] > sevRank[cw.maxSev] {
			cw.maxSev = sev
		}
	}

	for cat, cw := range cws {
		if cw.hits == 0 {
			cw.w.Write("No matches found.\n")
			continue
		}
		catLabel := ioc.StringHuntCategoryLabels[cat]
		fname := ioc.StringHuntCategoryFiles[cat]
		detLabel, ok := ioc.StringHuntCategoryDetectionLabel[cat]
		if !ok {
			detLabel = "Suspicious string match in config/script"
		}
		ctx.Registry.Add(cw.maxSev, "deepscan", detLabel,
			fmt.Sprintf("%s: %d hit(s) in %d file(s) — see %s",
				catLabel, cw.hits, cw.fileCount, fname))
	}

	if totalHits == 0 {
		output.Ok("No suspicious strings found in configs/scripts")
	} else {
		output.Warn(fmt.Sprintf("String hunting hits: %d across all categories", totalHits))
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
