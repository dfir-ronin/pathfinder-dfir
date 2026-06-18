package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"archive/zip"

	"github.com/pathfinder/internal/cloud"
	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/modules"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/report"
	"github.com/pathfinder/internal/suppress"
)

var (
	GitCommit = "dev"
	BuildDate = "2026"
)

const metaBorderWidth = 80 // matches Case Metadata box rule width

func computeVerdict(high, breachThreshold, compromiseThreshold, med int) string {
	switch {
	case high >= breachThreshold:
		return "HOSTILE INDICATORS DETECTED — IMMEDIATE ACTION REQUIRED"
	case high >= compromiseThreshold:
		return "RISK DETECTED — HIGH SEVERITY FINDINGS PRESENT"
	case high > 0, med > 0:
		return "SUSPICIOUS — INVESTIGATE MEDIUM FINDINGS"
	default:
		return "ALL CLEAR"
	}
}

func main() {
	cfg := config.Parse()
	output.SetQuiet(cfg.Stealth)

	host := collectHostMeta()

	if !cfg.Stealth {
		printBanner()
	}

	ctx, err := modules.NewModuleContext(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	if cfg.IOCFile != "" {
		sh, err := ioc.ParseIOCSet(cfg.IOCFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "IOC ERROR: %v\n", err)
			os.Exit(1)
		}
		ctx.IOC = sh
		msg := fmt.Sprintf("%d IOC indicators loaded", sh.Loaded)
		if sh.Skipped > 0 {
			msg += fmt.Sprintf(", %d skipped (invalid regex/hash)", sh.Skipped)
		}
		if sh.Loaded+sh.Skipped > 500 {
			msg += " -- consider splitting IOC file for faster scans"
		}
		output.Info(msg)
	}

	{
		var userRules []suppress.SuppressRule
		if cfg.SuppressFile != "" {
			rules, err2 := suppress.LoadUserRules(cfg.SuppressFile)
			if err2 != nil {
				output.Warn(fmt.Sprintf("suppress-config error: %v", err2))
			} else {
				userRules = rules
			}
		}
		eng, err2 := suppress.New(suppress.DetectDistro(), userRules)
		if err2 != nil {
			output.Warn(fmt.Sprintf("suppression engine init failed: %v", err2))
		} else {
			ctx.Registry.SetEngine(eng)
			ctx.Registry.SetShowSuppressed(cfg.ShowSuppressed)
		}
	}

	if cfg.AzSASURL != "" {
		u, err := cloud.NewSASUploader(cfg.AzSASURL, cfg.CaseID, false)
		if err != nil {
			output.Warn(fmt.Sprintf("Azure uploader disabled: %v", err))
		} else {
			ctx.Uploader = u
			output.Ok(fmt.Sprintf("Azure upload enabled → case %s", cfg.CaseID))
		}
	}

	// SSE-only mode: run manifest collection exclusively, no detection modules, no main zip.
	if cfg.SSEOnly {
		runSSEOnly(ctx, cfg, host)
		return
	}

	// Open main archive up front; modules stream entries directly in sequential mode.
	zipPath := ctx.Dirs.Base + ".zip"
	zipFile, zipCreateErr := os.Create(zipPath)
	if zipCreateErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot create archive %s: %v\n", zipPath, zipCreateErr)
		os.Exit(1)
	}
	zw := zip.NewWriter(zipFile)
	baseParent := filepath.Dir(ctx.Dirs.Base)

	if !cfg.Stealth {
		printMetadata(cfg, ctx, host)
		cG := "\033[1;32m" // Bold Green
		cR := "\033[0m"    // Reset
		fmt.Printf("%s  [DEPLOY] Initializing tactical interface...%s\n\n", cG, cR)
	}

	start := time.Now()
	archiveSkipped := runModules(ctx, cfg, zw, baseParent)

	elapsed := time.Since(start).Round(time.Second)

	if e, ok := ctx.Registry.Engine(); ok {
		p, u := e.Counts()
		if p+u > 0 {
			output.Info(fmt.Sprintf("%d finding(s) suppressed (distro profile: %d, user config: %d)", p+u, p, u))
		}
	}

	ctx.Log.Close()
	printCasebook(ctx, cfg, host)

	if !cfg.Stealth {
		printImpactMap(ctx, cfg)
		cG := "\033[1;32m" // Bold Green
		cR := "\033[0m"    // Reset
		fmt.Printf("%s  [INTEL-WRAP] Archiving evidence for analysis...%s\n\n", cG, cR)
	}

	archiveSound, manifestPath := finalizeArchive(ctx, cfg, host, start, archiveSkipped, zipPath, zw, zipFile, baseParent)

	high, med, low, _ := ctx.Registry.Counts()
	verdict := computeVerdict(high, cfg.BreachThreshold, cfg.CompromiseThreshold, med)

	if cfg.Stealth {
		fmt.Printf("VERDICT=%s\nARCHIVE=%s\nELAPSED=%s\n", verdict, zipPath, elapsed)
		if ctx.SSEZipPath != "" {
			fmt.Printf("SSE=%s\n", ctx.SSEZipPath)
		}
		fmt.Printf("MANIFEST=%s\n", manifestPath)
		if !archiveSound {
			os.Exit(2)
		}
		return
	}

	cR := output.ResetColor()
	cC := output.ForestColor()
	cO := output.SageColor()
	cRed := output.CrimsonColor()
	cY := output.OrangeColor()
	cLow := output.OchreColor()

	fmt.Printf("\n")
	if high >= cfg.BreachThreshold {
		fmt.Printf("%s  ┌──────────────────────────────────────────────────────────┐%s\n", cRed, cR)
		fmt.Printf("%s  │      ⚠  MULTIPLE HIGH-SEVERITY INDICATORS DETECTED.      │%s\n", cRed, cR)
		fmt.Printf("%s  │                  URGENT ACTION REQUIRED                  │%s\n", cRed, cR)
		fmt.Printf("%s  └──────────────────────────────────────────────────────────┘%s\n\n", cRed, cR)
	} else {
		fmt.Printf("%s  ┌──────────────────────────────────────────────────────────┐%s\n", cC, cR)
		fmt.Printf("%s  │%s  ✓  %-53s%s%s│%s\n", cC, cO, "Scan complete — case "+cfg.CaseID, cR, cC, cR)
		fmt.Printf("%s  └──────────────────────────────────────────────────────────┘%s\n\n", cC, cR)
	}

	fmt.Printf("%s  Archive  :%s %s\n", cO, cR, zipPath)
	if ctx.SSEZipPath != "" {
		fmt.Printf("%s  SSE      :%s %s\n", cO, cR, ctx.SSEZipPath)
	}
	fmt.Printf("%s  Manifest :%s %s\n", cO, cR, manifestPath)
	fmt.Printf("%s  Elapsed  :%s %s\n", cO, cR, elapsed)
	fmt.Printf("\n")
	fmt.Printf("%s  HIGH   : %d%s  ·  %s  MEDIUM : %d%s  ·  %s  LOW : %d%s\n\n",
		cRed, high, cR, cY, med, cR, cLow, low, cR)
	fmt.Printf("%s  Pathfinder has left the AO.%s\n\n", cO, cR)
	if !archiveSound {
		os.Exit(2)
	}
}

func printBanner() {
	cG := output.CrimsonColor()
	cO := output.SageColor()
	cR := output.ResetColor()

	const boxTotalWidth = 2 + 1 + metaBorderWidth + 1 // 84

	artLines := []string{
		`________       ___________ ____________       _________            `,
		`___  __ \_____ __  /___  /____  __/__(_)____________  /____________`,
		`__  /_/ /  __ ` + "`" + `/  __/_  __ \_  /_ __  /__  __ \  __  /_  _ \_  ___/`,
		`_  ____// /_/ // /_ _  / / /  __/ _  / _  / / / /_/ / /  __/  /     `,
		`/_/     \__,_/ \__/ /_/ /_//_/    /_/  /_/ /_/\__,_/  \___//_/  `,
	}
	maxW := 0
	for _, l := range artLines {
		if len(l) > maxW {
			maxW = len(l)
		}
	}
	artIndent := (boxTotalWidth - maxW) / 2
	if artIndent < 0 {
		artIndent = 0
	}
	artPrefix := strings.Repeat(" ", artIndent)

	center := func(s string) string {
		pad := (boxTotalWidth - utf8.RuneCountInString(s)) / 2
		if pad < 0 {
			pad = 0
		}
		return strings.Repeat(" ", pad) + s
	}

	fmt.Print(cG)
	fmt.Println()
	for _, l := range artLines {
		fmt.Println(artPrefix + l)
	}
	fmt.Println()
	fmt.Print(cR)

	hRule := strings.Repeat("─", 41)
	meta := fmt.Sprintf("v%s  ·  %s / %s", config.Version, GitCommit, BuildDate)
	fmt.Printf("%s%s%s\n", cG, center("Drop in. Hunt down. Collect artifacts. Get out."), cR)
	fmt.Printf("%s%s%s\n", cO, center(hRule), cR)
	fmt.Printf("%s%s%s\n", cO, center("Digital Forensics & Incident Response"), cR)
	fmt.Printf("%s%s%s\n", cO, center(hRule), cR)
	fmt.Printf("%s%s%s\n\n", cO, center(meta), cR)
}

func printMetadata(cfg *config.Config, ctx *modules.ModuleContext, host HostMeta) {
	cC := output.ForestColor()
	cO := output.SageColor()
	cR := output.ResetColor()
	h := strings.Repeat("─", metaBorderWidth)

	row := func(label, value string) {
		fmt.Printf("%s  │ %s%-13s %-64s%s%s │%s\n", cC, cR, label, value, cR, cC, cR)
	}

	trunc := func(s string) string {
		if len(s) > 64 {
			return s[:61] + "..."
		}
		return s
	}

	outPath := ctx.Dirs.Base
	if len(outPath) > 64 {
		outPath = outPath[:61] + "..."
	}

	fmt.Printf("%s  ┌%s┐%s\n", cC, h, cR)
	fmt.Printf("%s  │ %s%-78s%s%s │%s\n", cC, cO, config.BuildName+"  ·  TACTICAL FORENSICS SUITE", cR, cC, cR)
	fmt.Printf("%s  ├%s┤%s\n", cC, h, cR)
	row("Case ID   :", cfg.CaseID)
	row("Host      :", host.Hostname)
	if host.OS != "" {
		row("OS        :", trunc(host.OS))
	}
	if host.Kernel != "" {
		row("Kernel    :", trunc(host.Kernel))
	}
	if host.Arch != "" {
		row("Arch      :", host.Arch)
	}
	if host.CPU != "" {
		row("CPU       :", trunc(host.CPU))
	}
	if host.MemTotal != "" {
		row("Memory    :", host.MemTotal)
	}
	if host.TimeZone != "" {
		row("TimeZone  :", host.TimeZone)
	}
	if len(host.Mounts) > 0 {
		row("Mounts    :", trunc(host.Mounts[0]))
		for _, mt := range host.Mounts[1:] {
			row("           ", trunc(mt))
		}
	}
	if len(host.IPs) > 0 {
		row("IPs       :", strings.Join(host.IPs, ", "))
	}
	row("Date UTC  :", time.Now().UTC().Format(time.RFC3339))
	row("Operator  :", host.Operator)
	if host.WorkDir != "" {
		row("WorkDir   :", trunc(host.WorkDir))
	}
	row("Mode      :", cfg.Mode)
	row("Output    :", outPath)
	fmt.Printf("%s  └%s┘%s\n\n", cC, h, cR)

	if !cfg.IsRoot {
		output.Warn("Not running as root — privileged sections will be skipped.")
	} else {
		output.Ok("Running as root — full collection enabled.")
	}
	fmt.Println()
}

func printCasebook(ctx *modules.ModuleContext, cfg *config.Config, host HostMeta) {
	if !cfg.Stealth {
		cG := "\033[1;32m" // Bold Green
		cR := "\033[0m"    // Reset
		fmt.Printf("\n")
		fmt.Printf("%s  [SITREP] Creating report...%s\n\n", cG, cR)
	}

	findings := ctx.Registry.All()
	high, med, low, info := ctx.Registry.Counts()

	summaryPath := filepath.Join(ctx.Dirs.Base, "findings_summary.txt")
	sf, err := os.Create(summaryPath)
	if err == nil {
		fmt.Fprintf(sf, "%s — Findings Summary\n", config.BuildName)
		fmt.Fprintf(sf, "%s\n", strings.Repeat("=", 40))
		fmt.Fprintf(sf, "Case ID  : %s\n", cfg.CaseID)
		fmt.Fprintf(sf, "Host     : %s\n", host.Hostname)
		if host.Kernel != "" {
			fmt.Fprintf(sf, "Kernel   : %s\n", host.Kernel)
		}
		if len(host.IPs) > 0 {
			fmt.Fprintf(sf, "IPs      : %s\n", strings.Join(host.IPs, ", "))
		}
		if host.OS != "" {
			fmt.Fprintf(sf, "OS       : %s\n", host.OS)
		}
		if host.Arch != "" {
			fmt.Fprintf(sf, "Arch     : %s\n", host.Arch)
		}
		if host.CPU != "" {
			fmt.Fprintf(sf, "CPU      : %s\n", host.CPU)
		}
		if host.MemTotal != "" {
			fmt.Fprintf(sf, "Memory   : %s\n", host.MemTotal)
		}
		if host.TimeZone != "" {
			fmt.Fprintf(sf, "TimeZone : %s\n", host.TimeZone)
		}
		for i, mt := range host.Mounts {
			if i == 0 {
				fmt.Fprintf(sf, "Mounts   : %s\n", mt)
			} else {
				fmt.Fprintf(sf, "           %s\n", mt)
			}
		}
		fmt.Fprintf(sf, "Date UTC : %s\n\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(sf, "HIGH: %d  MEDIUM: %d  LOW: %d  INFO: %d  (Total: %d)\n\n",
			high, med, low, info, len(findings))
		fmt.Fprintf(sf, "%s\n\n", strings.Repeat("─", 70))
		for _, f := range findings {
			fmt.Fprintf(sf, "[%s] [%s] [%s] [%s] %s\n",
				f.Severity, f.Timestamp.Format("15:04:05"), f.Module, f.Label, f.Message)
		}
		sf.Close()
		output.Ok("Findings summary: " + summaryPath)
	}

	jsonReport := output.FindingsReport{
		CaseID:   cfg.CaseID,
		Host:     host.Hostname,
		ScanTime: time.Now().UTC(),
		Verdict:  computeVerdict(high, cfg.BreachThreshold, cfg.CompromiseThreshold, med),
		OS:       host.OS,
		Arch:     host.Arch,
		CPU:      host.CPU,
		MemTotal: host.MemTotal,
		TimeZone: host.TimeZone,
		Mounts:   host.Mounts,
		TempDir:  host.TempDir,
		Kernel:   host.Kernel,
		IPs:      host.IPs,
	}
	jsonSummaryPath := filepath.Join(ctx.Dirs.Base, "findings_summary.json")
	if err := ctx.Registry.WriteJSONReport(jsonSummaryPath, jsonReport); err != nil {
		output.Warn(fmt.Sprintf("JSON summary error: %v", err))
	} else {
		output.Ok("Findings summary (JSON): " + jsonSummaryPath)
	}

	reportPath := filepath.Join(ctx.Dirs.Base, "Report.md")
	writeReport(reportPath, ctx, cfg, high, med, low, findings, host)
}

// HostMeta holds host identification fields collected once at startup.
type HostMeta struct {
	Hostname string
	Operator string
	IPs      []string
	OS       string
	Kernel   string
	Arch     string
	CPU      string
	MemTotal string
	TimeZone string
	Mounts   []string
	TempDir  string
	WorkDir  string
}

func collectHostMeta() HostMeta {
	hostname, _ := os.Hostname()
	m := HostMeta{
		Hostname: hostname,
		Operator: whoami(),
		OS:       hostOS(),
		Kernel:   hostKernel(),
		Arch:     hostArch(),
		CPU:      hostCPU(),
		MemTotal: hostMemTotal(),
		TimeZone: hostTimeZone(),
		Mounts:   hostMounts(),
		TempDir:  hostTempDir(),
		WorkDir:  hostWorkDir(),
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			m.IPs = append(m.IPs, ip.String())
		}
	}
	return m
}

func hostOS() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func hostKernel() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	// "Linux version X.X.X-... (gcc ...) #N ..." -- keep only up to first " ("
	if i := strings.Index(line, " ("); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return line
}

func hostArch() string { return runtime.GOARCH }

func hostCPU() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.ToLower(line), "model name") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func hostMemTotal() string {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb int64
				fmt.Sscanf(fields[1], "%d", &kb)
				return osutil.FormatFileSize(kb * 1024)
			}
		}
	}
	return ""
}

func hostTimeZone() string {
	data, err := os.ReadFile("/etc/timezone")
	if err == nil {
		if tz := strings.TrimSpace(string(data)); tz != "" {
			return tz
		}
	}
	name, _ := time.Now().Local().Zone()
	return name
}

func hostMounts() []string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	var mounts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		dev, mp := fields[0], fields[1]
		if isRelevantMount(dev) {
			mounts = append(mounts, dev+" "+mp)
		}
	}
	return mounts
}

func isRelevantMount(dev string) bool {
	for _, p := range []string{"/dev/sd", "/dev/nvme", "/dev/vd", "/dev/mapper/", "/dev/xvd", "/dev/hd"} {
		if strings.HasPrefix(dev, p) {
			return true
		}
	}
	return strings.HasPrefix(dev, "//") || strings.Contains(dev, ":/")
}

func hostTempDir() string { return os.TempDir() }

func hostWorkDir() string { d, _ := os.Getwd(); return d }

// writeReport produces Report.md, a 4-level nested hierarchy analyst report.
func writeReport(path string, ctx *modules.ModuleContext, cfg *config.Config,
	high, med, low int, findings []output.Finding, host HostMeta) {

	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	_, _, _, info := ctx.Registry.Counts()
	verdict := computeVerdict(high, cfg.BreachThreshold, cfg.CompromiseThreshold, med)

	fmt.Fprintf(f, "# PATHFINDER — THREAT REPORT\n\n")
	fmt.Fprintf(f, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(f, "| Case ID | `%s` |\n", cfg.CaseID)
	fmt.Fprintf(f, "| Host | `%s` |\n", host.Hostname)
	fmt.Fprintf(f, "| Operator | `%s` |\n", host.Operator)
	if len(host.IPs) > 0 {
		fmt.Fprintf(f, "| IP(s) | `%s` |\n", strings.Join(host.IPs, ", "))
	}
	if host.OS != "" {
		fmt.Fprintf(f, "| OS | `%s` |\n", host.OS)
	}
	if host.Kernel != "" {
		fmt.Fprintf(f, "| Kernel | `%s` |\n", host.Kernel)
	}
	if host.Arch != "" {
		fmt.Fprintf(f, "| Architecture | `%s` |\n", host.Arch)
	}
	if host.CPU != "" {
		fmt.Fprintf(f, "| CPU | `%s` |\n", host.CPU)
	}
	if host.MemTotal != "" {
		fmt.Fprintf(f, "| Memory | `%s` |\n", host.MemTotal)
	}
	if host.TimeZone != "" {
		fmt.Fprintf(f, "| Time Zone | `%s` |\n", host.TimeZone)
	}
	if len(host.Mounts) > 0 {
		fmt.Fprintf(f, "| Mount Points | `%s` |\n", strings.Join(host.Mounts, ", "))
	}
	fmt.Fprintf(f, "| Date UTC | `%s` |\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(f, "---\n\n## Severity Summary\n\n")
	fmt.Fprintf(f, "| Severity | Count |\n|---|---|\n")
	fmt.Fprintf(f, "| 🟠 HIGH | **%d** |\n", high)
	fmt.Fprintf(f, "| 🟡 MEDIUM | **%d** |\n", med)
	fmt.Fprintf(f, "| 🔵 LOW | **%d** |\n", low)
	fmt.Fprintf(f, "| ⚪ INFO | **%d** |\n\n", info)
	fmt.Fprintf(f, "**VERDICT: %s**\n\n---\n\n", verdict)

	for _, fi := range findings {
		if fi.Label != "" {
			if _, ok := report.Detections[fi.Label]; !ok {
				fmt.Fprintf(os.Stderr, "[WARN] Finding label %q has no entry in report.Detections\n", fi.Label)
			}
		}
	}

	type sevBlock struct {
		sev    output.Severity
		header string
	}
	severities := []sevBlock{
		{output.HIGH, "## 🟠 High Findings"},
		{output.MEDIUM, "## 🟡 Medium Findings"},
		{output.LOW, "## 🔵 Low Findings"},
		{output.INFO, "## ⚪ Informational"},
	}

	for _, sb := range severities {
		var sevFindings []output.Finding
		for _, fi := range findings {
			if fi.Severity == sb.sev {
				sevFindings = append(sevFindings, fi)
			}
		}
		if len(sevFindings) == 0 {
			continue
		}

		// Group by category, then label, then instances.
		catLabelMap := make(map[string]map[string][]output.Finding)
		for _, fi := range sevFindings {
			cat := ""
			if det, ok := report.Detections[fi.Label]; ok {
				cat = det.Category
			}
			if cat == "" {
				cat = fi.Module
			}
			if catLabelMap[cat] == nil {
				catLabelMap[cat] = make(map[string][]output.Finding)
			}
			catLabelMap[cat][fi.Label] = append(catLabelMap[cat][fi.Label], fi)
		}

		type catEntry struct {
			cat   string
			total int
		}
		var cats []catEntry
		for cat, labelMap := range catLabelMap {
			total := 0
			for _, instances := range labelMap {
				total += len(instances)
			}
			cats = append(cats, catEntry{cat, total})
		}
		sort.Slice(cats, func(i, j int) bool {
			if cats[i].total != cats[j].total {
				return cats[i].total > cats[j].total
			}
			return cats[i].cat < cats[j].cat
		})

		fmt.Fprintf(f, "%s  (%d)\n\n", sb.header, len(sevFindings))

		for _, ce := range cats {
			labelMap := catLabelMap[ce.cat]
			fmt.Fprintf(f, "### [%s]\n\n", ce.cat)

			var labels []string
			for lbl := range labelMap {
				labels = append(labels, lbl)
			}
			sort.Strings(labels)

			for _, lbl := range labels {
				instances := labelMap[lbl]
				fmt.Fprintf(f, "#### %s\n\n", lbl)
				if det, ok := report.Detections[lbl]; ok {
					fmt.Fprintf(f, "> **Why it was flagged:** %s\n>\n> **Next Steps:** %s\n\n",
						det.WhyFlagged, det.NextSteps)
				}
				sort.Slice(instances, func(i, j int) bool {
					return instances[i].Timestamp.Before(instances[j].Timestamp)
				})
				const reportInstanceCap = 20
				displayed := instances
				if len(instances) > reportInstanceCap {
					displayed = instances[:reportInstanceCap]
				}
				for _, inst := range displayed {
					fmt.Fprintf(f, "- `[%s]` %s\n", inst.Timestamp.Format("15:04:05"), inst.Message)
				}
				if len(instances) > reportInstanceCap {
					fmt.Fprintf(f, "\n_%d more — see findings_summary.txt for complete list._\n", len(instances)-reportInstanceCap)
				}
				fmt.Fprintf(f, "\n")
			}
		}
	}

	fmt.Fprintf(f, "---\n\n")
	fmt.Fprintf(f, "*Generated by %s v%s · Pathfinder has left the AO.*\n",
		config.BuildName, config.Version)

	output.Ok("Report: " + path)
	fmt.Printf("\n")
}

func printImpactMap(ctx *modules.ModuleContext, cfg *config.Config) {
	type modStats struct {
		name   string
		ran    bool
		high   int
		medium int
		low    int
	}

	findings := ctx.Registry.All()
	counts := map[string]*modStats{
		"volatile":    {name: "VOLATILE", ran: cfg.RunVolatile},
		"users":       {name: "USERS", ran: cfg.RunUsers},
		"baseline":    {name: "BASELINE", ran: cfg.RunBaseline},
		"persistence": {name: "PERSISTENCE", ran: cfg.RunPersistence},
		"audit":       {name: "AUDIT", ran: cfg.RunAudit},
		"journal":     {name: "JOURNAL", ran: cfg.RunJournal},
		"deepscan":    {name: "DEEPSCAN", ran: cfg.RunDeepScan},
		"bodyfile":    {name: "BODYFILE", ran: cfg.RunBodyfile},
		"ioc":         {name: "IOC", ran: cfg.IOCFile != ""},
	}

	for _, f := range findings {
		if s, ok := counts[f.Module]; ok {
			switch f.Severity {
			case output.HIGH:
				s.high++
			case output.MEDIUM:
				s.medium++
			case output.LOW:
				s.low++
			}
		}
	}

	modDesc := map[string]string{
		"volatile":    "Volatile memory & processes",
		"users":       "User artifacts & credentials",
		"baseline":    "System baseline & network",
		"persistence": "Persistence & scheduling",
		"audit":       "Security config & auth logs",
		"journal":     "System journal analysis",
		"deepscan":    "Threat hunting",
		"bodyfile":    "Filesystem timeline analysis",
		"ioc":         "Custom IOC matching",
	}

	cRed := output.CrimsonColor()
	cY := output.OrangeColor()
	cC := output.ForestColor()
	cG := output.GrayColor()
	cW := output.WhiteColor()
	cR := output.ResetColor()

	modColor := func(s *modStats) string {
		if !s.ran {
			return cG
		}
		if s.high > 0 {
			return cRed
		}
		if s.medium > 0 {
			return cY
		}
		return cC
	}

	overallHigh, overallMed := 0, 0
	for _, s := range counts {
		overallHigh += s.high
		overallMed += s.medium
	}
	borderCol := cC
	if overallHigh > 0 {
		borderCol = cRed
	} else if overallMed > 0 {
		borderCol = cY
	}

	h := strings.Repeat("─", 66)
	sep := strings.Repeat("─", 64)
	order := []string{"volatile", "users", "baseline", "persistence", "audit", "journal", "deepscan", "bodyfile", "ioc"}

	rightPart := fmt.Sprintf("%s v%s", config.BuildName, config.Version)
	leftWidth := 64 - len(rightPart)
	if leftWidth < 0 {
		leftWidth = 0
	}
	headerContent := fmt.Sprintf("%-*s%s", leftWidth, "● OPERATION SUMMARY", rightPart)

	colHeader := fmt.Sprintf("%-11s  %-36s %4s %4s %4s", "MODULE", "DESCRIPTION", "HIGH", "MED", "LOW")

	fmt.Printf("%s  ┌%s┐%s\n", borderCol, h, cR)
	fmt.Printf("%s  │ %s%-64s%s%s │%s\n", borderCol, cW, headerContent, cR, borderCol, cR)
	fmt.Printf("%s  ├%s┤%s\n", borderCol, h, cR)
	fmt.Printf("%s  │ %s%-64s%s%s │%s\n", borderCol, cW, colHeader, cR, borderCol, cR)
	fmt.Printf("%s  │ %s%s%s%s │%s\n", borderCol, cG, sep, cR, borderCol, cR)

	for _, key := range order {
		s := counts[key]
		col := modColor(s)
		nameField := fmt.Sprintf("%-11s", s.name)
		descField := fmt.Sprintf("%-36s", modDesc[key])
		if !s.ran {
			fmt.Printf("%s  │ %s%s%s  %s%-36s%s %4s %4s %4s %s│%s\n",
				borderCol,
				col, nameField, cR,
				cG, "SKIPPED", cR,
				"-", "-", "-",
				borderCol, cR)
		} else {
			fmt.Printf("%s  │ %s%s%s  %s %4d %4d %4d %s│%s\n",
				borderCol,
				col, nameField, cR,
				descField,
				s.high, s.medium, s.low,
				borderCol, cR)
		}
	}

	fmt.Printf("%s  │ %s%s%s%s │%s\n", borderCol, cG, sep, cR, borderCol, cR)
	legendPad := strings.Repeat(" ", 24)
	fmt.Printf("%s  │ %s●%s HIGH  %s●%s MEDIUM  %s●%s ALL CLEAR  %s○%s SKIPPED%s%s │%s\n",
		borderCol,
		cRed, cR, cY, cR, cC, cR, cG, cR,
		legendPad, borderCol, cR)
	fmt.Printf("%s  └%s┘%s\n\n", borderCol, h, cR)
}

func whoami() string {
	uid := os.Getuid()
	name := fmt.Sprintf("uid/%d", uid)
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	if os.Geteuid() == 0 && os.Geteuid() != uid {
		return name + " (euid 0 via sudo)"
	}
	return name
}
