package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const Version = "1.0.0-beta"
const BuildName = "PATHFINDER"
const BinaryName = "pathfinder"

type Config struct {
	CaseID              string
	Mode                string
	CmdTimeout          time.Duration
	FindTimeout         time.Duration
	RunVolatile         bool
	RunUsers            bool
	RunBaseline         bool
	RunPersistence      bool
	RunAudit            bool
	RunBodyfile         bool
	RunDeepScan         bool
	RunJournal          bool
	ReportDir           string
	IsRoot              bool
	ManifestPath        string
	AzSASURL            string // Azure container-scoped SAS URL (-azure-sas-url or PATHFINDER_AZ_SAS_URL)
	OutputFormat        string // "text" | "json"
	BreachThreshold     int
	CompromiseThreshold int
	Stealth             bool
	IOCFile             string        // path to custom IOC file (-ioc)
	IOCMaxHashMB        int           // max file size in MB for hash computation (default 100)
	SuppressFile        string        // path to user suppress rules YAML (-suppress-config)
	ShowSuppressed      bool          // print suppressed findings with [SUPPRESSED] tag (-show-suppressed)
	SSEOnly             bool          // run SSE-PACKAGE only, skip all detection modules (-sse-only)
	SSEWalkTimeout      time.Duration // per-directory walk deadline for SSE-PACKAGE dir collection
}

// resolveMode maps the -mode flag to a canonical value. known is false for an
// unrecognized mode, which the caller surfaces as a warning before defaulting.
func resolveMode(mode string) (resolved string, known bool) {
	switch mode {
	case "full":
		return "full", true
	case "quick":
		return "quick", true
	default:
		return "full", false
	}
}

// outputJSONDeprecated reports whether the -output value selects the deprecated
// json format. findings_summary.json is always written, so -output json no
// longer writes a separate findings.json; it is retained only for script
// compatibility and warns.
func outputJSONDeprecated(format string) bool {
	return format == "json"
}

func Parse() *Config {
	c := &Config{}

	volatile := flag.Bool("volatile", false, "Scan volatile process and memory space")
	users := flag.Bool("users", false, "Collect user artifact trace")
	baseline := flag.Bool("baseline", false, "Audit system baseline and network config")
	persistence := flag.Bool("persistence", false, "Collect persistence mechanisms and scheduled tasks")
	audit := flag.Bool("audit", false, "Audit security config and auth logs")
	bodyfile := flag.Bool("bodyfile", false, "Run filesystem timeline analysis (BODYFILE)")
	deepscan := flag.Bool("deepscan", false, "Run the Pathfinder threat-hunt engine")
	journal := flag.Bool("journal", false, "Collect and analyze systemd journal")
	mode := flag.String("mode", "full", "Scan mode: full (default) or quick")
	caseID := flag.String("case-id", "", "Case / incident identifier")
	reportDir := flag.String("report-dir", "/tmp", "Directory to write output (default: /tmp)")
	ssePackage := flag.String("sse-package", "", "Custom artifact manifest file (alias: -m)")
	azSAS := flag.String("azure-sas-url", "", "Azure container-scoped SAS URL (or set PATHFINDER_AZ_SAS_URL env var)")
	outputFmt := flag.String("output", "text", "Output format: text (default). json is deprecated (no-op; findings_summary.json is always written)")
	breachThreshold := flag.Int("breach-threshold", 50, "HIGH finding count to trigger BREACH verdict")
	compromiseThreshold := flag.Int("compromise-threshold", 10, "Minimum HIGH finding count to trigger RISK DETECTED verdict (default: 10)")
	stealth := flag.Bool("stealth", false, "Suppress all stdout except verdict and archive path")
	iocFile := flag.String("ioc", "", "Custom IOC file (commands/filenames/processes/domains/ips/hashes)")
	iocMaxHashMB := flag.Int("ioc-max-hash-mb", 100, "Max file size in MB for IOC hash computation (default: 100)")
	suppressConfig := flag.String("suppress-config", "", "Path to user suppression rules YAML file")
	showSuppressed := flag.Bool("show-suppressed", false, "Print suppressed findings tagged [SUPPRESSED]")
	sseOnly := flag.Bool("sse-only", false, "Run SSE-PACKAGE manifest collection only; skips all detection modules. Requires -sse-package.")
	sseWalkTimeout := flag.Duration("sse-walk-timeout", 5*time.Minute, "Per-directory walk deadline for SSE-PACKAGE dir collection")
	help := flag.Bool("h", false, "Show help")
	flag.StringVar(ssePackage, "m", "", "Custom artifact manifest file (alias: -sse-package)")

	flag.Usage = func() { printHelp() }
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Resolve mode first, needed to set the correct default for RunBodyfile.
	resolvedMode, known := resolveMode(*mode)
	if !known {
		fmt.Fprintf(os.Stderr, "pathfinder: unrecognized -mode %q, defaulting to full\n", *mode)
	}
	c.Mode = resolvedMode
	switch c.Mode {
	case "quick":
		c.CmdTimeout = 10 * time.Second
		c.FindTimeout = 30 * time.Second
	default:
		c.CmdTimeout = 60 * time.Second
		c.FindTimeout = 120 * time.Second
	}

	anyModule := *volatile || *users || *baseline || *persistence || *audit || *bodyfile || *deepscan || *journal
	if !anyModule {
		c.RunVolatile = true
		c.RunUsers = true
		c.RunBaseline = true
		c.RunPersistence = true
		c.RunAudit = true
		c.RunBodyfile = c.Mode == "full" // BODYFILE skipped in quick mode by default
		c.RunDeepScan = c.Mode == "full" // DEEPSCAN skipped in quick mode by default
		c.RunJournal = true
	} else {
		c.RunVolatile = *volatile
		c.RunUsers = *users
		c.RunBaseline = *baseline
		c.RunPersistence = *persistence
		c.RunAudit = *audit
		c.RunBodyfile = *bodyfile
		c.RunDeepScan = *deepscan
		c.RunJournal = *journal
	}

	if *caseID != "" {
		c.CaseID = *caseID
	} else {
		c.CaseID = fmt.Sprintf("PF-%s", time.Now().UTC().Format("20060102150405"))
	}

	c.ReportDir = *reportDir
	c.IsRoot = os.Geteuid() == 0
	c.ManifestPath = *ssePackage
	c.IOCFile = *iocFile
	c.IOCMaxHashMB = *iocMaxHashMB
	c.SuppressFile = *suppressConfig
	c.ShowSuppressed = *showSuppressed
	c.SSEOnly = *sseOnly
	c.SSEWalkTimeout = *sseWalkTimeout
	if *azSAS != "" {
		c.AzSASURL = *azSAS
	} else {
		c.AzSASURL = os.Getenv("PATHFINDER_AZ_SAS_URL")
	}
	c.OutputFormat = *outputFmt
	if outputJSONDeprecated(c.OutputFormat) {
		fmt.Fprintln(os.Stderr, "pathfinder: -output json is deprecated; findings_summary.json is always written")
	}
	c.BreachThreshold = *breachThreshold
	c.CompromiseThreshold = *compromiseThreshold
	c.Stealth = *stealth

	return c
}

func printHelp() {
	fmt.Printf(`
  %s — v%s
  Drop in. Hunt down. Collect artifacts. Get out.

  Usage: sudo %s [MODULES] [OPTIONS]

  Modules (combinable; all run if none specified):
    -volatile     Scan volatile process and memory space
    -users        Collect user artifact trace
    -baseline     Audit system baseline and network config
    -persistence  Collect persistence mechanisms and scheduled tasks
    -audit        Audit security config and auth logs
    -bodyfile     Run filesystem timeline analysis (skipped in quick mode by default)
    -deepscan     Run the Pathfinder threat-hunt engine (skipped in quick mode by default)
    -journal      Collect and analyze systemd journal

  Options:
    -mode <full|quick>       Scan mode — full (default) or quick (10s timeouts)
    -output <text>           Output format: text (default). -output json is deprecated (prints a notice to stderr)
    -breach-threshold N      HIGH finding count to trigger BREACH verdict (default: 50)
    -compromise-threshold N  Minimum HIGH count to trigger RISK DETECTED verdict (default: 10)
    -stealth                 Suppress all stdout except final verdict and archive path
    -case-id                 Assign a case / incident identifier
    -report-dir              Output directory (default: /tmp)
    -sse-package / -m        Custom artifact manifest file (one path per line)
    -ioc                     Custom IOC file (commands/filenames/processes/domains/ips/hashes)
    -ioc-max-hash-mb N       Max file size in MB for IOC hash computation (default: 100)
    -suppress-config <file>  Path to user suppression rules YAML file
    -show-suppressed         Print suppressed findings tagged [SUPPRESSED]
    -sse-only                Run SSE-PACKAGE manifest collection only; skips all detection
                             modules. Requires -sse-package / -m.
    -azure-sas-url           Azure container-scoped SAS URL (env: PATHFINDER_AZ_SAS_URL)
    -h                       Show this help

`, BuildName, Version, BinaryName)
}
