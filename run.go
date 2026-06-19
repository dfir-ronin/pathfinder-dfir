package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pathfinder/internal/archive"
	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/modules"
	"github.com/pathfinder/internal/output"
)

// moduleEntry binds a detection module to the config flag that enables it and,
// for staged modules, the disk dir flushed into the zip in stealth mode.
type moduleEntry struct {
	name    string
	enabled func(*config.Config) bool
	run     func(*modules.ModuleContext)
	dir     func(*modules.ModuleContext) string
}

// stagedModules run first, in Order-of-Volatility. In stealth mode they run
// concurrently and write to disk dirs that are then flushed into the zip; in
// non-stealth they run sequentially and stream directly. Order is frozen:
// findings land in registry order, which findings_summary.txt prints verbatim.
var stagedModules = []moduleEntry{
	{"volatile", func(c *config.Config) bool { return c.RunVolatile }, modules.RunVolatile, func(x *modules.ModuleContext) string { return x.Dirs.Volatile }},
	{"audit", func(c *config.Config) bool { return c.RunAudit }, modules.RunAudit, func(x *modules.ModuleContext) string { return x.Dirs.Audit }},
	{"journal", func(c *config.Config) bool { return c.RunJournal }, modules.RunJournal, func(x *modules.ModuleContext) string { return x.Dirs.Journal }},
	{"users", func(c *config.Config) bool { return c.RunUsers }, modules.RunUsers, func(x *modules.ModuleContext) string { return x.Dirs.Users }},
	{"persistence", func(c *config.Config) bool { return c.RunPersistence }, modules.RunPersistence, func(x *modules.ModuleContext) string { return x.Dirs.Persistence }},
	{"baseline", func(c *config.Config) bool { return c.RunBaseline }, modules.RunBaseline, func(x *modules.ModuleContext) string { return x.Dirs.Baseline }},
}

// streamModules run after the staged group, streaming directly into the open
// zip in both modes. sse-package has no run flag and always runs.
var streamModules = []moduleEntry{
	{"bodyfile", func(c *config.Config) bool { return c.RunBodyfile }, modules.RunBodyfile, nil},
	{"sse", func(c *config.Config) bool { return true }, modules.RunSSEPackage, nil},
	{"deepscan", func(c *config.Config) bool { return c.RunDeepScan }, modules.RunDeepScan, nil},
	{"ioc", func(c *config.Config) bool { return c.IOCFile != "" }, modules.RunIOC, nil},
}

// runModules runs the staged group then the stream group. In stealth the
// staged group runs concurrently and is flushed to the zip; in non-stealth it
// streams directly. Returns the list of files skipped during the stealth flush.
func runModules(ctx *modules.ModuleContext, cfg *config.Config, zw *zip.Writer, baseParent string) []string {
	var archiveSkipped []string

	if cfg.Stealth {
		var wg sync.WaitGroup
		for _, m := range stagedModules {
			if m.enabled(cfg) {
				wg.Add(1)
				go func() { defer wg.Done(); m.run(ctx) }()
			}
		}
		wg.Wait()

		// Flush every staged dir unconditionally (a disabled module's dir may
		// still exist); only the run above is gated.
		for _, m := range stagedModules {
			dir := m.dir(ctx)
			skips, flushErr := archive.FlushDirToZip(zw, dir, baseParent)
			archiveSkipped = append(archiveSkipped, skips...)
			if flushErr != nil {
				output.Warn(fmt.Sprintf("flush %s: %v", filepath.Base(dir), flushErr))
			}
			os.RemoveAll(dir)
		}

		ctx.ZipWriter = zw
		for _, m := range streamModules {
			if m.enabled(cfg) {
				m.run(ctx)
			}
		}
		return archiveSkipped
	}

	ctx.ZipWriter = zw
	for _, m := range stagedModules {
		if m.enabled(cfg) {
			m.run(ctx)
		}
	}
	for _, m := range streamModules {
		if m.enabled(cfg) {
			m.run(ctx)
		}
	}
	return archiveSkipped
}

func runSSEOnly(ctx *modules.ModuleContext, cfg *config.Config, host HostMeta) {
	if cfg.ManifestPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -sse-only requires -sse-package")
		os.Exit(1)
	}
	modules.RunSSEPackage(ctx)

	var sseSize int64
	if fi, statErr := os.Stat(ctx.SSEZipPath); statErr == nil {
		sseSize = fi.Size()
	}
	sseManifestPath := strings.TrimSuffix(ctx.SSEZipPath, ".zip") + "-manifest.txt"
	mp := archive.ManifestParams{
		CaseID:       cfg.CaseID,
		Examiner:     host.Operator,
		Hostname:     host.Hostname,
		OS:           host.OS,
		Kernel:       host.Kernel,
		Arch:         host.Arch,
		CPU:          host.CPU,
		Memory:       host.MemTotal,
		Timezone:     host.TimeZone,
		IPs:          host.IPs,
		Mounts:       host.Mounts,
		StartTime:    time.Now().UTC(),
		EndTime:      time.Now().UTC(),
		Mode:         cfg.Mode,
		ManifestPath: cfg.ManifestPath,
		Stealth:      cfg.Stealth,
		Artifacts:    ctx.SSEArtifacts,
		Collected:    ctx.SSECollected,
		Skipped:      ctx.SSESkipped,
		SSEZipPath:   ctx.SSEZipPath,
		SSEZipSize:   sseSize,
		SSEZipSHA256: ctx.SSEZipSHA256,
	}
	manifestOK := true
	if manifestErr := archive.WriteManifest(sseManifestPath, mp); manifestErr != nil {
		output.Warn(fmt.Sprintf("manifest write error: %v", manifestErr))
		manifestOK = false
	} else {
		output.Ok("Acquisition manifest: " + sseManifestPath)
	}
	if cfg.Stealth {
		fmt.Printf("ARCHIVE=%s\nSHA256=%s\n", ctx.SSEZipPath, ctx.SSEZipSHA256)
	}
	if !manifestOK {
		output.Warn(fmt.Sprintf("staging dir preserved for recovery: %s", ctx.Dirs.Base))
		os.Exit(1)
	}
	if removeErr := os.RemoveAll(ctx.Dirs.Base); removeErr != nil {
		output.Warn(fmt.Sprintf("could not remove staging dir %s: %v", ctx.Dirs.Base, removeErr))
	}
}
