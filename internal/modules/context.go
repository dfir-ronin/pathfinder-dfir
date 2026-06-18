package modules

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pathfinder/internal/cloud"
	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

const (
	sshBruteForceHighThreshold   = 100
	sshBruteForceMediumThreshold = 20

	// maxEvidenceFileBytes caps a single config/text evidence read. Forensic
	// config files are KB-scale; this ceiling stops a planted multi-GB file
	// from OOM-killing the run mid-collection.
	maxEvidenceFileBytes = 10 << 20 // 10 MiB
)

// Dirs holds the module output directories and the base path
type Dirs struct {
	Base        string
	Baseline    string
	Volatile    string
	Persistence string
	Users       string
	Audit       string
	Journal     string
	DeepScan    string
	Bodyfile    string
	IOC         string
}

// ModuleContext is passed to every module function
type ModuleContext struct {
	Cfg          *config.Config
	Dirs         Dirs
	Registry     *output.Registry
	Log          *output.MasterLog
	Uploader     cloud.Uploader // nil when cloud upload is disabled
	IOC          *ioc.IOCSet    // nil when -ioc flag is not set
	SelfPath     string         // resolved path of this binary; modules skip scanning it
	OutputPrefix string         // prefix shared by all Pathfinder output files/dirs; modules skip scanning it
	// ZipWriter, when non-nil, causes newSectionWriter to stream entries directly
	// into the zip archive instead of writing to disk files.
	ZipWriter *zip.Writer
	// SSE-PACKAGE streaming results, populated by RunSSEPackage when ManifestPath is set.
	SSEZipPath   string
	SSEZipSHA256 string
	SSEArtifacts int
	SSECollected int
	SSESkipped   int

	procSnapshot []*procfs.Process // shared read-only /proc snapshot, populated once via procOnce
	procOnce     sync.Once
}

// Processes returns a single shared /proc snapshot for the run, populated
// exactly once on first call. The returned slice is read-only; callers must
// not mutate it or its elements. Stealth mode runs several modules as
// concurrent goroutines (see main stealth branch), so the lazy population is
// guarded by sync.Once to stay race-free; the snapshot is computed once even
// if the underlying read returned nothing.
func (ctx *ModuleContext) Processes() []*procfs.Process {
	ctx.procOnce.Do(func() {
		procs, _ := procfs.ListProcesses()
		ctx.procSnapshot = procs
	})
	return ctx.procSnapshot
}

// NewModuleContext creates the directory tree and returns a context
func NewModuleContext(cfg *config.Config) (*ModuleContext, error) {
	stamp := fmt.Sprintf("%s-%s",
		sanitizeHostname(),
		time.Now().UTC().Format("20060102_150405"))
	base := filepath.Join(cfg.ReportDir, "pathfinder-"+stamp)

	dirs := Dirs{
		Base:        base,
		Baseline:    filepath.Join(base, "baseline"),
		Volatile:    filepath.Join(base, "volatile"),
		Persistence: filepath.Join(base, "persistence"),
		Users:       filepath.Join(base, "users"),
		Audit:       filepath.Join(base, "audit"),
		Journal:     filepath.Join(base, "journal"),
		DeepScan:    filepath.Join(base, "deepscan"),
		Bodyfile:    filepath.Join(base, "bodyfile"),
		IOC:         filepath.Join(base, "ioc"),
	}

	dirList := []string{
		dirs.Baseline, dirs.Volatile, dirs.Persistence, dirs.Users,
		dirs.Audit, dirs.Journal, dirs.DeepScan, dirs.Bodyfile, dirs.IOC,
	}
	for _, d := range dirList {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	logPath := filepath.Join(base, "commands.log")
	log, err := output.NewMasterLog(logPath)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}

	ctx := &ModuleContext{
		Cfg:      cfg,
		Dirs:     dirs,
		Registry: output.NewRegistry(),
		Log:      log,
	}

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			ctx.SelfPath = resolved
		} else {
			ctx.SelfPath = exe
		}
	}
	ctx.OutputPrefix = filepath.Join(cfg.ReportDir, "pathfinder-")

	return ctx, nil
}

func sanitizeHostname() string {
	h, _ := os.Hostname()
	r := strings.NewReplacer(" ", "_", "/", "_", "\\", "_")
	return r.Replace(h)
}

// newSectionWriter creates a Writer for a module output file, writes the standard
// header, and hooks the Azure uploader if one is configured.
func newSectionWriter(ctx *ModuleContext, dir, filename, label, source string) *output.Writer {
	path := filepath.Join(dir, filename)

	if ctx.ZipWriter != nil {
		entryName := zipEntryName(ctx.Dirs.Base, path)
		hdr := &zip.FileHeader{
			Name:     entryName,
			Method:   zip.Deflate,
			Modified: time.Now(),
		}
		// Buffer all writes; flush to a single zip entry on Close.
		// archive/zip requires each entry to be fully written before the next
		// CreateHeader call. Creating entries upfront (before content is ready)
		// closes the previous entry's writer, silently discarding all subsequent
		// writes via fmt.Fprintf's ignored error return.
		buf := new(bytes.Buffer)
		w := output.NewWriterFromIO(buf)
		w.WriteHeader(label, source)
		ctx.Log.Log("section", "open", entryName)
		zipW := ctx.ZipWriter
		w.SetOnClose(func(_ string) {
			fw, err := zipW.CreateHeader(hdr)
			if err != nil {
				output.Warn(fmt.Sprintf("cannot create zip entry %s: %v", entryName, err))
				return
			}
			buf.WriteTo(fw)
		})
		return w
	}

	w, err := output.NewWriter(path)
	if err != nil {
		output.Warn(fmt.Sprintf("cannot create %s: %v", path, err))
		w2, _ := output.NewWriter(os.DevNull)
		return w2
	}
	w.WriteHeader(label, source)
	ctx.Log.Log("section", "open", path)
	// Per-file upload removed: SAS upload sends only final artifacts (see main.go).
	return w
}

// newSectionWriterWithBuf is like newSectionWriter but in zip mode uses the
// caller-supplied buf as the backing store instead of allocating a new
// bytes.Buffer. This lets the caller share the same buffer for both output and
// downstream in-process analysis, avoiding the double-buffer peak that would
// otherwise occur when the caller also needs the content for analysis.
// buf is ignored when ZipWriter is nil (disk path writes directly to a file).
func newSectionWriterWithBuf(ctx *ModuleContext, dir, filename, label, source string, buf *bytes.Buffer) *output.Writer {
	if ctx.ZipWriter == nil {
		return newSectionWriter(ctx, dir, filename, label, source)
	}
	path := filepath.Join(dir, filename)
	entryName := zipEntryName(ctx.Dirs.Base, path)
	hdr := &zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	w := output.NewWriterFromIO(buf)
	w.WriteHeader(label, source)
	ctx.Log.Log("section", "open", entryName)
	zipW := ctx.ZipWriter
	w.SetOnClose(func(_ string) {
		fw, err := zipW.CreateHeader(hdr)
		if err != nil {
			output.Warn(fmt.Sprintf("cannot create zip entry %s: %v", entryName, err))
			return
		}
		buf.WriteTo(fw)
	})
	return w
}

// zipEntryName returns the zip entry path for absPath, relative to the parent
// of base. Produces entries like "<stamp>/volatile/processes.txt".
func zipEntryName(base, absPath string) string {
	rel, err := filepath.Rel(filepath.Dir(base), absPath)
	if err != nil {
		// Only reachable if base and absPath are on different volumes (Windows).
		// This tool targets Linux; all paths share the same root.
		return filepath.Base(absPath)
	}
	return filepath.ToSlash(rel)
}

// readEvidenceFile reads a config/text evidence file without updating atime, capped at maxEvidenceFileBytes.
// It is a drop-in for os.ReadFile across the collection modules. When the
// file exceeds the cap the read is truncated and the event is recorded in
// commands.log -- a capped read must never silently shorten evidence.
func readEvidenceFile(ctx *ModuleContext, path string) ([]byte, error) {
	data, trunc, err := osutil.ReadFileCapped(path, maxEvidenceFileBytes)
	if err != nil {
		return nil, err
	}
	if trunc {
		ctx.Log.Log("read", "truncated", fmt.Sprintf("%s exceeded %d bytes", path, maxEvidenceFileBytes))
		output.Warn(fmt.Sprintf("evidence file truncated at %d bytes: %s", maxEvidenceFileBytes, path))
	}
	return data, nil
}

// walkFiles walks a directory tree, calling fn for each regular file.
// Skips /proc, /sys, /run, /dev, ctx.SelfPath, and user-supplied input files
// (cfg.SuppressFile, cfg.ManifestPath, cfg.IOCFile).
func walkFiles(ctx *ModuleContext, root string, fn func(path string, info os.FileInfo)) {
	skip := map[string]bool{
		"/proc": true, "/sys": true, "/run": true, "/dev": true,
	}

	userFiles := map[string]bool{}
	for _, p := range []string{ctx.Cfg.SuppressFile, ctx.Cfg.ManifestPath, ctx.Cfg.IOCFile} {
		if p != "" {
			if abs, err := filepath.Abs(p); err == nil {
				userFiles[abs] = true
			}
		}
	}

	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if skip[path] {
			return filepath.SkipDir
		}
		if ctx.SelfPath != "" && path == ctx.SelfPath {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if userFiles[path] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		fn(path, info)
		return nil
	})
}

// execFallback runs an external binary with a timeout and returns combined output.
func execFallback(ctx *ModuleContext, name string, args ...string) (string, error) {
	return execWithTimeout(ctx.Cfg.CmdTimeout, name, args...)
}

// copyFileNoAtime copies src to dst using O_NOATIME to avoid updating evidence timestamps.
// After copying, the destination's mtime and atime are stamped to match the source.
func copyFileNoAtime(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	in, err := osutil.OpenNoAtime(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if fi, err := os.Stat(src); err == nil {
		atime := fi.ModTime()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			atime = time.Unix(st.Atim.Sec, st.Atim.Nsec)
		}
		os.Chtimes(dst, atime, fi.ModTime())
	}
	return nil
}
