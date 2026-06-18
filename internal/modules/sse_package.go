// internal/modules/sse_package.go
package modules

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
)

const sseRootDir = "[root_dir]"

type sseFilterOpts struct {
	MaxDepth           int
	NamePattern        []string
	ExcludeNamePattern []string
	PathPattern        []string
	ExcludePathPattern []string
	MaxFileSize        int64 // 0 = no limit
	FileType           []string
}

type sseLogEntry struct {
	path   string
	reason string
}

type sseArtifactLog struct {
	name             string
	collected        int
	skippedByReason  map[string]int
	errors           []sseLogEntry
	followedSymlinks []sseLogEntry // path = link, reason = "-> " + resolvedTarget
}

func newSseArtifactLog(name string) sseArtifactLog {
	return sseArtifactLog{name: name, skippedByReason: map[string]int{}}
}

func writeArtifactBlock(w *bufio.Writer, al sseArtifactLog) {
	totalSkipped := 0
	for _, n := range al.skippedByReason {
		totalSkipped += n
	}

	fmt.Fprintf(w, "=== ARTIFACT: %s ===\n", al.name)
	fmt.Fprintf(w, "  Collected : %d\n", al.collected)
	fmt.Fprintf(w, "  Skipped   : %d\n", totalSkipped)

	if totalSkipped > 0 {
		type rc struct {
			reason string
			count  int
		}
		var reasons []rc
		for r, n := range al.skippedByReason {
			reasons = append(reasons, rc{r, n})
		}
		sort.Slice(reasons, func(i, j int) bool {
			if reasons[i].count != reasons[j].count {
				return reasons[i].count > reasons[j].count
			}
			return reasons[i].reason < reasons[j].reason
		})
		for _, r := range reasons {
			fmt.Fprintf(w, "    %d  %s\n", r.count, r.reason)
		}
	}

	fmt.Fprintf(w, "  Errors    : %d\n", len(al.errors))
	for _, e := range al.errors {
		fmt.Fprintf(w, "    %s — %s\n", e.path, e.reason)
	}
	if len(al.followedSymlinks) > 0 {
		fmt.Fprintf(w, "  Followed symlinks : %d\n", len(al.followedSymlinks))
		for _, e := range al.followedSymlinks {
			fmt.Fprintf(w, "    %s %s\n", e.path, e.reason)
		}
	}
	fmt.Fprintln(w)
}

func containsLinuxOS(oses []string) bool {
	for _, o := range oses {
		if strings.EqualFold(o, "linux") || strings.EqualFold(o, "all") {
			return true
		}
	}
	return false
}

// RunSSEPackage collects artifacts defined in an operator-supplied YAML manifest.
func RunSSEPackage(ctx *ModuleContext) {
	if ctx.Cfg.ManifestPath == "" {
		return
	}

	var m *sseManifest
	var err error
	if fi, statErr := os.Stat(ctx.Cfg.ManifestPath); statErr == nil && fi.IsDir() {
		m, err = loadManifestDir(ctx.Cfg.ManifestPath)
	} else {
		m, err = loadManifest(ctx.Cfg.ManifestPath)
	}
	if err != nil {
		output.Warn(fmt.Sprintf("sse-package: invalid manifest %s — %v", ctx.Cfg.ManifestPath, err))
		return
	}

	if len(m.Artifacts) == 0 {
		return
	}

	output.Chapter("[SSE-PACKAGE] Custom manifest detected. Expanding collection parameters...")
	ctx.Log.Log("sse-package", "manifest", fmt.Sprintf("%d artifacts from %s", len(m.Artifacts), ctx.Cfg.ManifestPath))

	sseLogPath := ctx.Dirs.Base + "-sse-log.txt"
	var lw *bufio.Writer
	if logFile, err := os.Create(sseLogPath); err != nil {
		sseLogPath = ""
		lw = bufio.NewWriter(io.Discard)
	} else {
		lw = bufio.NewWriter(logFile)
		defer func() { lw.Flush(); logFile.Close() }()
	}

	sseZipPath := ctx.Dirs.Base + "-sse.zip"
	f, err := os.Create(sseZipPath)
	if err != nil {
		output.Warn(fmt.Sprintf("sse-package: cannot create archive %s — %v", sseZipPath, err))
		return
	}
	sha256h := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(f, sha256h))

	var maxTotalBytes int64
	if m.MaxTotalSize != "" {
		sz, parseErr := parseFileSize(m.MaxTotalSize)
		if parseErr != nil {
			output.Warn(fmt.Sprintf("sse-package: invalid max_total_size %q — ignoring limit", m.MaxTotalSize))
		} else {
			maxTotalBytes = sz
		}
	}
	var totalBytes int64
	limitReached := false

	collected, skipped, totalLogErrors := 0, 0, 0

	for _, artifact := range m.Artifacts {
		if len(artifact.SupportedOS) > 0 && !containsLinuxOS(artifact.SupportedOS) {
			continue
		}
		if artifact.Collector != "file" {
			fmt.Fprintf(lw, "[!] artifact %q — skipped: unsupported collector: %s\n", artifact.Description, artifact.Collector)
			continue
		}
		if len(artifact.Path) == 0 {
			fmt.Fprintf(lw, "[!] artifact %q — skipped: missing path\n", artifact.Description)
			continue
		}

		if strings.Contains(artifact.OutputDirectory, "..") || strings.Contains(artifact.OutputFile, "..") {
			output.Warn(fmt.Sprintf("sse-package: manifest field contains '..' (sanitized): output_directory=%q output_file=%q",
				artifact.OutputDirectory, artifact.OutputFile))
		}

		var maxFileSize int64
		if artifact.MaxFileSize != "" {
			sz, parseErr := parseFileSize(artifact.MaxFileSize)
			if parseErr != nil {
				fmt.Fprintf(lw, "[!] artifact %q — skipped: invalid max_file_size: %s\n", artifact.Description, artifact.MaxFileSize)
				continue
			}
			maxFileSize = sz
		}
		opts := sseFilterOpts{
			MaxDepth:           artifact.MaxDepth,
			NamePattern:        artifact.NamePattern,
			ExcludeNamePattern: artifact.ExcludeNamePattern,
			MaxFileSize:        maxFileSize,
			ExcludePathPattern: artifact.ExcludePathPattern,
			PathPattern:        artifact.PathPattern,
			FileType:           artifact.FileType,
		}

		targets := resolveTargets(artifact.Path, "/etc/passwd")
		if len(targets) == 0 {
			hasUserHome := false
			for _, token := range artifact.Path {
				if strings.Contains(token, uacUserHomePlaceholder) {
					hasUserHome = true
					break
				}
			}
			if hasUserHome {
				if len(readHomeDirs("/etc/passwd")) == 0 {
					fmt.Fprintf(lw, "[!] artifact %q — skipped: %%user_home%% expanded to zero users\n", artifact.Description)
				} else {
					fmt.Fprintf(lw, "[~] artifact %q — no files matched\n", artifact.Description)
				}
			} else {
				fmt.Fprintf(lw, "[~] artifact %q — no paths resolved\n", artifact.Description)
			}
			continue
		}

		// isMulti guards outputFile to prevent N resolved paths writing to the same entry name.
		// Based on resolved path count so a single glob expanding to multiple targets
		// is treated as multi correctly.
		isMulti := len(targets) > 1
		al := newSseArtifactLog(artifact.Description)

		for _, rt := range targets {
			target := rt.path
			fi, err := os.Lstat(target)
			if err != nil {
				al.errors = append(al.errors, sseLogEntry{path: target, reason: err.Error()})
				skipped++
				continue
			}

			if !fi.IsDir() && opts.MaxFileSize > 0 && fi.Size() > opts.MaxFileSize {
				al.skippedByReason["exceeds max_file_size"]++
				skipped++
				continue
			}

			if fi.IsDir() {
				prevCollected := al.collected
				var walkDeadline time.Time
				if ctx.Cfg.SSEWalkTimeout > 0 {
					walkDeadline = time.Now().Add(ctx.Cfg.SSEWalkTimeout)
				}
				s := collectDirArtifact(ctx, target, artifact.OutputDirectory, opts, zw, &al, maxTotalBytes, &totalBytes, walkDeadline)
				collected += al.collected - prevCollected
				skipped += s
				if al.skippedByReason["total size limit reached"] > 0 {
					limitReached = true
				}
			} else if !fi.Mode().IsRegular() && fi.Mode()&os.ModeSymlink == 0 {
				al.skippedByReason["unsupported file type"]++
				skipped++
			} else {
				if maxTotalBytes > 0 && totalBytes+fi.Size() > maxTotalBytes {
					al.skippedByReason["total size limit reached"]++
					skipped++
					limitReached = true
					continue
				}
				// Symlink: glob/wildcard matches are contained to their glob base;
				// a literal operator-named path may follow cross-tree. Never follow
				// into a non-regular target.
				if fi.Mode()&os.ModeSymlink != 0 {
					real, ok, reason := symlinkDereferenceAllowed(target, rt.globBase, rt.fromGlob)
					if !ok {
						al.skippedByReason[reason]++
						skipped++
						continue
					}
					al.followedSymlinks = append(al.followedSymlinks, sseLogEntry{path: target, reason: "-> " + real})
				}
				rel := filepath.Base(target)
				if artifact.OutputFile != "" && !isMulti {
					rel = artifact.OutputFile
				}
				entryName := entryNameForPath(target, rel, artifact.OutputDirectory)
				if err := copyFileToZipEntry(target, zw, entryName); err != nil {
					al.errors = append(al.errors, sseLogEntry{path: target, reason: "copy failed: " + err.Error()})
					skipped++
				} else {
					collected++
					al.collected++
					ctx.Log.Log("sse-package", "file", target)
					totalBytes += fi.Size()
				}
			}
		}

		writeArtifactBlock(lw, al)
		totalLogErrors += len(al.errors)
	}

	fmt.Fprintf(lw, "=== TOTAL: %d collected | %d skipped | %d errors ===\n", collected, skipped, totalLogErrors)

	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(sseZipPath)
		output.Warn(fmt.Sprintf("sse-package: archive finalization failed — %v", err))
		return
	}
	f.Close()

	zr, verifyErr := zip.OpenReader(sseZipPath)
	if verifyErr != nil {
		os.Remove(sseZipPath)
		output.Warn("sse-package: archive verification failed — output removed")
		return
	}
	count := len(zr.File)
	zr.Close()
	if count == 0 {
		os.Remove(sseZipPath)
		if sseLogPath != "" {
			os.Remove(sseLogPath)
		}
		output.Warn("sse-package: archive is empty — output removed")
		return
	}

	ctx.SSEZipPath = sseZipPath
	ctx.SSEZipSHA256 = fmt.Sprintf("%x", sha256h.Sum(nil))
	ctx.SSEArtifacts = len(m.Artifacts)
	ctx.SSECollected = collected
	ctx.SSESkipped = skipped

	if ctx.Uploader != nil {
		ctx.Uploader.Upload(sseZipPath)
	}

	okMsg := fmt.Sprintf("SSE-Package: %d files collected (%d skipped) → %s", collected, skipped, sseZipPath)
	if limitReached {
		okMsg += " | size limit reached"
	}
	if sseLogPath != "" {
		okMsg += " | log → " + sseLogPath
	}
	output.Ok(okMsg)
}

// collectDirArtifact streams a source directory into zw with optional filtering.
// If outputDirectory is set, files land under outputDirectory/ (source prefix stripped).
// Otherwise the full source path is mirrored.
func collectDirArtifact(ctx *ModuleContext, src, outputDirectory string, opts sseFilterOpts, zw *zip.Writer, al *sseArtifactLog, maxTotalBytes int64, totalBytes *int64, deadline time.Time) (skipped int) {
	src = filepath.Clean(src)
	sep := string(os.PathSeparator)
	startCollected := al.collected

	var pathPatternREs []*regexp.Regexp
	for _, pat := range opts.PathPattern {
		if re := shellGlobToRegexp(pat); re != nil {
			pathPatternREs = append(pathPatternREs, re)
		}
	}

	var timedOut bool
	filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if !deadline.IsZero() && time.Now().After(deadline) {
			timedOut = true
			return filepath.SkipAll
		}
		if walkErr != nil {
			if d == nil || d.IsDir() {
				al.errors = append(al.errors, sseLogEntry{path: path, reason: walkErr.Error()})
			} else {
				skipped++
				al.skippedByReason["walk error"]++
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if rel != "." && len(opts.ExcludePathPattern) > 0 && isExcludedPath(path, opts.ExcludePathPattern) {
				return filepath.SkipDir
			}
			if rel != "." && opts.MaxDepth > 0 && strings.Count(rel, sep) >= opts.MaxDepth-1 {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip special files (FIFOs, sockets, devices): opening them without O_NONBLOCK
		// blocks indefinitely when no writer/reader is present on the other end.
		if !d.Type().IsRegular() && d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		if len(opts.FileType) > 0 {
			allowed := false
			for _, ft := range opts.FileType {
				switch ft {
				case "f":
					if d.Type().IsRegular() {
						allowed = true
					}
				case "l":
					if d.Type()&fs.ModeSymlink != 0 {
						allowed = true
					}
				}
				if allowed {
					break
				}
			}
			if !allowed {
				skipped++
				al.skippedByReason["unsupported file type"]++
				return nil
			}
		}

		name := filepath.Base(path)

		if len(opts.NamePattern) > 0 {
			matched := false
			for _, p := range opts.NamePattern {
				if ok, _ := filepath.Match(p, name); ok {
					matched = true
					break
				}
			}
			if !matched {
				skipped++
				al.skippedByReason["excluded by name pattern"]++
				return nil
			}
		}

		for _, p := range opts.ExcludeNamePattern {
			if ok, _ := filepath.Match(p, name); ok {
				skipped++
				al.skippedByReason["excluded by name pattern"]++
				return nil
			}
		}

		if len(opts.ExcludePathPattern) > 0 && isExcludedPath(filepath.Dir(path), opts.ExcludePathPattern) {
			skipped++
			al.skippedByReason["excluded by path pattern"]++
			return nil
		}

		if len(pathPatternREs) > 0 {
			matched := false
			for _, re := range pathPatternREs {
				if re.MatchString(path) {
					matched = true
					break
				}
			}
			if !matched {
				skipped++
				al.skippedByReason["excluded by path pattern"]++
				return nil
			}
		}

		if opts.MaxFileSize > 0 {
			if fi, err := d.Info(); err == nil && fi.Size() > opts.MaxFileSize {
				skipped++
				al.skippedByReason["exceeds max_file_size"]++
				return nil
			}
		}

		if maxTotalBytes > 0 && totalBytes != nil {
			if fi, infoErr := d.Info(); infoErr == nil && *totalBytes+fi.Size() > maxTotalBytes {
				skipped++
				al.skippedByReason["total size limit reached"]++
				return nil
			}
		}

		entryName := entryNameForPath(path, rel, outputDirectory)

		// Symlinks: contain to the collection root and never follow into a
		// non-regular target. In-scope regular targets are dereferenced as before.
		if d.Type()&fs.ModeSymlink != 0 {
			if _, ok, reason := symlinkDereferenceAllowed(path, src, true); !ok {
				skipped++
				al.skippedByReason[reason]++
				return nil
			}
			real, _ := filepath.EvalSymlinks(path)
			al.followedSymlinks = append(al.followedSymlinks, sseLogEntry{path: path, reason: "-> " + real})
		}

		if err := copyFileToZipEntry(path, zw, entryName); err == nil {
			al.collected++
			ctx.Log.Log("sse-package", "file", path)
			if maxTotalBytes > 0 && totalBytes != nil {
				if fi, infoErr := d.Info(); infoErr == nil {
					*totalBytes += fi.Size()
				}
			}
		} else {
			skipped++
			al.errors = append(al.errors, sseLogEntry{path: path, reason: "copy failed: " + err.Error()})
		}
		return nil
	})

	if timedOut {
		al.errors = append(al.errors, sseLogEntry{path: src, reason: "walk deadline exceeded - collection truncated"})
	}

	ctx.Log.Log("sse-package", "dir", fmt.Sprintf("%s → %d files", src, al.collected-startCollected))
	return
}

// isExcludedPath reports whether path matches or is a descendant of any pattern.
// Matching is exact or directory-prefix only -- not glob. Patterns must be absolute
// directory paths (e.g. "/proc", "/var/cache"). For glob-based filtering use
// path_pattern or exclude_name_pattern instead.
// Both sides are cleaned with filepath.Clean before comparison.
func isExcludedPath(path string, patterns []string) bool {
	path = filepath.Clean(path)
	for _, p := range patterns {
		p = filepath.Clean(p)
		if path == p || strings.HasPrefix(path, p+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// shellGlobToRegexp compiles a UAC path_pattern glob to a regexp.
// Unlike filepath.Match, * matches any character sequence including /.
// Returns nil if the pattern is invalid.
func shellGlobToRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, c := range pattern {
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// loadManifestDir walks dir recursively and merges all .yaml/.yml manifests into one.
// Per-file parse errors and inaccessible entries are silently skipped.
// Returns a non-nil error only if the directory cannot be walked.
func loadManifestDir(dir string) (*sseManifest, error) {
	merged := &sseManifest{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		m, loadErr := loadManifest(path)
		if loadErr != nil {
			output.Warn(fmt.Sprintf("sse-package: skipping invalid manifest %s — %v", path, loadErr))
			return nil
		}
		merged.Artifacts = append(merged.Artifacts, m.Artifacts...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return merged, nil
}

// symlinkDereferenceAllowed decides whether a symlink may be followed and copied.
// It never follows into a non-regular target (closing the FIFO-hang and device-read),
// and when contained is true it requires the resolved target to live inside root.
// realPath is the fully resolved target; reason is the skip reason when ok is false.
func symlinkDereferenceAllowed(linkPath, root string, contained bool) (realPath string, ok bool, reason string) {
	real, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return "", false, "broken or cyclic symlink"
	}
	fi, err := os.Lstat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false, "symlink target is not a regular file"
	}
	if contained {
		rootReal, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", false, "symlink target outside collection scope"
		}
		if real != rootReal && !strings.HasPrefix(real, rootReal+string(os.PathSeparator)) {
			return "", false, "symlink target outside collection scope"
		}
	}
	return real, true, ""
}

// copyFileToZipEntry writes src into zw as a zip entry named entryName.
// Source mtime is preserved in the zip header. Source atime is not updated (O_NOATIME).
func copyFileToZipEntry(src string, zw *zip.Writer, entryName string) error {
	in, err := osutil.OpenNoAtime(src)
	if err != nil {
		return err
	}
	defer in.Close()

	fi, err := in.Stat() // fd-level stat: no race between open and stat; follows symlinks because OpenNoAtime does
	if err != nil {
		return err
	}

	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return err
	}
	hdr.Name = entryName
	hdr.Method = zip.Deflate

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, in)
	return err
}
