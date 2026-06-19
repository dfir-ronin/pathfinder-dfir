package archive

import (
	"archive/zip"
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FlushDirToZip walks srcDir and writes its contents as entries into an already-open zw.
// baseDir is the ancestor directory used to compute relative entry names. It returns the
// list of source paths that could not be read into the archive (e.g. permission denied),
// so callers can record the gap in the manifest instead of losing evidence silently. A
// non-nil error means a write into the zip itself failed and the archive cannot be trusted.
func FlushDirToZip(zw *zip.Writer, srcDir, baseDir string) ([]string, error) {
	var skipped []string
	err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			skipped = append(skipped, path)
			return nil
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			skipped = append(skipped, path)
			return nil
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if !strings.HasSuffix(rel, "/") {
				rel += "/"
			}
			info, err := d.Info()
			if err != nil {
				skipped = append(skipped, path)
				return nil
			}
			hdr, err := zip.FileInfoHeader(info)
			if err != nil {
				skipped = append(skipped, path)
				return nil
			}
			hdr.Name = rel
			hdr.Method = zip.Store
			_, err = zw.CreateHeader(hdr)
			return err // a CreateHeader failure is a zip-write failure: fatal
		}

		info, err := d.Info()
		if err != nil {
			skipped = append(skipped, path)
			return nil
		}

		mode := info.Mode()

		// Symlinks: never follow. os.Open(path) would read the TARGET's bytes
		// (info-leak: a link named notes.txt -> /etc/shadow exfiltrates shadow),
		// block forever on a FIFO target, or read unbounded on a device. Store the
		// link itself as a symlink entry whose content is the target path, so the
		// artifact and its target are preserved as evidence without reading it.
		if mode&os.ModeSymlink != 0 {
			target, rlErr := os.Readlink(path)
			if rlErr != nil {
				skipped = append(skipped, fmt.Sprintf("%s (unreadable symlink)", path))
				return nil
			}
			hdr, err := zip.FileInfoHeader(info) // SetMode carries ModeSymlink bits
			if err != nil {
				skipped = append(skipped, path)
				return nil
			}
			hdr.Name = rel
			hdr.Method = zip.Store
			fw, err := zw.CreateHeader(hdr)
			if err != nil {
				return err // zip-write failure: fatal
			}
			_, wErr := fw.Write([]byte(target))
			return wErr
		}

		// Devices, sockets, named pipes: opening these can block (FIFO) or read
		// unbounded (/dev/zero). They carry no file content worth archiving.
		// Record the gap in the manifest skip list and move on without opening.
		if !mode.IsRegular() {
			skipped = append(skipped, fmt.Sprintf("%s (non-regular: %s)", path, mode.Type().String()))
			return nil
		}

		// Open the source BEFORE creating the header. If the file is unreadable we
		// skip it without leaving a phantom zero-byte entry that VerifyZip would pass.
		src, err := os.Open(path)
		if err != nil {
			skipped = append(skipped, path)
			return nil
		}

		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			src.Close()
			skipped = append(skipped, path)
			return nil
		}
		hdr.Name = rel
		hdr.Method = zip.Deflate

		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			src.Close()
			return err // zip-write failure: fatal
		}

		_, copyErr := io.Copy(fw, src)
		// Close per iteration: a deferred close inside WalkDir would leak fds until the
		// entire tree is walked and can exhaust ulimit -n on large collections.
		src.Close()
		return copyErr
	})
	return skipped, err
}

// VerifyZip opens the zip and reads every entry to completion, forcing the
// archive/zip reader to validate each entry's CRC-32. It returns the number of
// file entries. An error means the archive is unreadable, truncated, or has a
// corrupt entry and must not be trusted as the sole evidence copy.
func VerifyZip(zipPath string) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 0, fmt.Errorf("verify open %s: %w", f.Name, err)
		}
		// Draining the reader triggers the CRC-32 check inside archive/zip;
		// a mismatch or short read surfaces here instead of being silently kept.
		if _, err := io.Copy(io.Discard, rc); err != nil {
			rc.Close()
			return 0, fmt.Errorf("verify read %s: %w", f.Name, err)
		}
		rc.Close()
	}
	return len(zr.File), nil
}

// ManifestParams carries all fields written to the acquisition manifest.
type ManifestParams struct {
	CaseID         string
	Examiner       string
	Notes          string
	Hostname       string
	OS             string
	Kernel         string
	Arch           string
	CPU            string
	Memory         string
	Timezone       string
	IPs            []string
	Mounts         []string
	StartTime      time.Time
	EndTime        time.Time
	Mode           string
	ManifestPath   string
	IOCFile        string
	SuppressFile   string
	Stealth        bool
	Artifacts      int
	Collected      int
	Skipped        int
	ArchiveSkipped []string // source files that could not be read into the main zip
	MainZipPath    string
	MainZipSize    int64
	MainZipMD5     string
	MainZipSHA256  string
	SSEZipPath     string
	SSEZipSize     int64
	SSEZipSHA256   string
}

// WriteManifest writes a plain-text acquisition manifest to path.
func WriteManifest(path string, p ManifestParams) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	none := func(s string) string {
		if s == "" {
			return "(none)"
		}
		return s
	}

	fmt.Fprintf(w, "PATHFINDER ACQUISITION MANIFEST\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("=", 32))
	fmt.Fprintf(w, "Generated:     %s\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(w, "[Case]\n")
	fmt.Fprintf(w, "Case ID:       %s\n", p.CaseID)
	fmt.Fprintf(w, "Examiner:      %s\n", p.Examiner)
	fmt.Fprintf(w, "Notes:         %s\n\n", none(p.Notes))

	fmt.Fprintf(w, "[System]\n")
	fmt.Fprintf(w, "Hostname:      %s\n", p.Hostname)
	if p.OS != "" {
		fmt.Fprintf(w, "OS:            %s\n", p.OS)
	}
	if p.Kernel != "" {
		fmt.Fprintf(w, "Kernel:        %s\n", p.Kernel)
	}
	if p.Arch != "" {
		fmt.Fprintf(w, "Arch:          %s\n", p.Arch)
	}
	if p.CPU != "" {
		fmt.Fprintf(w, "CPU:           %s\n", p.CPU)
	}
	if p.Memory != "" {
		fmt.Fprintf(w, "Memory:        %s\n", p.Memory)
	}
	if p.Timezone != "" {
		fmt.Fprintf(w, "Timezone:      %s\n", p.Timezone)
	}
	if len(p.IPs) > 0 {
		fmt.Fprintf(w, "IPs:           %s\n", strings.Join(p.IPs, ", "))
	}
	for i, mt := range p.Mounts {
		if i == 0 {
			fmt.Fprintf(w, "Mounts:        %s\n", mt)
		} else {
			fmt.Fprintf(w, "               %s\n", mt)
		}
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "[Acquisition]\n")
	fmt.Fprintf(w, "Started:       %s\n", p.StartTime.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Completed:     %s\n", p.EndTime.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Mode:          %s\n", p.Mode)
	fmt.Fprintf(w, "Manifest:      %s\n", none(p.ManifestPath))
	fmt.Fprintf(w, "IOC file:      %s\n", none(p.IOCFile))
	fmt.Fprintf(w, "Suppress file: %s\n", none(p.SuppressFile))
	fmt.Fprintf(w, "Flags:         -stealth=%v\n", p.Stealth)
	fmt.Fprintf(w, "Artifacts:     %d\n", p.Artifacts)
	fmt.Fprintf(w, "Collected:     %d files\n", p.Collected)
	fmt.Fprintf(w, "Skipped:       %d files\n\n", p.Skipped)
	if len(p.ArchiveSkipped) > 0 {
		fmt.Fprintf(w, "Unreadable (not archived): %d files\n", len(p.ArchiveSkipped))
		for _, s := range p.ArchiveSkipped {
			fmt.Fprintf(w, "  - %s\n", s)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "[Archives]\n")
	fmt.Fprintf(w, "Main:          %-45s (%s)\n", filepath.Base(p.MainZipPath), formatSize(p.MainZipSize))
	fmt.Fprintf(w, "  MD5:         %s\n", p.MainZipMD5)
	fmt.Fprintf(w, "  SHA-256:     %s\n", p.MainZipSHA256)

	if p.SSEZipPath != "" {
		fmt.Fprintf(w, "\nSSE:           %-45s (%s)\n", filepath.Base(p.SSEZipPath), formatSize(p.SSEZipSize))
		fmt.Fprintf(w, "  SHA-256:     %s   <- authoritative\n", p.SSEZipSHA256)
	}

	fmt.Fprintf(w, "\nNote: MD5 provided for legacy tool compatibility only. SHA-256 is authoritative.\n")

	return w.Flush()
}

func formatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// FileHashes returns the hex MD5 and SHA-256 digests of the file at path in one pass
func FileHashes(path string) (md5sum, sha256sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	md5h := md5.New()
	sha256h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5h, sha256h), f); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%x", md5h.Sum(nil)), fmt.Sprintf("%x", sha256h.Sum(nil)), nil
}
