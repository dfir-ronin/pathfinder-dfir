package modules

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"golang.org/x/sys/unix"
)

const bodyfileMD5SizeLimit = 50 * 1024 * 1024 // 50 MB

type bfStatResult struct {
	ino, mode, uid, gid        uint64
	atime, mtime, ctime, btime int64
}

func bodyfileStat(path string, fi os.FileInfo) (bfStatResult, bool) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return bfStatResult{}, false
	}
	r := bfStatResult{
		ino:   s.Ino,
		mode:  uint64(s.Mode),
		uid:   uint64(s.Uid),
		gid:   uint64(s.Gid),
		atime: s.Atim.Sec,
		mtime: s.Mtim.Sec,
		ctime: s.Ctim.Sec,
	}
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_BTIME, &stx); err == nil {
		if stx.Mask&unix.STATX_BTIME != 0 {
			r.btime = stx.Btime.Sec
		}
	}
	return r, true
}

// RunBodyfile generates a mactime-format body file for key filesystem paths,
// then runs inline analysis to flag timestomping, SUID anomalies, FHS violations,
// volatile directory activity, and deleted artifacts.
func RunBodyfile(ctx *ModuleContext) {
	output.Chapter("[BODYFILE] Building mactime body file...")
	output.Info("Output → " + filepath.Join(ctx.Dirs.Bodyfile, "bodyfile.txt"))

	var bodyBuf bytes.Buffer
	w := newSectionWriterWithBuf(ctx, ctx.Dirs.Bodyfile, "bodyfile.txt",
		"Bodyfile — mactime format", "/bin /usr/bin /etc /home /tmp /var /dev/shm", &bodyBuf)
	defer w.Close()

	w.Write("# Live collection — kernel-level rootkits may manipulate stat results.\n")
	w.Write("# MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|btime\n")

	roots := []string{"/bin", "/usr/bin", "/etc", "/home", "/tmp", "/var", "/dev/shm"}
	count, errCount := 0, 0

	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
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
			fi, err := os.Lstat(path)
			if err != nil {
				return nil
			}
			stat, ok := bodyfileStat(path, fi)
			if !ok {
				return nil
			}
			md5sum := "0"
			if fi.Mode().IsRegular() && fi.Size() <= bodyfileMD5SizeLimit {
				if h := bodyfileMD5(path); h != "" {
					md5sum = h
				} else {
					errCount++
				}
			}
			line := fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",
				md5sum, path, stat.ino, stat.mode,
				stat.uid, stat.gid, fi.Size(),
				stat.atime, stat.mtime, stat.ctime, stat.btime)
			w.WriteString(line)
			// In zip mode w.f IS bodyBuf (shared via newSectionWriterWithBuf),
			// so w.WriteString already populates it. On disk mode bodyBuf is
			// separate and needs the explicit write for in-process analysis.
			if ctx.ZipWriter == nil {
				bodyBuf.WriteString(line)
			}
			count++
			return nil
		})
	}

	output.Ok(fmt.Sprintf("Bodyfile: %d entries (%d unreadable)", count, errCount))
	ctx.Log.Log("bodyfile", "complete", fmt.Sprintf("%d entries, %d errors", count, errCount))

	analyzeBodyfile(ctx, bodyBuf.Bytes())
}

// analyzeBodyfile parses the collected bodyfile data and flags anomalies.
func analyzeBodyfile(ctx *ModuleContext, data []byte) {
	w := newSectionWriter(ctx, ctx.Dirs.Bodyfile, "bodyfile_analysis.txt",
		"Bodyfile Analysis — Timestomping / SUID / FHS / Volatile Activity",
		"bodyfile/bodyfile.txt")
	defer w.Close()

	now := time.Now().Unix()
	sevenDaysAgo := now - 7*86400
	seventyTwoHrsAgo := now - 72*3600

	volatileCount := 0
	const volatileCap = 20
	hits := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 11 {
			continue
		}
		// MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|btime
		const sIFMT = 0o170000
		const sIFREG = 0o100000
		path := fields[1]
		if ctx.SelfPath != "" && path == ctx.SelfPath {
			continue
		}
		if ctx.OutputPrefix != "" && strings.HasPrefix(path, ctx.OutputPrefix) {
			continue
		}
		modeRaw, _ := strconv.ParseUint(fields[3], 10, 32)
		uid, _ := strconv.ParseInt(fields[4], 10, 64)
		atime, _ := strconv.ParseInt(fields[7], 10, 64)
		mtime, _ := strconv.ParseInt(fields[8], 10, 64)
		btime, _ := strconv.ParseInt(fields[10], 10, 64)

		// 2. Volatile / hidden directory activity within 72 hours.
		// Volatile dirs (/tmp, /var/tmp, /dev/shm): flag regular files only.
		// Hidden paths: only flag REGULAR EXECUTABLE files. Directories always
		// carry the execute bit for traversal, and standard dotfiles (.bashrc,
		// .cache/, .config/, .local/, .mozilla/) are not worth flagging.
		inVolatile := strings.HasPrefix(path, "/tmp/") ||
			strings.HasPrefix(path, "/var/tmp/") ||
			strings.HasPrefix(path, "/dev/shm/")
		isHidden := bfIsHiddenPath(path)
		recentActivity := mtime >= seventyTwoHrsAgo || atime >= seventyTwoHrsAgo
		isExec := modeRaw&0o111 != 0
		isRegFile := modeRaw&sIFMT == sIFREG
		inSysBin := strings.HasPrefix(path, "/bin/") ||
			strings.HasPrefix(path, "/sbin/") ||
			strings.HasPrefix(path, "/usr/bin/") ||
			strings.HasPrefix(path, "/usr/sbin/")

		hiddenExecFile := isHidden && isExec && isRegFile && !bfIsKnownHiddenSafe(path)
		volatileFile := inVolatile && isRegFile

		// 1. Timestomping: modification time set in the future.
		// mtime > now indicates utimes() was used to set a future timestamp; no
		// legitimate process writes a future mtime. Grace of 60s covers clock skew.
		if inSysBin && mtime > now+60 {
			w.Write("[TIMESTOMP-FUTURE] %s — mtime=%s is in the future\n", path, bfTime(mtime))
			ctx.Registry.Add(output.HIGH, "bodyfile", "Timestomped binary: future mtime",
				fmt.Sprintf("System binary with future modification time: %s (mtime=%s)", path, bfTime(mtime)))
			hits++
		}

		// 2. Volatile / hidden directory activity within 72 hours.
		if recentActivity && (volatileFile || hiddenExecFile) {
			sev, label := output.MEDIUM, "VOLATILE-ACTIVITY"
			if isExec {
				sev, label = output.HIGH, "VOLATILE-EXEC"
			}
			w.Write("[%s] %s — mtime=%s\n", label, path, bfTime(mtime))
			registryLabel := "Recent activity in volatile/hidden path"
			registryMsg := fmt.Sprintf("Recent activity in volatile/hidden path: %s", path)
			if isExec {
				registryLabel = "Executable in volatile/hidden path"
				registryMsg = fmt.Sprintf("Executable in volatile/hidden path: %s", path)
			}
			if volatileCount < volatileCap {
				ctx.Registry.Add(sev, "bodyfile", registryLabel, registryMsg)
			} else {
				ctx.Registry.AddSilent(sev, "bodyfile", registryLabel, registryMsg)
			}
			volatileCount++
			hits++
		}

		// 3. SUID owned by root in non-standard path
		hasSUID := modeRaw&0o4000 != 0
		if hasSUID && uid == 0 && !ioc.IsInSafeDir(path) {
			w.Write("[SUID-NONSTANDARD] %s — mode=%04o UID=%d\n", path, modeRaw&0o7777, uid)
			ctx.Registry.Add(output.HIGH, "bodyfile", "SUID binary in non-standard path",
				fmt.Sprintf("SUID binary outside safe dirs: %s (mode=%04o)", path, modeRaw&0o7777))
			hits++
		}

		// 4. Binary replacement heuristic: system binary recently modified, older birth time.
		// Uses only mtime (not atime) -- atime updates on every execution and would fire for
		// every active binary on the system, making the check useless.
		recentMod := mtime >= sevenDaysAgo
		if inSysBin && recentMod && btime != 0 && btime < sevenDaysAgo {
			w.Write("[BIN-REPLACE] %s — recently modified (mtime=%s) but born=%s\n",
				path, bfTime(mtime), bfTime(btime))
			ctx.Registry.Add(output.MEDIUM, "bodyfile", "System binary replacement heuristic",
				fmt.Sprintf("System binary recently modified but older birth time: %s", path))
			hits++
		}

		// 5. FHS violation: executable regular file in a non-executable directory.
		fhsViolation := strings.HasPrefix(path, "/etc/") ||
			strings.HasPrefix(path, "/usr/share/man/") ||
			strings.HasPrefix(path, "/boot/")
		if isRegFile && isExec && fhsViolation {
			w.Write("[FHS-VIOLATION] %s — executable in non-exec dir (mode=%04o)\n", path, modeRaw&0o7777)
			ctx.Registry.Add(output.HIGH, "bodyfile", "FHS violation: executable in non-exec directory",
				fmt.Sprintf("Executable in FHS non-exec directory: %s", path))
			hits++
		}

	}

	if volatileCount > volatileCap {
		output.Info(fmt.Sprintf("%d more volatile/hidden path detections not shown — see bodyfile_analysis.txt",
			volatileCount-volatileCap))
	}

	if hits == 0 {
		w.Write("No bodyfile anomalies detected.\n")
		output.Ok("Bodyfile analysis: clean")
	} else {
		output.Warn(fmt.Sprintf("Bodyfile analysis: %d anomalies flagged", hits))
	}
	ctx.Log.Log("bodyfile", "analysis", fmt.Sprintf("%d hits", hits))
}

func bfTime(ts int64) string {
	if ts <= 0 {
		return "N/A"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05")
}

func bfIsHiddenPath(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if strings.HasPrefix(part, ".") && len(part) > 1 {
			return true
		}
	}
	return false
}

// bfIsKnownHiddenSafe returns true for hidden paths that are expected system or
// user-profile files and should never trigger the hidden-exec detection.
func bfIsKnownHiddenSafe(path string) bool {
	knownSafePrefixes := []string{
		"/etc/skel/",
		"/etc/selinux/",
	}
	for _, p := range knownSafePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	knownSafeFiles := []string{
		"/etc/.pwd.lock",
		"/etc/.updated",
	}
	for _, f := range knownSafeFiles {
		if path == f {
			return true
		}
	}
	return false
}

func bodyfileMD5(path string) string {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
