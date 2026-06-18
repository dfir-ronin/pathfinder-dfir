package procfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pathfinder/internal/osutil"
)

// maxProcFileBytes caps a single /proc read. A pathological process map can be
// several MiB; 16 MiB keeps real maps intact while bounding a hostile blow-up.
const maxProcFileBytes = 16 << 20

// Process represents a single entry from /proc/<pid>/
type Process struct {
	PID        int
	PPid       int
	Tgid       int
	Name       string
	Exe        string
	ExeDeleted bool
	Cmdline    string
	UID        int
	GID        int
	NetNS      string
	MntNS      string
	UtsNS      string
	StartTime  time.Time
	Environ    map[string]string
	State      string
}

// ListProcesses walks /proc and returns all readable process entries
func ListProcesses() ([]*Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("ReadDir /proc: %w", err)
	}

	var procs []*Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProcess(pid)
		if err != nil {
			continue
		}
		procs = append(procs, p)
	}
	return procs, nil
}

func readProcess(pid int) (*Process, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	p := &Process{PID: pid, Environ: make(map[string]string)}

	// /proc/<pid>/status: virtual FS, no real atime to preserve; capped.
	if data, _, err := osutil.ReadFileCapped(base+"/status", maxProcFileBytes); err == nil {
		parseStatus(data, p)
	}

	if exe, err := os.Readlink(base + "/exe"); err == nil {
		p.Exe = exe
		p.ExeDeleted = strings.Contains(exe, "(deleted)")
	}

	if data, err := os.ReadFile(base + "/cmdline"); err == nil {
		parts := bytes.Split(data, []byte{0})
		var args []string
		for _, part := range parts {
			if len(part) > 0 {
				args = append(args, string(part))
			}
		}
		p.Cmdline = strings.Join(args, " ")
	}

	if ns, err := os.Readlink(base + "/ns/net"); err == nil {
		p.NetNS = ns
	}
	if ns, err := os.Readlink(base + "/ns/mnt"); err == nil {
		p.MntNS = ns
	}
	if ns, err := os.Readlink(base + "/ns/uts"); err == nil {
		p.UtsNS = ns
	}
	if sf, err := parseStatFile(pid); err == nil {
		p.StartTime = startTimeFromTicks(sf.starttime)
	}

	if data, _, err := osutil.ReadFileCapped(base+"/environ", maxProcFileBytes); err == nil {
		pairs := bytes.Split(data, []byte{0})
		for _, pair := range pairs {
			kv := bytes.SplitN(pair, []byte("="), 2)
			if len(kv) == 2 {
				p.Environ[string(kv[0])] = string(kv[1])
			}
		}
	}

	return p, nil
}

// parseStatus fills p from the contents of /proc/<pid>/status. The kernel uses
// either ":\t" or ": " as the key/value separator depending on the field, so we
// split on the first colon and trim, rather than assuming a tab.
func parseStatus(data []byte, p *Process) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "Name":
			p.Name = val
		case "PPid":
			p.PPid, _ = strconv.Atoi(val)
		case "Tgid":
			p.Tgid, _ = strconv.Atoi(val)
		case "State":
			p.State = val
		case "Uid":
			if fields := strings.Fields(val); len(fields) > 0 {
				p.UID, _ = strconv.Atoi(fields[0])
			}
		case "Gid":
			if fields := strings.Fields(val); len(fields) > 0 {
				p.GID, _ = strconv.Atoi(fields[0])
			}
		}
	}
}

// ReadMaps returns the memory map of a process, capped at maxProcFileBytes.
// On truncation a marker line is appended so the cap is visible in evidence.
func ReadMaps(pid int) (string, error) {
	data, trunc, err := osutil.ReadFileCapped(fmt.Sprintf("/proc/%d/maps", pid), maxProcFileBytes)
	if err != nil {
		return "", err
	}
	s := string(data)
	if trunc {
		s += fmt.Sprintf("\n# [pathfinder: /proc/%d/maps truncated at %d bytes]\n", pid, maxProcFileBytes)
	}
	return s, nil
}

// MapsNonEmpty reports whether /proc/<pid>/maps exists and has at least one
// byte, reading only a single byte. It replaces a full os.ReadFile in the
// PID brute-force loop: the loop only needs existence, and reading one byte
// per PID instead of the whole map removes both the uncapped-read OOM and the
// per-iteration cost across a 1..pid_max sweep.
func MapsNonEmpty(pid int) bool {
	data, _, err := osutil.ReadFileCapped(fmt.Sprintf("/proc/%d/maps", pid), 1)
	return err == nil && len(data) > 0
}

// ReadEnvironRaw returns the raw environ of a process as a string, capped at
// maxProcFileBytes. NUL separators are rendered as newlines.
func ReadEnvironRaw(pid int) (string, error) {
	data, trunc, err := osutil.ReadFileCapped(fmt.Sprintf("/proc/%d/environ", pid), maxProcFileBytes)
	if err != nil {
		return "", err
	}
	s := strings.ReplaceAll(string(data), "\x00", "\n")
	if trunc {
		s += fmt.Sprintf("\n# [pathfinder: /proc/%d/environ truncated at %d bytes]\n", pid, maxProcFileBytes)
	}
	return s, nil
}

// OpenFD represents a file descriptor pointing to a deleted file
type OpenFD struct {
	PID    int
	FD     string
	Target string
}

func FindDeletedFDs() ([]OpenFD, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var results []OpenFD
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(link, "(deleted)") {
				results = append(results, OpenFD{
					PID:    pid,
					FD:     fd.Name(),
					Target: link,
				})
			}
		}
	}
	return results, nil
}

// HostNetNS returns the network namespace of PID 1
func HostNetNS() string {
	ns, _ := os.Readlink("/proc/1/ns/net")
	return ns
}

// HostMntNS returns the mount namespace of PID 1
func HostMntNS() string {
	ns, _ := os.Readlink("/proc/1/ns/mnt")
	return ns
}

// HostUtsNS returns the UTS namespace of PID 1
func HostUtsNS() string {
	ns, _ := os.Readlink("/proc/1/ns/uts")
	return ns
}

// ReadProcessCWD returns the current working directory of the given PID by
// reading /proc/<pid>/cwd. Returns "" on error (process gone or EPERM).
func ReadProcessCWD(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}

// ReadProcessCPUMem returns lifetime average CPU% and resident set size in KB
// for the given PID. startTime comes from Process.StartTime to avoid a second
// stat parse. Returns cpuPct=0 when the process has been running < 30s to
// avoid division by a near-zero denominator.
func ReadProcessCPUMem(pid int, startTime time.Time) (cpuPct float64, rssKB int64, err error) {
	statmData, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, 0, err
	}
	statmFields := strings.Fields(string(statmData))
	if len(statmFields) < 2 {
		return 0, 0, fmt.Errorf("statm: too few fields")
	}
	rssPages, err := strconv.ParseInt(statmFields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("statm: parse rss: %w", err)
	}
	rssKB = rssPages * int64(os.Getpagesize()) / 1024

	startAge := time.Since(startTime).Seconds()
	if startAge < 30 {
		return 0, rssKB, nil
	}

	sf, err := parseStatFile(pid)
	if err != nil {
		return 0, rssKB, nil
	}

	const clkTck = 100
	cpuPct = (float64(sf.utime+sf.stime) / clkTck) / startAge * 100
	return cpuPct, rssKB, nil
}

// KernelModule holds a parsed entry from /proc/modules
type KernelModule struct {
	Name  string
	Size  int64
	Used  int
	Taint string // taint flags from field 6, e.g. "(OE)"; empty if absent
}

// parseModuleLine parses a slice of fields from one /proc/modules line.
func parseModuleLine(fields []string) (KernelModule, bool) {
	if len(fields) < 3 {
		return KernelModule{}, false
	}
	size, _ := strconv.ParseInt(fields[1], 10, 64)
	used, _ := strconv.Atoi(fields[2])
	taint := ""
	if len(fields) >= 7 {
		taint = fields[6]
	}
	return KernelModule{Name: fields[0], Size: size, Used: used, Taint: taint}, true
}

// ReadModules parses /proc/modules
func ReadModules() ([]KernelModule, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	var mods []KernelModule
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if mod, ok := parseModuleLine(fields); ok {
			mods = append(mods, mod)
		}
	}
	return mods, nil
}

// ReadKernelVersion returns the running kernel release string (e.g. "5.15.0-139-generic")
// by reading the third field of /proc/version.
func ReadKernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	// format: "Linux version <release> (<compiler>) ..."
	if len(fields) < 3 {
		return "", fmt.Errorf("unexpected /proc/version format")
	}
	return fields[2], nil
}

// SysModules returns module names found in /sys/module/
func SysModules() ([]string, error) {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

const (
	utmpRecordSize = 384
	utTypeUser     = 7
)

// UtmpRecord represents one parsed utmp/wtmp entry
type UtmpRecord struct {
	Type   int16
	PID    int32
	Line   string
	User   string
	Host   string
	TVSec  int32
	TVUsec int32
}

func (u *UtmpRecord) Time() time.Time {
	return time.Unix(int64(u.TVSec), int64(u.TVUsec)*1000).UTC()
}

func parseUtmpFile(path string) ([]UtmpRecord, error) {
	// utmp/wtmp are binary files on disk, preserve atime
	data, err := osutil.ReadFileNoAtime(path)
	if err != nil {
		return nil, err
	}
	// Callers only ever pass trusted, fixed utmp paths (/var/run/utmp,
	// /var/log/wtmp, /var/log/btmp). These are header-less fixed-size record
	// streams that are actively appended, so a length that is not a multiple of
	// the record size just means the last record is mid-write. We parse every
	// complete record from the start and ignore the trailing partial rather than
	// rejecting the whole file (which would drop all evidence from a live log).
	var records []UtmpRecord
	for i := 0; i+utmpRecordSize <= len(data); i += utmpRecordSize {
		rec := data[i : i+utmpRecordSize]
		var r UtmpRecord
		r.Type = int16(binary.LittleEndian.Uint16(rec[0:2]))
		r.PID = int32(binary.LittleEndian.Uint32(rec[4:8]))
		r.Line = cstring(rec[8:40])
		r.User = cstring(rec[44:76])
		r.Host = cstring(rec[76:332])
		r.TVSec = int32(binary.LittleEndian.Uint32(rec[340:344]))
		r.TVUsec = int32(binary.LittleEndian.Uint32(rec[344:348]))
		records = append(records, r)
	}
	return records, nil
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ReadWtmp() ([]UtmpRecord, error) { return parseUtmpFile("/var/log/wtmp") }
func ReadBtmp() ([]UtmpRecord, error) { return parseUtmpFile("/var/log/btmp") }

func ReadUtmp() ([]UtmpRecord, error) {
	recs, err := parseUtmpFile("/var/run/utmp")
	if err != nil {
		return nil, err
	}
	var active []UtmpRecord
	for _, r := range recs {
		if r.Type == utTypeUser {
			active = append(active, r)
		}
	}
	return active, nil
}

type PasswdEntry struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
	Shell    string
	Raw      string
}

func ReadPasswd() ([]PasswdEntry, error) {
	return parsePasswd("/etc/passwd")
}

func parsePasswd(path string) ([]PasswdEntry, error) {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []PasswdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		entries = append(entries, PasswdEntry{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  fields[5],
			Shell:    fields[6],
			Raw:      line,
		})
	}
	return entries, sc.Err()
}

type ShadowEntry struct {
	Username     string
	PasswordHash string
	HasHash      bool
}

func ReadShadow() ([]ShadowEntry, error) {
	f, err := osutil.OpenNoAtime("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []ShadowEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		hash := fields[1]
		hasHash := len(hash) > 3 && hash[0] == '$'
		entries = append(entries, ShadowEntry{
			Username:     fields[0],
			PasswordHash: hash,
			HasHash:      hasHash,
		})
	}
	return entries, sc.Err()
}

// DiffFiles compares two text files and returns changed lines with prefix markers
func DiffFiles(oldPath, newPath string) (string, error) {
	oldLines, err := readLines(oldPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", oldPath, err)
	}
	newLines, err := readLines(newPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", newPath, err)
	}

	oldSet := make(map[string]bool)
	newSet := make(map[string]bool)
	for _, l := range oldLines {
		oldSet[l] = true
	}
	for _, l := range newLines {
		newSet[l] = true
	}

	var sb strings.Builder
	for _, l := range oldLines {
		if !newSet[l] {
			fmt.Fprintf(&sb, "- %s\n", l)
		}
	}
	for _, l := range newLines {
		if !oldSet[l] {
			fmt.Fprintf(&sb, "+ %s\n", l)
		}
	}
	if sb.Len() == 0 {
		sb.WriteString("No differences found.\n")
	}
	return sb.String(), nil
}

func readLines(path string) ([]string, error) {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// ReadPidMax reads the kernel's configured PID ceiling.
func ReadPidMax() int {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 131072
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || v < 1 || v > 4194304 {
		return 131072
	}
	return v
}

type statFields struct {
	utime     uint64
	stime     uint64
	starttime uint64
}

// parseStatRaw parses the content of /proc/<pid>/stat. Field 2 (comm) is
// parenthesized and may contain spaces, so we split on the last ')' rather
// than on whitespace alone.
func parseStatRaw(raw string) (statFields, error) {
	lastParen := strings.LastIndex(raw, ")")
	if lastParen < 0 || lastParen+2 >= len(raw) {
		return statFields{}, fmt.Errorf("malformed stat line: no closing paren or empty suffix")
	}
	rest := strings.TrimSpace(raw[lastParen+1:])
	fields := strings.Fields(rest)
	// fields[0]=state(3) ... fields[11]=utime(14) fields[12]=stime(15) ... fields[19]=starttime(22)
	if len(fields) < 20 {
		return statFields{}, fmt.Errorf("stat: too few fields after comm (%d)", len(fields))
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	starttime, _ := strconv.ParseUint(fields[19], 10, 64)
	return statFields{utime: utime, stime: stime, starttime: starttime}, nil
}

func parseStatFile(pid int) (statFields, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return statFields{}, err
	}
	return parseStatRaw(strings.TrimSpace(string(data)))
}

var (
	btimeOnce sync.Once
	btimeSecs int64
)

func readBtime() int64 {
	// If /proc/stat is unreadable on first call, btimeSecs stays 0 for the
	// process lifetime. Callers must treat 0 as "unknown boot time".
	btimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					btimeSecs, _ = strconv.ParseInt(fields[1], 10, 64)
				}
				break
			}
		}
	})
	return btimeSecs
}

func startTimeFromTicks(startTicks uint64) time.Time {
	if startTicks == 0 {
		return time.Time{}
	}
	btime := readBtime()
	if btime == 0 {
		return time.Time{}
	}
	const clkTck = 100 // always 100 on Linux; sysconf(_SC_CLK_TCK) not in Go stdlib
	return time.Unix(btime+int64(startTicks)/clkTck, 0)
}
