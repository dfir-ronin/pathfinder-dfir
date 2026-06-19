package modules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pathfinder/internal/ioc"
	"github.com/pathfinder/internal/netfs"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

type mapAnomalyKind int

const (
	anomalyExecDeleted     mapAnomalyKind = iota // exec mapping with (deleted) suffix
	anomalyExecMemfd                             // exec mapping backed by memfd:
	anomalyExecStagingPath                       // exec mapping in a known malware dir
	anomalyRWXFileBacked                         // file-backed rwxp segment
	anomalyExecUserHome                          // exec mapping under /home/ or /root/
)

func (k mapAnomalyKind) String() string {
	switch k {
	case anomalyExecDeleted:
		return "execDeleted"
	case anomalyExecMemfd:
		return "execMemfd"
	case anomalyExecStagingPath:
		return "execStagingPath"
	case anomalyRWXFileBacked:
		return "rwxpFileBacked"
	case anomalyExecUserHome:
		return "execUserHome"
	default:
		return "unknown"
	}
}

type mapHit struct {
	Kind mapAnomalyKind
	Path string
	Line string
}

// classifyMapLine parses one /proc/<pid>/maps line. Returns anomaly kind, backing
// path, and ok=true if an anomaly was found. Priority order: execMemfd >
// execDeleted > execStagingPath > rwxpFileBacked > execUserHome.
func classifyMapLine(line string) (mapAnomalyKind, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return 0, "", false
	}
	perms := fields[1]
	hasExec := strings.Contains(perms, "x")
	isRWXP := perms == "rwxp"

	if !hasExec {
		return 0, "", false
	}

	path := ""
	if len(fields) >= 6 {
		path = strings.Join(fields[5:], " ")
	}

	if strings.HasPrefix(path, "memfd:") {
		return anomalyExecMemfd, path, true
	}
	if strings.HasSuffix(path, "(deleted)") && path != "(deleted)" {
		cleanPath := strings.TrimSuffix(path, " (deleted)")
		_, statErr := os.Stat(cleanPath)
		if statErr == nil || !os.IsNotExist(statErr) {
			// File exists, or stat failed for a reason other than ENOENT
			// (e.g. EACCES). Either way, do not report as deleted.
			return 0, "", false
		}
		return anomalyExecDeleted, path, true
	}
	if ioc.IsInMalwareDir(path) {
		return anomalyExecStagingPath, path, true
	}
	if isRWXP && path != "" {
		return anomalyRWXFileBacked, path, true
	}
	if strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/root/") {
		return anomalyExecUserHome, path, true
	}
	return 0, "", false
}

func mapAnomalySeverity(k mapAnomalyKind) output.Severity {
	switch k {
	case anomalyExecUserHome, anomalyRWXFileBacked:
		return output.MEDIUM
	default:
		return output.HIGH
	}
}

func describeMapKinds(hits []mapHit) string {
	seen := make(map[mapAnomalyKind]bool)
	var parts []string
	for _, k := range []mapAnomalyKind{
		anomalyExecDeleted, anomalyExecMemfd, anomalyExecStagingPath,
		anomalyRWXFileBacked, anomalyExecUserHome,
	} {
		for _, h := range hits {
			if h.Kind == k && !seen[k] {
				seen[k] = true
				parts = append(parts, k.String())
			}
		}
	}
	return strings.Join(parts, " + ")
}

func highestMapSeverity(hits []mapHit) output.Severity {
	for _, h := range hits {
		if mapAnomalySeverity(h.Kind) == output.HIGH {
			return output.HIGH
		}
	}
	return output.MEDIUM
}

// extractStrings scans b for printable ASCII runs of at least minLen bytes,
// separated by non-printable bytes. Each run is appended as a line so that
// ioc.ScanLines can match against them.
func extractStrings(b []byte, minLen int) string {
	var sb strings.Builder
	start := -1
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 0x20 && c < 0x7f {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minLen {
				sb.Write(b[start:i])
				sb.WriteByte('\n')
			}
			start = -1
		}
	}
	if start >= 0 && len(b)-start >= minLen {
		sb.Write(b[start:])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// volatileSnapshot holds all /proc-derived data collected once at the start of
// RunVolatile and shared across all sub-functions to avoid redundant walks.
type volatileSnapshot struct {
	Procs         []*procfs.Process
	ByPID         map[int]*procfs.Process
	InodeMap      map[uint64]int
	PromiscIfaces []string
	VisiblePIDs   map[int]bool
}

func buildSnapshot(procs []*procfs.Process) *volatileSnapshot {
	byPID := make(map[int]*procfs.Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	return &volatileSnapshot{
		Procs:         procs,
		ByPID:         byPID,
		InodeMap:      BuildInodePIDMap(),
		PromiscIfaces: collectPromiscInterfaces(),
		VisiblePIDs:   buildVisiblePIDSet(),
	}
}

// RunVolatile executes the -volatile module (volatile evidence)
func RunVolatile(ctx *ModuleContext) {
	output.Chapter("[VOLATILE] Scanning process memory space...")
	output.Info("Output → " + ctx.Dirs.Volatile)

	procs := ctx.Processes()
	if len(procs) == 0 {
		output.Warn("process snapshot failed: could not read /proc -- volatile results may be incomplete")
	}
	snap := buildSnapshot(procs)

	volatileProcessList(ctx, snap)
	volatileFullCmdlines(ctx, snap)
	volatileProcessTree(ctx, snap)
	volatileUnmaskedProcesses(ctx, snap)
	volatileHiddenKernelModules(ctx)
	volatileInodeDiscrepancy(ctx)
	volatileProcessBinaries(ctx, snap)
	volatileMasqueradeDetector(ctx, snap)
	volatileProcessAnomalies(ctx, snap)
	volatileCPUMemAnomalies(ctx, snap)
	volatileMemoryMaps(ctx, snap)
	volatileUnbackedExecutableMemory(ctx, snap)
	volatileSuspiciousEnviron(ctx, snap)
	volatileMissingStandardEnv(ctx, snap)
	volatileNetworkConnections(ctx)
	volatileFirewall(ctx)
	volatilePacketSniffers(ctx, snap)
	volatileEBPFPrograms(ctx, snap)
	volatileNamespaceAnomalies(ctx, snap)
	volatileContainerAnalysis(ctx, snap)
	volatileDeletedFilesOpen(ctx)

	ctx.Log.Log("volatile", "complete", "all sections done")
}

func volatileFullCmdlines(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "02_cmdlines_full.txt",
		"Full Process Command Lines (untruncated)", "/proc/<pid>/cmdline")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })

	for _, p := range procs {
		cmdline := p.Cmdline
		if cmdline == "" {
			cmdline = "[" + p.Name + "]"
		}
		w.Write("%-8d %-6d %s\n", p.PID, p.UID, cmdline)
	}

	output.Ok(fmt.Sprintf("Full cmdlines written: %d processes", len(procs)))
}

type dockerContainerConfig struct {
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		Binds       []string `json:"Binds"`
	} `json:"HostConfig"`
}

// dangerousBindExacts are host paths that must never be bind-mounted (exact match).
var dangerousBindExacts = []string{
	"/var/run/docker.sock",
	"/",
}

// dangerousBindDirPrefixes are host directory prefixes that must never be bind-mounted.
var dangerousBindDirPrefixes = []string{
	"/etc/",
	"/proc/",
	"/sys/",
}

// sensitiveMountPrefixes are host directory prefixes worth flagging at MEDIUM severity.
var sensitiveMountPrefixes = []string{
	"/home/",
	"/root/",
	"/var/lib/",
}

// bindHostPath returns the host-side path from a Docker bind spec "host:container[:opts]".
func bindHostPath(bind string) string {
	if idx := strings.Index(bind, ":"); idx >= 0 {
		return bind[:idx]
	}
	return bind
}

// isBindDangerous reports whether the host-side path of bind is in a dangerous category.
func isBindDangerous(bind string) bool {
	hp := bindHostPath(bind)
	for _, exact := range dangerousBindExacts {
		if hp == exact {
			return true
		}
	}
	for _, prefix := range dangerousBindDirPrefixes {
		// Match both "/etc/..." subdirectory files and "/etc" exact directory mount.
		if strings.HasPrefix(hp, prefix) || strings.HasPrefix(hp+"/", prefix) {
			return true
		}
	}
	return false
}

// isBindSensitive reports whether the host-side path of bind is in a sensitive category.
func isBindSensitive(bind string) bool {
	hp := bindHostPath(bind)
	for _, prefix := range sensitiveMountPrefixes {
		// Match both "/home/alice/..." and "/home/alice" exact directory mount.
		if strings.HasPrefix(hp, prefix) || strings.HasPrefix(hp+"/", prefix) {
			return true
		}
	}
	return false
}

func volatileContainerAnalysis(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "20_container_analysis.txt",
		"Container & Namespace Analysis",
		"/.dockerenv, /proc/1/cgroup, /var/lib/docker/containers/*, /run/containerd/containerd.sock, /run/crio/crio.sock, /var/run/podman/podman.sock, /var/lib/docker/image/overlay2/repositories.json, /proc/<pid>/status (CapEff), /proc/<pid>/ns/*, /run/docker/runtime-runc/moby/*/state.json, /proc/<pid>/cmdline (nsenter), /var/lib/docker/image/overlay2/imagedb/content/sha256/*, crictl, ctr")
	defer w.Close()

	h0, m0, l0, _ := ctx.Registry.Counts()

	w.WriteSectionHeader("Container Self-Detection")
	inContainer := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		w.Write("  [INSIDE-CONTAINER] /.dockerenv present — running inside a Docker container\n")
		inContainer = true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		w.Write("  [INSIDE-CONTAINER] /run/.containerenv present — running inside Podman/OCI container\n")
		inContainer = true
	}
	if cgroup, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		cgroupStr := string(cgroup)
		for _, marker := range []string{"docker/", "containerd/", "kubepods"} {
			if strings.Contains(cgroupStr, marker) {
				w.Write("  [INSIDE-CONTAINER] /proc/1/cgroup contains '%s'\n", marker)
				inContainer = true
			}
		}
	}
	if inContainer {
		ctx.Registry.Add(output.MEDIUM, "volatile", "Container environment detected",
			"Tool is running inside a container — host-level artifacts may be incomplete")
	} else {
		w.Write("  Not running inside a container (host execution confirmed).\n")
	}

	w.WriteSectionHeader("Docker Socket Exposure")
	if fi, err := os.Stat("/var/run/docker.sock"); err == nil {
		mode := fi.Mode()
		w.Write("  [DOCKER-SOCK] /var/run/docker.sock exists — mode=%s\n", mode.String())
		if mode&0o002 != 0 || mode&0o020 != 0 {
			ctx.Registry.Add(output.HIGH, "volatile", "Docker socket exposed",
				"Docker socket /var/run/docker.sock is world/group writable — container escape possible")
		} else {
			ctx.Registry.Add(output.MEDIUM, "volatile", "Docker socket exposed",
				"Docker socket /var/run/docker.sock present — verify access controls")
		}
	} else {
		w.Write("  /var/run/docker.sock not found.\n")
	}

	w.WriteSectionHeader("Docker Container Inventory")
	dockerBase := "/var/lib/docker/containers"
	containerDirs, err := os.ReadDir(dockerBase)
	if err != nil {
		w.Write("  Cannot read %s: %v\n", dockerBase, err)
	} else if len(containerDirs) == 0 {
		w.Write("  No Docker containers found.\n")
	} else {
		for _, d := range containerDirs {
			if !d.IsDir() {
				continue
			}
			cfgPath := filepath.Join(dockerBase, d.Name(), "config.v2.json")
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				continue
			}
			var cfg dockerContainerConfig
			if json.Unmarshal(raw, &cfg) != nil {
				continue
			}

			w.Write("  Container: %s  Image: %s\n", cfg.Name, cfg.Config.Image)

			if cfg.HostConfig.Privileged {
				w.Write("    [PRIVILEGED] Container is running with --privileged\n")
				ctx.Registry.Add(output.HIGH, "volatile", "Privileged container configuration",
					fmt.Sprintf("Privileged Docker container: %s (image: %s)", cfg.Name, cfg.Config.Image))
			}
			if strings.EqualFold(cfg.HostConfig.NetworkMode, "host") {
				w.Write("    [HOST-NETWORK] Container shares host network namespace\n")
				ctx.Registry.Add(output.HIGH, "volatile", "Privileged container configuration",
					fmt.Sprintf("Docker container %s using host network mode", cfg.Name))
			}
			if strings.EqualFold(cfg.HostConfig.PidMode, "host") {
				w.Write("    [HOST-PID] Container shares host PID namespace\n")
				ctx.Registry.Add(output.HIGH, "volatile", "Privileged container configuration",
					fmt.Sprintf("Docker container %s using host PID mode", cfg.Name))
			}
			for _, bind := range cfg.HostConfig.Binds {
				if isBindDangerous(bind) {
					w.Write("    [DANGEROUS-BIND] %s\n", bind)
					ctx.Registry.Add(output.HIGH, "volatile", "Dangerous container bind mount",
						fmt.Sprintf("Dangerous bind mount in container %s: %s", cfg.Name, bind))
				} else if isBindSensitive(bind) {
					w.Write("    [SENSITIVE-BIND] %s\n", bind)
					ctx.Registry.Add(output.MEDIUM, "volatile", "Dangerous container bind mount",
						fmt.Sprintf("Sensitive bind mount in container %s: %s", cfg.Name, bind))
				}
			}
		}
	}

	w.WriteSectionHeader("CRI Containers (crictl)")
	if out, err := execFallback(ctx, "crictl", "ps", "-o", "json"); err == nil && strings.TrimSpace(out) != "" {
		w.WriteString(out)
		output.Ok("crictl container list captured")
	} else {
		w.Write("  crictl not available or no CRI runtime found.\n")
	}

	w.WriteSectionHeader("containerd Containers (ctr)")
	if out, err := execFallback(ctx, "ctr", "containers", "list"); err == nil && strings.TrimSpace(out) != "" {
		w.WriteString(out)
		output.Ok("ctr container list captured")
	} else {
		w.Write("  ctr not available or no containerd runtime found.\n")
	}

	containerCheckRuntimeSockets(w, ctx)
	containerCheckUntaggedImages(w, ctx)
	containerCheckProcessCapabilities(w, ctx)
	pids := containerCheckOCIState(w, ctx)
	containerCheckNamespaceIsolation(w, ctx, pids)
	containerCheckNsenter(w, ctx, snap.Procs)
	containerCheckRecentImages(w, ctx)

	h1, m1, l1, _ := ctx.Registry.Counts()
	delta := (h1 - h0) + (m1 - m0) + (l1 - l0)
	if delta > 0 {
		output.Warn(fmt.Sprintf("Container analysis: %d hit(s)", delta))
	} else {
		output.Ok("Container analysis: clean")
	}
	ctx.Log.Log("volatile", "containers", fmt.Sprintf("in_container=%v", inContainer))
}

type dangerousCap struct {
	name string
	bit  uint
	sev  output.Severity
}

var dangerousCapabilities = []dangerousCap{
	{"CAP_SYS_ADMIN", 21, output.HIGH},
	{"CAP_SYS_MODULE", 16, output.HIGH},
	{"CAP_SYS_PTRACE", 19, output.MEDIUM},
	{"CAP_NET_ADMIN", 12, output.MEDIUM},
	{"CAP_NET_RAW", 13, output.MEDIUM},
	{"CAP_SYS_RAWIO", 17, output.MEDIUM},
	{"CAP_DAC_READ_SEARCH", 2, output.MEDIUM},
	{"CAP_BPF", 39, output.MEDIUM},
}

type runcState struct {
	ID             string `json:"id"`
	InitProcessPID int    `json:"init_process_pid"`
	Config         struct {
		Process struct {
			Capabilities struct {
				Effective []string `json:"effective"`
			} `json:"capabilities"`
		} `json:"process"`
		Linux struct {
			Namespaces []struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"namespaces"`
		} `json:"linux"`
	} `json:"config"`
}

type dockerRepositories struct {
	Repositories map[string]map[string]string `json:"Repositories"`
}

func containerCheckRuntimeSockets(w *output.Writer, ctx *ModuleContext) {
	w.WriteSectionHeader("Container Runtime Sockets")
	sockets := []struct {
		path    string
		runtime string
	}{
		{"/run/containerd/containerd.sock", "containerd"},
		{"/run/crio/crio.sock", "CRI-O"},
		{"/var/run/podman/podman.sock", "Podman"},
		{"/run/podman/podman.sock", "Podman (alternate)"},
	}
	found := 0
	for _, s := range sockets {
		fi, err := os.Stat(s.path)
		if err != nil {
			continue
		}
		found++
		mode := fi.Mode()
		w.Write("  [%s] %s — mode=%s\n", s.runtime, s.path, mode.String())
		if mode&0o002 != 0 || mode&0o020 != 0 {
			ctx.Registry.Add(output.HIGH, "volatile", "Container runtime socket exposed",
				fmt.Sprintf("%s socket %s is world/group writable — container escape possible", s.runtime, s.path))
		} else {
			ctx.Registry.Add(output.MEDIUM, "volatile", "Container runtime socket exposed",
				fmt.Sprintf("%s socket %s present — verify access controls", s.runtime, s.path))
		}
	}
	if found == 0 {
		w.Write("  No non-Docker container runtime sockets found.\n")
	}
}

func containerCheckUntaggedImages(w *output.Writer, ctx *ModuleContext) {
	w.WriteSectionHeader("Untagged Container Images")
	reposPath := "/var/lib/docker/image/overlay2/repositories.json"
	raw, err := os.ReadFile(reposPath)
	if err != nil {
		w.Write("  %s not readable: %v\n", reposPath, err)
		return
	}
	var repos dockerRepositories
	if err := json.Unmarshal(raw, &repos); err != nil {
		w.Write("  Cannot parse %s: %v\n", reposPath, err)
		return
	}
	untagged := findUntaggedRepos(repos.Repositories)
	if len(untagged) == 0 {
		w.Write("  No digest-only (untagged) images found.\n")
		return
	}
	for _, repo := range untagged {
		w.Write("  [UNTAGGED] %s\n", repo)
		ctx.Registry.Add(output.LOW, "volatile", "Untagged container image",
			fmt.Sprintf("Image repository %q has only digest-only refs — pulled without human-readable tag", repo))
	}
}

func containerCheckProcessCapabilities(w *output.Writer, ctx *ModuleContext) {
	w.WriteSectionHeader("Container Process Capabilities")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		w.Write("  Cannot read /proc: %v\n", err)
		return
	}
	found := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		cgroupStr := string(cgroupData)
		inContainer := strings.Contains(cgroupStr, "docker") ||
			strings.Contains(cgroupStr, "containerd") ||
			strings.Contains(cgroupStr, "kubepods")
		if !inContainer {
			continue
		}
		statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		var capHex string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				capHex = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				break
			}
		}
		if capHex == "" {
			continue
		}
		highCaps, medCaps, err := parseDangerousCapabilities(capHex)
		if err != nil {
			continue
		}
		if len(highCaps) == 0 && len(medCaps) == 0 {
			continue
		}
		name := readProcNameDirect(pid)
		found++
		w.Write("  [CAP] PID %-7d  NAME %-20s  CapEff: %s\n", pid, name, capHex)
		if len(highCaps) > 0 {
			w.Write("    [HIGH] %s\n", strings.Join(highCaps, ", "))
			ctx.Registry.Add(output.HIGH, "volatile", "Dangerous container process capabilities",
				fmt.Sprintf("PID %d (%s) has dangerous container capabilities: %s", pid, name, strings.Join(highCaps, ", ")))
		}
		if len(medCaps) > 0 {
			w.Write("    [MEDIUM] %s\n", strings.Join(medCaps, ", "))
			ctx.Registry.Add(output.MEDIUM, "volatile", "Dangerous container process capabilities",
				fmt.Sprintf("PID %d (%s) has elevated container capabilities: %s", pid, name, strings.Join(medCaps, ", ")))
		}
	}
	if found == 0 {
		w.Write("  No container processes with dangerous capabilities found.\n")
	}
}

func containerCheckOCIState(w *output.Writer, ctx *ModuleContext) []int {
	w.WriteSectionHeader("OCI Runtime State")
	matches, err := filepath.Glob("/run/docker/runtime-runc/moby/*/state.json")
	if err != nil || len(matches) == 0 {
		w.Write("  No runc state files found at /run/docker/runtime-runc/moby/*/state.json\n")
		return nil
	}
	var initPIDs []int
	for _, statePath := range matches {
		raw, err := os.ReadFile(statePath)
		if err != nil {
			continue
		}
		var state runcState
		if err := json.Unmarshal(raw, &state); err != nil {
			continue
		}
		w.Write("  Container: %s  PID: %d\n", state.ID, state.InitProcessPID)
		if state.InitProcessPID > 0 {
			initPIDs = append(initPIDs, state.InitProcessPID)
		}
		highCaps, hostNSPaths := ociStateFlags(state)
		if len(highCaps) > 0 {
			w.Write("    [HIGH-CAPS] %s\n", strings.Join(highCaps, ", "))
			ctx.Registry.Add(output.HIGH, "volatile", "Privileged OCI runtime state",
				fmt.Sprintf("Container %s has dangerous OCI capabilities: %s", state.ID, strings.Join(highCaps, ", ")))
		}
		if len(hostNSPaths) > 0 {
			w.Write("    [HOST-NS] %s\n", strings.Join(hostNSPaths, ", "))
			ctx.Registry.Add(output.HIGH, "volatile", "Privileged OCI runtime state",
				fmt.Sprintf("Container %s shares host namespaces via runc state: %s", state.ID, strings.Join(hostNSPaths, ", ")))
		}
	}
	return initPIDs
}

// discoverContainerPIDsFromCgroups walks /proc and returns PIDs whose cgroup
// membership indicates a container runtime (Docker, containerd, Kubernetes).
// Used as a fallback when no OCI state files are present.
func discoverContainerPIDsFromCgroups() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			pids = append(pids, pid)
		}
	}
	return pids
}

func containerCheckNamespaceIsolation(w *output.Writer, ctx *ModuleContext, containerPIDs []int) {
	w.WriteSectionHeader("Container Namespace Isolation")
	if len(containerPIDs) == 0 {
		containerPIDs = discoverContainerPIDsFromCgroups()
		if len(containerPIDs) == 0 {
			w.Write("  No container PIDs available.\n")
			return
		}
		w.Write("  (Cgroup fallback: %d container PID(s) discovered for non-Docker runtime)\n", len(containerPIDs))
	}
	nsTypes := []string{"pid", "mnt", "net"}
	hostNS := make(map[string]string, len(nsTypes))
	for _, nsType := range nsTypes {
		link, err := os.Readlink(fmt.Sprintf("/proc/1/ns/%s", nsType))
		if err != nil {
			continue
		}
		hostNS[nsType] = link
	}
	if len(hostNS) == 0 {
		w.Write("  Cannot read host namespace links from /proc/1/ns/.\n")
		return
	}
	found := 0
	for _, pid := range containerPIDs {
		for _, nsType := range nsTypes {
			pidLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, nsType))
			if err != nil {
				continue
			}
			if pidLink == hostNS[nsType] {
				found++
				w.Write("  [ESCAPE] PID %d shares host %s namespace: %s\n", pid, nsType, pidLink)
				ctx.Registry.Add(output.HIGH, "volatile", "Container namespace escape",
					fmt.Sprintf("PID %d shares host %s namespace (%s) — namespace isolation broken", pid, nsType, pidLink))
			}
		}
	}
	if found == 0 {
		w.Write("  All container PIDs have isolated namespaces.\n")
	}
}

// isNsenterHostAttach returns true if the space-joined cmdline represents an
// nsenter process targeting PID 1 (the host init process).
func isNsenterHostAttach(cmdline string) bool {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 || !strings.HasSuffix(fields[0], "nsenter") {
		return false
	}
	for i, f := range fields {
		if f == "-t1" || f == "--target=1" {
			return true
		}
		if (f == "-t" || f == "--target") && i+1 < len(fields) && fields[i+1] == "1" {
			return true
		}
	}
	return false
}

func containerCheckNsenter(w *output.Writer, ctx *ModuleContext, procs []*procfs.Process) {
	w.WriteSectionHeader("nsenter Host-Namespace Attach")
	hits := 0
	for _, p := range procs {
		if !isNsenterHostAttach(p.Cmdline) {
			continue
		}
		w.Write("  [HIGH] PID %d: %s\n", p.PID, p.Cmdline)
		ctx.Registry.Add(output.HIGH, "volatile", "Host namespace attach via nsenter",
			fmt.Sprintf("nsenter targeting host PID 1: PID %d cmdline: %s", p.PID, p.Cmdline))
		hits++
	}
	if hits == 0 {
		w.Write("  No nsenter host-namespace attach detected.\n")
	}
}

// isRecentDockerImage returns true if the file at path has a mtime within window.
func isRecentDockerImage(path string, window time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < window
}

func containerCheckRecentImages(w *output.Writer, ctx *ModuleContext) {
	w.WriteSectionHeader("Recently Created Docker Images")
	imageDir := "/var/lib/docker/image/overlay2/imagedb/content/sha256"
	entries, err := os.ReadDir(imageDir)
	if err != nil {
		w.Write("  %s not accessible.\n", imageDir)
		return
	}
	window := 7 * 24 * time.Hour
	hits := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(imageDir, e.Name())
		if !isRecentDockerImage(p, window) {
			continue
		}
		info, _ := e.Info()
		created := ""
		if info != nil {
			created = info.ModTime().Format(time.RFC3339)
		}
		name := e.Name()
		shortDigest := name
		if len(name) >= 12 {
			shortDigest = name[:12]
		}
		w.Write("  [MEDIUM] sha256:%s (created: %s)\n", shortDigest, created)
		ctx.Registry.Add(output.MEDIUM, "volatile", "Recently created Docker image",
			fmt.Sprintf("Docker image created within 7 days: sha256:%s", name))
		hits++
	}
	if hits == 0 {
		w.Write("  No recently created Docker images found.\n")
	}
}

func findUntaggedRepos(repos map[string]map[string]string) []string {
	var untagged []string
	for repoName, refs := range repos {
		if len(refs) == 0 {
			continue
		}
		hasNamedTag := false
		for ref := range refs {
			if !strings.Contains(ref, "@sha256:") {
				hasNamedTag = true
				break
			}
		}
		if !hasNamedTag {
			untagged = append(untagged, repoName)
		}
	}
	sort.Strings(untagged)
	return untagged
}

func parseDangerousCapabilities(capHex string) (highCaps, medCaps []string, err error) {
	bitmask, err := strconv.ParseUint(strings.TrimSpace(capHex), 16, 64)
	if err != nil {
		return nil, nil, err
	}
	for _, cap := range dangerousCapabilities {
		if bitmask&(1<<cap.bit) != 0 {
			if cap.sev == output.HIGH {
				highCaps = append(highCaps, cap.name)
			} else {
				medCaps = append(medCaps, cap.name)
			}
		}
	}
	return highCaps, medCaps, nil
}

func ociStateFlags(state runcState) (highCaps []string, hostNSPaths []string) {
	dangerous := make(map[string]bool)
	for _, c := range dangerousCapabilities {
		if c.sev == output.HIGH {
			dangerous[c.name] = true
		}
	}
	for _, cap := range state.Config.Process.Capabilities.Effective {
		if dangerous[cap] {
			highCaps = append(highCaps, cap)
		}
	}
	for _, ns := range state.Config.Linux.Namespaces {
		if ns.Path != "" {
			hostNSPaths = append(hostNSPaths, fmt.Sprintf("%s=%s", ns.Type, ns.Path))
		}
	}
	return highCaps, hostNSPaths
}

func volatileProcessList(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "01_running_processes.txt",
		"Running Processes", "/proc/<pid>/status + cmdline")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })

	w.Write("%-8s %-8s %-20s %-6s %-17s %s\n", "PID", "PPID", "USER/UID", "STATE", "STARTED", "EXE / CMDLINE")
	w.Write("%s\n", strings.Repeat("─", 120))

	for _, p := range procs {
		userLabel := fmt.Sprintf("uid/%d", p.UID)
		if p.UID == 0 {
			userLabel = "root"
		}
		exe := p.Exe
		if exe == "" {
			exe = "[" + p.Name + "]"
		}
		cmd := p.Cmdline
		if len(cmd) > 80 {
			cmd = cmd[:80] + "…"
		}
		line := exe
		if cmd != "" && cmd != exe {
			line = cmd
		}
		started := "(unknown)"
		if !p.StartTime.IsZero() {
			started = p.StartTime.Format("2006-01-02 15:04")
		}
		w.Write("%-8d %-8d %-20s %-6s %-17s %s\n", p.PID, p.PPid, userLabel, p.State, started, line)
	}

	output.Ok(fmt.Sprintf("Processes listed: %d", len(procs)))
	ctx.Log.Log("volatile", "process_list", fmt.Sprintf("count=%d", len(procs)))
}

func volatileProcessTree(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "03_process_tree.txt",
		"Process Tree", "/proc/<pid>/status (PPid field)")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	byPID := snap.ByPID
	children := make(map[int][]int)
	for _, p := range procs {
		children[p.PPid] = append(children[p.PPid], p.PID)
	}

	var printTree func(pid, depth int)
	printTree = func(pid, depth int) {
		p, ok := byPID[pid]
		if !ok {
			return
		}
		prefix := strings.Repeat("  ", depth)
		name := p.Name
		if p.Cmdline != "" && p.Cmdline != p.Name {
			short := p.Cmdline
			if len(short) > 60 {
				short = short[:60] + "…"
			}
			name = short
		}
		w.Write("%s%d  %s\n", prefix, p.PID, name)
		kids := children[pid]
		sort.Ints(kids)
		for _, kid := range kids {
			printTree(kid, depth+1)
		}
	}
	printTree(1, 0)

	for _, p := range procs {
		if p.PID == 1 {
			continue
		}
		// PPID 0 is the kernel idle/swapper thread, never in /proc, not suspicious.
		if p.PPid == 0 {
			continue
		}
		if _, ok := byPID[p.PPid]; !ok {
			w.Write("[orphan] %d  %s\n", p.PID, p.Name)
			ctx.Registry.Add(output.MEDIUM, "volatile", "Orphan process detected",
				fmt.Sprintf("Orphan process PID %d (%s) — parent PID %d not found; possible reparenting by rootkit",
					p.PID, p.Name, p.PPid))
		}
	}

	output.Ok("Process tree written")
}

func volatileProcessBinaries(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "07_process_binaries.txt",
		"Process Binaries — SHA-256 Hashes", "/proc/<pid>/exe (all running processes)")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	// Deduplicate by exe path; track deleted separately
	type binEntry struct {
		sha256  string
		deleted bool
		pids    []int
	}
	seen := make(map[string]*binEntry)

	for _, p := range procs {
		if p.Exe == "" || strings.HasPrefix(p.Exe, "[") {
			continue
		}
		key := p.Exe
		if e, ok := seen[key]; ok {
			e.pids = append(e.pids, p.PID)
			continue
		}
		hash := computeExeHash(p.PID)
		seen[key] = &binEntry{
			sha256:  hash,
			deleted: p.ExeDeleted,
			pids:    []int{p.PID},
		}
	}

	// Sort for deterministic output
	paths := make([]string, 0, len(seen))
	for k := range seen {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	deletedCount := 0
	w.Write("%-64s  %-8s  %s\n", "SHA-256", "STATUS", "PATH")
	w.Write("%s\n", strings.Repeat("─", 120))
	for _, path := range paths {
		e := seen[path]
		status := "OK"
		if e.deleted {
			status = "DELETED"
			deletedCount++
			ctx.Registry.Add(output.HIGH, "volatile", "Running deleted binary",
				fmt.Sprintf("Running deleted binary: %s [sha256:%s] — in-memory implant possible", path, e.sha256))
		}
		w.Write("%-64s  %-8s  %s\n", e.sha256, status, path)
	}

	output.Ok(fmt.Sprintf("Process binaries hashed: %d unique paths (%d deleted)", len(seen), deletedCount))
}

// hashFileNoAtime computes the SHA-256 of the file at path using O_NOATIME so
// that reading a process's backing binary does not stamp its access time.
func hashFileNoAtime(path string) (string, error) {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// computeExeHash reads /proc/<pid>/exe and returns its SHA-256 hex digest.
// The read goes through O_NOATIME so the live binary's atime is preserved.
func computeExeHash(pid int) string {
	hexsum, err := hashFileNoAtime(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "(unreadable — non-root or sealed)"
	}
	return hexsum
}

func shouldSkipPID(pid int) bool {
	return pid == os.Getpid()
}

func volatileMemoryMaps(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "11_memory_maps.txt",
		"Memory Maps (suspicious PIDs)", "/proc/<pid>/maps + /proc/<pid>/environ")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	found := 0
	for _, p := range procs {
		if shouldSkipPID(p.PID) {
			continue
		}
		maps, err := procfs.ReadMaps(p.PID)
		if err != nil {
			continue
		}

		var hits []mapHit
		for _, line := range strings.Split(maps, "\n") {
			if line == "" {
				continue
			}
			kind, path, ok := classifyMapLine(line)
			if !ok {
				continue
			}
			hits = append(hits, mapHit{Kind: kind, Path: path, Line: line})
		}
		if len(hits) == 0 {
			continue
		}

		found++
		w.Write("═══ PID %d — %s ═══\n", p.PID, p.Name)
		w.Write("# EXE: %s\n# CMD: %s\n\n", p.Exe, p.Cmdline)
		w.Write("── maps ──\n%s\n", maps)
		if env, err := procfs.ReadEnvironRaw(p.PID); err == nil {
			w.Write("── environ ──\n%s\n\n", env)
		}

		soleRWX := true
		for _, h := range hits {
			if h.Kind != anomalyRWXFileBacked {
				soleRWX = false
				break
			}
		}
		label := "Suspicious memory map"
		if soleRWX {
			label = "RWX file-backed memory region"
		}

		ctx.Registry.Add(highestMapSeverity(hits), "volatile", label,
			fmt.Sprintf("PID %d (%s): %s — see 11_memory_maps.txt",
				p.PID, p.Name, describeMapKinds(hits)))
	}

	if found == 0 {
		w.Write("No suspicious memory maps detected.\n")
		output.Ok("No suspicious memory maps")
	} else {
		output.Warn(fmt.Sprintf("%d process(es) with suspicious memory maps", found))
	}
}

func volatileUnbackedExecutableMemory(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "12_unbacked_exec_memory.txt",
		"Unbacked Executable Memory Regions", "/proc/<pid>/maps")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	found := 0
	for _, p := range procs {
		data, err := procfs.ReadMaps(p.PID)
		if err != nil {
			continue
		}

		var anonExec []string
		var rwxRegions []string

		for _, line := range strings.Split(data, "\n") {
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			perms := fields[1]
			inode := fields[4]
			pathname := ""
			if len(fields) >= 6 {
				pathname = fields[5]
			}

			isExec := strings.Contains(perms, "x")
			isWrite := strings.Contains(perms, "w")
			if !isExec {
				continue
			}

			isSpecial := pathname == "[stack]" || pathname == "[heap]" ||
				pathname == "[vdso]" || pathname == "[vsyscall]" ||
				pathname == "[vvar]" || strings.HasPrefix(pathname, "[stack:")

			if inode == "0" && pathname == "" && !isSpecial {
				anonExec = append(anonExec, "    "+line)
			}
			if isWrite && inode == "0" && pathname == "" && !isSpecial {
				rwxRegions = append(rwxRegions, "    "+line)
			}
		}

		if len(anonExec) == 0 && len(rwxRegions) == 0 {
			continue
		}

		found++
		w.Write("═══ PID %d — %s (UID %d) ═══\n", p.PID, p.Name, p.UID)
		w.Write("  EXE: %s\n  CMD: %s\n", p.Exe, p.Cmdline)

		if len(anonExec) > 0 {
			w.Write("  Anonymous executable regions (possible shellcode injection):\n")
			for _, r := range anonExec {
				w.Write("%s\n", r)
			}
			ctx.Registry.Add(output.HIGH, "volatile", "Anonymous executable memory region",
				fmt.Sprintf("PID %d (%s) has %d anonymous executable memory region(s) — injected shellcode possible",
					p.PID, p.Name, len(anonExec)))
		}
		if len(rwxRegions) > 0 {
			w.Write("  RWX regions (write + exec simultaneously):\n")
			for _, r := range rwxRegions {
				w.Write("%s\n", r)
			}
			ctx.Registry.Add(output.MEDIUM, "volatile", "RWX memory region",
				fmt.Sprintf("PID %d (%s) has %d RWX memory region(s) — suspicious permission combination",
					p.PID, p.Name, len(rwxRegions)))
		}
		w.Write("\n")
	}

	if found == 0 {
		w.Write("No unbacked or RWX executable memory regions detected.\n")
		output.Ok("No unbacked executable memory regions")
	} else {
		output.Warn(fmt.Sprintf("%d process(es) with suspicious executable memory regions", found))
	}
}

func volatileNetworkConnections(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "15_network_connections.txt",
		"Network Connections", "/proc/net/tcp, tcp6, udp, udp6")
	defer w.Close()

	sockets, err := netfs.ReadSockets()
	if err != nil {
		w.Write("ERROR: %v\n", err)
		return
	}

	w.Write("%-6s %-25s %-25s %-14s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE", "PROCESS")
	w.Write("%s\n", strings.Repeat("─", 90))
	for _, s := range sockets {
		w.Write("%-6s %-25s %-25s %-14s %s\n",
			s.Proto,
			fmt.Sprintf("%s:%d", s.LocalAddr, s.LocalPort),
			fmt.Sprintf("%s:%d", s.RemoteAddr, s.RemotePort),
			s.State,
			s.ProcessName)
	}

	nonStdPorts := map[int]bool{22: true, 80: true, 443: true, 53: true, 25: true, 587: true, 993: true, 995: true}
	for _, s := range sockets {
		if s.State == "ESTABLISHED" && !nonStdPorts[s.RemotePort] {
			ctx.Registry.Add(output.MEDIUM, "volatile", "Established connection on non-standard port",
				fmt.Sprintf("Established connection on non-standard port: %s:%d → %s:%d (%s)",
					s.LocalAddr, s.LocalPort, s.RemoteAddr, s.RemotePort, s.ProcessName))
		}
	}

	output.Ok(fmt.Sprintf("Sockets enumerated: %d", len(sockets)))
}

func volatileFirewall(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "16_firewall_rules.txt",
		"Firewall Rules", "iptables / nft (exec fallback)")
	defer w.Close()

	if out, err := execFallback(ctx, "iptables", "-L", "-vn"); err == nil {
		w.WriteSectionHeader("iptables -L -vn")
		w.WriteString(out)
	} else {
		w.WriteSectionHeader("iptables -L -vn")
		w.Write("  Not available: %v\n", err)
	}

	if out, err := execFallback(ctx, "nft", "list", "ruleset"); err == nil {
		w.WriteSectionHeader("nft list ruleset")
		w.WriteString(out)
	} else {
		w.WriteSectionHeader("nft list ruleset")
		w.Write("  Not available: %v\n", err)
	}

	output.Ok("Firewall rules collected")
}

func volatileNamespaceAnomalies(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "19_namespace_anomalies.txt",
		"Namespace Anomalies",
		"/proc/<pid>/ns/{net,mnt,uts} comparison against PID 1")
	defer w.Close()

	hostNetNS := procfs.HostNetNS()
	hostMntNS := procfs.HostMntNS()
	hostUtsNS := procfs.HostUtsNS()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	w.Write("Host namespaces: net=%s  mnt=%s  uts=%s\n\n", hostNetNS, hostMntNS, hostUtsNS)

	type nsHit struct {
		pid     int
		uid     int
		name    string
		nsType  string
		nsValue string
		cmdline string
	}
	var hits []nsHit

	for _, p := range procs {
		if hostNetNS != "" && p.NetNS != "" && p.NetNS != hostNetNS {
			hits = append(hits, nsHit{p.PID, p.UID, p.Name, "NET", p.NetNS, p.Cmdline})
		}
		if hostMntNS != "" && p.MntNS != "" && p.MntNS != hostMntNS {
			hits = append(hits, nsHit{p.PID, p.UID, p.Name, "MNT", p.MntNS, p.Cmdline})
		}
		if hostUtsNS != "" && p.UtsNS != "" && p.UtsNS != hostUtsNS {
			hits = append(hits, nsHit{p.PID, p.UID, p.Name, "UTS", p.UtsNS, p.Cmdline})
		}
	}

	uniquePIDs := make(map[int]struct{})
	for _, h := range hits {
		uniquePIDs[h.pid] = struct{}{}
	}

	if len(hits) == 0 {
		w.Write("No namespace anomalies detected.\n")
		output.Ok("No namespace anomalies")
		return
	}

	w.Write("%-8s %-6s %-6s %-30s %s\n", "PID", "UID", "TYPE", "NAMESPACE", "CMD")
	w.Write("%s\n", strings.Repeat("─", 90))
	for _, h := range hits {
		cmd := h.cmdline
		if len(cmd) > 40 {
			cmd = cmd[:40] + "…"
		}
		w.Write("%-8d %-6d %-6s %-30s %s\n", h.pid, h.uid, h.nsType, h.nsValue, cmd)
		nsFullName := map[string]string{"NET": "network", "MNT": "mount", "UTS": "uts"}[h.nsType]
		ctx.Registry.Add(output.MEDIUM, "volatile",
			fmt.Sprintf("Process in non-host %s namespace", nsFullName),
			fmt.Sprintf("PID %d (%s) in non-host %s namespace %s", h.pid, h.name, h.nsType, h.nsValue))
	}
	output.Warn(fmt.Sprintf("%d process(es) in non-host namespaces", len(uniquePIDs)))
}

// envRuleApplies returns true if the rule fires for the given process comm name and env value.
// Returns false if the value fails CheckValue or if comm matches a SuppressionComm prefix.
func envRuleApplies(rule ioc.EnvVarRule, procName, val string) bool {
	if rule.CheckValue != nil && !rule.CheckValue(val) {
		return false
	}
	for _, comm := range rule.SuppressionComms {
		if strings.HasPrefix(procName, comm) {
			return false
		}
	}
	return true
}

func volatileSuspiciousEnviron(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "13_suspicious_environ.txt",
		"Suspicious Environment Variables",
		"/proc/<pid>/environ — history evasion, rootkit injection, staging, CGI, SSH, access traces")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	envRuleHits := 0
	for _, p := range procs {
		if len(p.Environ) == 0 {
			continue
		}

		type ruleHit struct {
			rule ioc.EnvVarRule
			val  string
		}
		var ruleHits []ruleHit
		for _, rule := range ioc.SuspiciousEnvRules {
			val, present := p.Environ[rule.Name]
			if !present {
				continue
			}
			if !envRuleApplies(rule, p.Name, val) {
				continue
			}
			ruleHits = append(ruleHits, ruleHit{rule, val})
		}
		if len(ruleHits) == 0 {
			continue
		}

		envRuleHits += len(ruleHits)
		w.Write("═══ [SUSPICIOUS ENV] PID %d — %s (UID %d) ═══\n", p.PID, p.Name, p.UID)
		w.Write("  EXE: %s\n  CMD: %s\n", p.Exe, p.Cmdline)

		byCategory := make(map[string][]ruleHit)
		for _, h := range ruleHits {
			byCategory[h.rule.Category] = append(byCategory[h.rule.Category], h)
		}
		for cat, catHits := range byCategory {
			w.Write("  [%s]\n", cat)
			for _, h := range catHits {
				w.Write("    [%s] %s=%s\n         → %s\n",
					h.rule.Severity, h.rule.Name, h.val, h.rule.Description)
				ctx.Registry.Add(output.Severity(h.rule.Severity), "volatile", "Suspicious process environment variable",
					fmt.Sprintf("PID %d (%s) suspicious env var %s: %s",
						p.PID, p.Name, h.rule.Name, h.rule.Description))
			}
		}
		w.Write("\n")
	}

	if envRuleHits == 0 {
		w.Write("No suspicious environment variables detected.\n")
		output.Ok("No suspicious environment variables in processes")
	} else {
		output.Warn(fmt.Sprintf("Suspicious environ: %d rule hit(s)", envRuleHits))
	}
}

func volatileUnmaskedProcesses(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "04_unmasked_processes.txt",
		"Hidden Process Detection (PID Brute-Force)",
		"Brute-force PID walk: /proc/<pid>/maps readable but PID absent from lstat or /proc listing")
	defer w.Close()

	visiblePIDs := snap.VisiblePIDs
	pidMax := procfs.ReadPidMax()
	w.Write("Scanning PID range: 1 – %d\n", pidMax)
	w.Write("PIDs visible in /proc listing: %d\n\n", len(visiblePIDs))

	hidden := 0
	for pid := 1; pid <= pidMax; pid++ {
		if !procfs.MapsNonEmpty(pid) {
			continue
		}
		tgid := readTgidDirect(pid)
		if tgid <= 0 || tgid != pid {
			continue
		}

		lstatHidden := false
		if _, err := os.Lstat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			lstatHidden = true
		}
		listingHidden := !visiblePIDs[pid]

		if !lstatHidden && !listingHidden {
			continue
		}

		name := readProcNameDirect(pid)
		method := "lstat+listing"
		if !lstatHidden {
			method = "listing-only"
		} else if !listingHidden {
			method = "lstat-only"
		}

		w.Write("  [HIDDEN] PID %-7d  Name: %-20s  Method: %s\n", pid, name, method)
		hidden++
		ctx.Registry.Add(output.HIGH, "volatile", "Hidden process detected",
			fmt.Sprintf("Hidden PID %d (%s) confirmed by brute-force unmasking [%s]", pid, name, method))
	}

	w.Write("\nHidden processes found: %d\n", hidden)
	if hidden == 0 {
		output.Ok("Process unmasking: no hidden PIDs detected")
	} else {
		output.Warn(fmt.Sprintf("Hidden processes detected: %d", hidden))
	}
}

func volatilePacketSniffers(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "17_packet_sniffers.txt",
		"Packet Sniffer Detection",
		"/sys/class/net/<iface>/flags (promisc), /proc/net/packet (AF_PACKET), process names")
	defer w.Close()

	w.WriteSectionHeader("Network Interfaces in Promiscuous Mode")
	promiscIfaces := snap.PromiscIfaces
	if len(promiscIfaces) == 0 {
		w.Write("  No interfaces in promiscuous mode.\n")
	} else {
		for _, iface := range promiscIfaces {
			w.Write("  [PROMISC] %s\n", iface)
			ctx.Registry.Add(output.HIGH, "volatile", "Network interface in promiscuous mode",
				fmt.Sprintf("Interface %s is in promiscuous mode — packet sniffing suspected", iface))
		}
	}

	w.WriteSectionHeader("Raw AF_PACKET Sockets (/proc/net/packet)")
	pktSockets, err := netfs.ReadPacketSockets()
	if err != nil {
		w.Write("  Cannot read /proc/net/packet: %v\n", err)
	} else if len(pktSockets) == 0 {
		w.Write("  No AF_PACKET sockets found.\n")
	} else {
		w.Write("  %-8s  %-6s  %s\n", "INODE", "REFCNT", "TYPE")
		w.Write("  %s\n", strings.Repeat("─", 30))
		for _, s := range pktSockets {
			sockTypeName := "UNKNOWN"
			if s.Type == 3 {
				sockTypeName = "SOCK_RAW"
			} else if s.Type == 2 {
				sockTypeName = "SOCK_DGRAM"
			}
			w.Write("  %-8d  %-6d  %s\n", s.Inode, s.RefCnt, sockTypeName)
		}
	}

	inodePIDMap := snap.InodeMap
	rawSockPIDs := make(map[int]bool)
	for _, s := range pktSockets {
		if pid, ok := inodePIDMap[s.Inode]; ok {
			rawSockPIDs[pid] = true
		}
	}

	w.WriteSectionHeader("Processes with Raw Sockets or Known Sniffer Binary Name")
	procs := snap.Procs
	snifferHits := 0
	for _, p := range procs {
		baseName := filepath.Base(p.Exe)
		knownSniffer := ioc.KnownSnifferNames[baseName] || ioc.KnownSnifferNames[p.Name]
		hasRawSock := rawSockPIDs[p.PID]

		if !knownSniffer && !hasRawSock {
			continue
		}

		tag := "raw-socket"
		sev := output.MEDIUM
		if hasRawSock && len(promiscIfaces) > 0 {
			tag = "raw-socket+promisc"
			sev = output.HIGH
		}
		if knownSniffer && !hasRawSock {
			tag = "known-sniffer-name"
		}
		if knownSniffer && hasRawSock {
			tag = "known-sniffer+raw-socket"
			sev = output.HIGH
		}

		w.Write("  [%-24s] PID %-7d UID %-6d %s\n", tag, p.PID, p.UID, p.Name)
		w.Write("    EXE: %s\n    CMD: %s\n\n", p.Exe, p.Cmdline)
		snifferHits++
		ctx.Registry.Add(sev, "volatile", "Packet sniffer detected",
			fmt.Sprintf("Packet sniffer detected: PID %d (%s) [%s]", p.PID, p.Name, tag))
	}
	if snifferHits == 0 {
		w.Write("  No packet sniffers detected.\n")
	}

	if len(promiscIfaces) == 0 && snifferHits == 0 {
		output.Ok("No packet sniffers detected")
	} else {
		output.Warn(fmt.Sprintf("Packet sniffer signals: %d promisc iface(s), %d process hit(s)",
			len(promiscIfaces), snifferHits))
	}
}

type kmsgHit struct {
	label    string
	line     string
	severity output.Severity
}

func volatileKmsgLines(lines []string) []kmsgHit {
	var hits []kmsgHit
	for _, raw := range lines {
		msg := raw
		if idx := strings.Index(raw, ";"); idx >= 0 {
			msg = raw[idx+1:]
		}
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "bpf_probe_write_user"):
			hits = append(hits, kmsgHit{label: "BPF write-to-userspace helper", line: msg, severity: output.HIGH})
		case strings.Contains(lower, "bpf_override_return"):
			hits = append(hits, kmsgHit{label: "BPF override-return helper", line: msg, severity: output.HIGH})
		case strings.Contains(lower, "bpf") &&
			(strings.Contains(lower, "fail") || strings.Contains(lower, "invalid") ||
				strings.Contains(lower, "reject") || strings.Contains(lower, "verif")): // "verif" matches both "verifier" and "verification"
			hits = append(hits, kmsgHit{label: "BPF verifier failure", line: msg, severity: output.INFO})
		}
	}
	return hits
}

var cpuMemSuppressedProcs = map[string]bool{
	"mysqld": true, "postgres": true, "java": true, "node": true,
	"python": true, "python3": true, "ffmpeg": true, "make": true, "gcc": true,
	"cc1": true, "bazel": true, "cargo": true,
}

var ebpfSafeProcs = map[string]bool{
	"systemd": true, "containerd": true, "dockerd": true, "docker": true,
	"cilium": true, "cilium-agent": true, "falco": true, "auditd": true,
	"bpftrace": true, "katana": true,
}

func volatileEBPFPrograms(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "18_ebpf_programs.txt",
		"eBPF Program & Hook Detection",
		"/sys/fs/bpf/, /proc/<pid>/fdinfo/*, bpftool (exec fallback), /dev/kmsg")
	defer w.Close()

	w.WriteSectionHeader("Pinned BPF Objects (/sys/fs/bpf/)")
	if entries, err := os.ReadDir("/sys/fs/bpf"); err != nil {
		w.Write("  /sys/fs/bpf not mounted or not readable.\n")
	} else if len(entries) == 0 {
		w.Write("  /sys/fs/bpf is mounted and empty.\n")
	} else {
		for _, e := range entries {
			w.Write("  %s\n", filepath.Join("/sys/fs/bpf", e.Name()))
		}
	}

	w.WriteSectionHeader("Processes with Open BPF Program FDs (/proc/<pid>/fdinfo)")
	procByPID := snap.ByPID

	bpfHolders := 0
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, e := range procEntries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			fdinfoDir := fmt.Sprintf("/proc/%d/fdinfo", pid)
			fdinfos, err := os.ReadDir(fdinfoDir)
			if err != nil {
				continue
			}
			var progIDs []string
			for _, fi := range fdinfos {
				data, err := os.ReadFile(filepath.Join(fdinfoDir, fi.Name()))
				if err != nil {
					continue
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "prog-id:") {
						id := strings.TrimSpace(strings.TrimPrefix(line, "prog-id:"))
						if id != "0" {
							progIDs = append(progIDs, id)
						}
						break
					}
				}
			}
			if len(progIDs) == 0 {
				continue
			}
			p := procByPID[pid]
			name := fmt.Sprintf("pid/%d", pid)
			exe := ""
			if p != nil {
				name = p.Name
				exe = p.Exe
			}
			if ebpfSafeProcs[name] {
				continue
			}
			bpfHolders++
			w.Write("  [BPF] PID %-7d  NAME %-20s  EXE %s\n", pid, name, exe)
			w.Write("        prog-ids: %s\n\n", strings.Join(progIDs, ", "))
			ctx.Registry.Add(output.MEDIUM, "volatile", "Process holding BPF program FDs",
				fmt.Sprintf("Process PID %d (%s) holds %d BPF program FD(s) — review for hook abuse",
					pid, name, len(progIDs)))
		}
	}
	if bpfHolders == 0 {
		w.Write("  No unexpected BPF program holders detected.\n")
	}

	w.WriteSectionHeader("SUPPLEMENTARY — bpftool prog show (host binary; verify independently)")
	w.Write("  NOTE: bpftool reads the same kernel data as above but may be replaced on a\n")
	w.Write("  compromised host. Use this output as a cross-reference only.\n\n")
	if out, err := execFallback(ctx, "bpftool", "prog", "show"); err != nil {
		w.Write("  bpftool not available: %v\n", err)
	} else if strings.TrimSpace(out) == "" {
		w.Write("  No BPF programs reported by bpftool.\n")
	} else {
		w.WriteString(out)
	}

	w.WriteSectionHeader("Kernel Log BPF Events (/dev/kmsg)")
	kmsgLines, kmsgCapped, kmsgErr := readKmsgLines()
	if kmsgErr != nil {
		// Partial reads still carry evidence; note the error but analyze what we got.
		w.Write("  /dev/kmsg read error after %d records (analyzing partial): %v\n", len(kmsgLines), kmsgErr)
		output.Warn(fmt.Sprintf("eBPF kmsg: partial read (%d records): %v", len(kmsgLines), kmsgErr))
	}
	if kmsgCapped {
		w.Write("  /dev/kmsg truncated at cap (%d records analyzed); analysis covers the head only\n", len(kmsgLines))
		ctx.Log.Log("volatile", "kmsg_truncated", fmt.Sprintf("%d records at cap", len(kmsgLines)))
		output.Warn(fmt.Sprintf("eBPF kmsg: truncated at cap (%d records); head only", len(kmsgLines)))
	}
	if kmsgErr != nil && len(kmsgLines) == 0 {
		output.Skip("eBPF kmsg: /dev/kmsg not readable")
	} else {
		hits := volatileKmsgLines(kmsgLines)
		if len(hits) == 0 {
			w.Write("  No BPF-related kernel log events detected.\n")
			output.Ok("eBPF kmsg: no dangerous BPF kernel events")
		} else {
			labelCounts := make(map[string]int)
			labelSev := make(map[string]output.Severity)
			highCount := 0
			for _, h := range hits {
				var prefix string
				switch h.label {
				case "BPF write-to-userspace helper":
					prefix = "BPF-WRITE-USER"
				case "BPF override-return helper":
					prefix = "BPF-OVERRIDE"
				default:
					prefix = "BPF-VERIFIER"
				}
				w.Write("  [%s] %s\n", prefix, h.line)
				labelCounts[h.label]++
				labelSev[h.label] = h.severity
				if h.severity == output.HIGH {
					highCount++
				}
			}
			for label, count := range labelCounts {
				ctx.Registry.Add(labelSev[label], "volatile", label,
					fmt.Sprintf("%d kernel log event(s) detected", count))
			}
			if highCount > 0 {
				output.Warn(fmt.Sprintf("eBPF kmsg: %d dangerous BPF kernel event(s) detected", highCount))
			} else {
				output.Info(fmt.Sprintf("eBPF kmsg: %d verifier event(s) detected (no dangerous helpers)", len(hits)))
			}
		}
	}

	if bpfHolders == 0 {
		output.Ok("eBPF: no unexpected program holders detected")
	} else {
		output.Warn(fmt.Sprintf("eBPF: %d process(es) holding BPF program FDs", bpfHolders))
	}
}

func volatileInodeDiscrepancy(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "06_inode_discrepancy.txt",
		"Inode Discrepancy Check (getdents64 Hook Detection)",
		"os.ReadDir vs os.Lstat inode comparison — detects simple VFS-hooking rootkits in staging dirs")
	defer w.Close()

	checkDirs := []string{"/tmp", "/dev/shm", "/var/tmp"}
	hits := 0

	for _, d := range checkDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		w.WriteSectionHeader(d)

		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			entryInfo, err := e.Info()
			if err != nil {
				continue
			}

			lstatInfo, err := os.Lstat(p)
			if err != nil {
				w.Write("  [DISCREPANCY] %s — ReadDir OK but Lstat failed: %v\n", e.Name(), err)
				hits++
				ctx.Registry.Add(output.HIGH, "volatile", "VFS hook suspected (inode discrepancy)",
					fmt.Sprintf("Inode discrepancy in %s: '%s' visible via ReadDir but Lstat fails — VFS hook suspected",
						d, e.Name()))
				continue
			}

			entrySys, ok1 := entryInfo.Sys().(*syscall.Stat_t)
			lstatSys, ok2 := lstatInfo.Sys().(*syscall.Stat_t)
			if ok1 && ok2 && entrySys.Ino != lstatSys.Ino {
				w.Write("  [DISCREPANCY] %s — ReadDir inode %d ≠ Lstat inode %d\n",
					e.Name(), entrySys.Ino, lstatSys.Ino)
				hits++
				ctx.Registry.Add(output.HIGH, "volatile", "VFS hook suspected (inode discrepancy)",
					fmt.Sprintf("Inode mismatch in %s: '%s' ReadDir=%d Lstat=%d — possible VFS hook",
						d, e.Name(), entrySys.Ino, lstatSys.Ino))
			}
		}
	}

	if hits == 0 {
		w.Write("No inode discrepancies detected in staging directories.\n")
		output.Ok("Inode discrepancy check: clean")
	} else {
		output.Warn(fmt.Sprintf("Inode discrepancies detected: %d", hits))
	}
}

func buildVisiblePIDSet() map[int]bool {
	set := make(map[int]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return set
	}
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			set[pid] = true
		}
	}
	return set
}

func readTgidDirect(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.Atoi(fields[1])
				return v
			}
		}
	}
	return 0
}

func readProcNameDirect(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

func collectPromiscInterfaces() []string {
	var promisc []string
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return promisc
	}
	for _, e := range entries {
		flagsPath := filepath.Join("/sys/class/net", e.Name(), "flags")
		data, err := os.ReadFile(flagsPath)
		if err != nil {
			continue
		}
		flagStr := strings.TrimSpace(string(data))
		flagStr = strings.TrimPrefix(flagStr, "0x")
		flags, err := strconv.ParseUint(flagStr, 16, 64)
		if err != nil {
			continue
		}
		const IFF_PROMISC = 0x100 // linux/if.h: IFF_PROMISC
		if flags&IFF_PROMISC != 0 {
			promisc = append(promisc, e.Name())
		}
	}
	return promisc
}

func BuildInodePIDMap() map[uint64]int {
	inodeMap := make(map[uint64]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeMap
	}
	for _, e := range entries {
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
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodeStr := link[len("socket:[") : len(link)-1]
				if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
					inodeMap[inode] = pid
				}
			}
		}
	}
	return inodeMap
}

// isOwnProcess reports whether p is the currently-running Pathfinder binary.
func isOwnProcess(p *procfs.Process, selfPath string) bool {
	return selfPath != "" && p.Exe != "" && p.Exe == selfPath
}

func volatileProcessAnomalies(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "09_process_anomalies.txt",
		"Process Anomalies",
		"/proc/<pid>/exe, cmdline, cwd — deleted binaries, unsafe dirs, staging CWD, suspicious strings")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	flaggedPIDs := make(map[int]bool)

	// -- Processes Running Outside Safe Directories ----------------------------
	w.WriteSectionHeader("Processes Running Outside Safe Directories")
	unsafeDirHits := 0
	for _, p := range procs {
		if p.Exe == "" || strings.HasPrefix(p.Exe, "[") {
			continue
		}
		if p.ExeDeleted {
			continue
		}
		if isOwnProcess(p, ctx.SelfPath) {
			continue
		}
		if !ioc.IsInSafeDir(p.Exe) {
			w.Write("  PID %-6d UID %-6d EXE %s\n    CMD: %s\n",
				p.PID, p.UID, p.Exe, p.Cmdline)
			unsafeDirHits++
			flaggedPIDs[p.PID] = true
		}
	}
	if unsafeDirHits == 0 {
		w.Write("  None detected.\n")
	} else {
		ctx.Registry.Add(output.MEDIUM, "volatile", "Process running outside safe directory",
			fmt.Sprintf("%d process(es) running outside safe directories — see 09_process_anomalies.txt",
				unsafeDirHits))
	}

	// -- Suspicious Process Cmdlines -------------------------------------------
	w.WriteSectionHeader("Suspicious Process Cmdlines")
	cmdHits := 0
	for _, p := range procs {
		if p.Cmdline == "" {
			continue
		}
		if isOwnProcess(p, ctx.SelfPath) {
			continue
		}
		hits := ioc.ScanLines(p.Cmdline, ioc.StringHuntSignatures)
		for _, h := range hits {
			w.Write("  PID %-6d [%s] %s\n    CMD: %s\n    MATCH: %s\n",
				p.PID, h.Sig.Severity, h.Sig.Description, p.Cmdline, h.Line)
			cmdHits++
			flaggedPIDs[p.PID] = true
			ctx.Registry.Add(output.Severity(h.Sig.Severity), "volatile", "Suspicious process cmdline",
				fmt.Sprintf("PID %d cmdline matches %s: %s", p.PID, h.Sig.ID, h.Sig.Description))
		}
	}
	if cmdHits == 0 {
		w.Write("  No suspicious cmdline strings detected.\n")
	}

	// -- Staging-Directory CWD -------------------------------------------------
	w.WriteSectionHeader("Processes with Staging-Directory Working Directory")
	cwdHits := 0
	for _, p := range procs {
		if isOwnProcess(p, ctx.SelfPath) {
			continue
		}
		cwd := procfs.ReadProcessCWD(p.PID)
		if cwd == "" {
			continue
		}
		if !ioc.IsInMalwareDir(cwd+"/") && cwd != "/proc" && !strings.HasPrefix(cwd, "/proc/") {
			continue
		}
		compound := p.ExeDeleted || (p.Exe != "" && ioc.IsInMalwareDir(p.Exe))
		sev := output.MEDIUM
		if compound {
			sev = output.HIGH
		}
		w.Write("  PID %-6d UID %-6d CWD %s\n    EXE: %s\n    CMD: %s\n",
			p.PID, p.UID, cwd, p.Exe, p.Cmdline)
		cwdHits++
		flaggedPIDs[p.PID] = true
		ctx.Registry.Add(sev, "volatile", "Process CWD in staging directory",
			fmt.Sprintf("PID %d (%s) CWD=%s exe=%s", p.PID, p.Name, cwd, p.Exe))
	}
	if cwdHits == 0 {
		w.Write("  None detected.\n")
	}

	// -- Suspicious Strings in Flagged Process Binaries ------------------------
	w.WriteSectionHeader("Suspicious Strings in Flagged Process Binaries")
	const maxBinaryBytes = 10 * 1024 * 1024
	const minStringLen = 8
	const maxHitsPerProcess = 20
	stringsHits := 0
	for _, p := range procs {
		if !p.ExeDeleted && !flaggedPIDs[p.PID] {
			continue
		}
		if isOwnProcess(p, ctx.SelfPath) {
			continue
		}
		f, err := os.Open(fmt.Sprintf("/proc/%d/exe", p.PID))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxBinaryBytes))
		f.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		text := extractStrings(data, minStringLen)
		hits := ioc.ScanLines(text, ioc.StringHuntSignatures)
		if len(hits) == 0 {
			continue
		}
		if len(hits) > maxHitsPerProcess {
			hits = hits[:maxHitsPerProcess]
		}
		w.Write("═══ [STRINGS] PID %d — %s ═══\n", p.PID, p.Name)
		for _, h := range hits {
			w.Write("  [%s] %s\n    MATCH: %s\n",
				h.Sig.Severity, h.Sig.Description, h.Line)
			ctx.Registry.Add(output.Severity(h.Sig.Severity), "volatile",
				"Suspicious strings in process binary",
				fmt.Sprintf("PID %d (%s) binary contains %s: %s",
					p.PID, p.Name, h.Sig.ID, h.Sig.Description))
			stringsHits++
		}
	}
	if stringsHits == 0 {
		w.Write("  No suspicious strings found in flagged process binaries.\n")
	}

	total := unsafeDirHits + cmdHits + cwdHits + stringsHits
	if total > 0 {
		output.Warn(fmt.Sprintf("Process anomalies: %d unsafe dir, %d suspicious cmdline, %d staging CWD, %d binary string hit(s)",
			unsafeDirHits, cmdHits, cwdHits, stringsHits))
	} else {
		output.Ok("Process anomalies: clean")
	}
}

func volatileHiddenKernelModules(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "05_hidden_kernel_modules.txt",
		"Hidden Kernel Module Detection",
		"diff /proc/modules (lsmod) vs /sys/module/ entries; includes .ko file path")
	defer w.Close()

	mods, err := procfs.ReadModules()
	if err != nil {
		w.Write("ERROR reading /proc/modules: %v\n", err)
		return
	}
	sysMods, err := procfs.SysModules()
	if err != nil {
		w.Write("ERROR reading /sys/module: %v\n", err)
		return
	}

	procSet := make(map[string]bool)
	for _, m := range mods {
		procSet[m.Name] = true
	}
	sysSet := make(map[string]bool)
	for _, name := range sysMods {
		sysSet[name] = true
	}

	w.Write("Modules in /proc/modules: %d\n", len(mods))
	w.Write("Entries in /sys/module:   %d\n\n", len(sysMods))

	w.WriteSectionHeader("In /sys/module but NOT in /proc/modules (possible hidden module)")
	hiddenCount := 0
	for _, name := range sysMods {
		if ioc.SysModuleAllowlist[name] {
			continue
		}
		if !procSet[name] {
			sysPath := fmt.Sprintf("/sys/module/%s", name)
			koPath := "(built-in — no filename file)"
			if data, err := os.ReadFile(sysPath + "/filename"); err == nil {
				koPath = strings.TrimSpace(string(data))
			}
			w.Write("  [HIDDEN?] %-30s\n", name)
			w.Write("            sys path : %s\n", sysPath)
			w.Write("            ko path  : %s\n\n", koPath)
			hiddenCount++
			sev := output.HIGH
			if koPath == "(built-in — no filename file)" {
				sev = output.MEDIUM
			}
			ctx.Registry.Add(sev, "volatile", "Hidden kernel module",
				fmt.Sprintf("Kernel module '%s' in /sys/module but absent from /proc/modules — rootkit indicator (ko: %s)",
					name, koPath))
		}
	}
	if hiddenCount == 0 {
		w.Write("  None detected.\n")
		output.Ok("No hidden kernel modules detected")
	} else {
		output.Warn(fmt.Sprintf("Possible hidden kernel modules: %d", hiddenCount))
	}

	w.WriteSectionHeader("In /proc/modules but NOT in /sys/module (unusual)")
	unusualCount := 0
	for _, m := range mods {
		if !sysSet[m.Name] {
			w.Write("  [UNUSUAL] %-30s  size=%d  used=%d\n", m.Name, m.Size, m.Used)
			unusualCount++
			ctx.Registry.Add(output.LOW, "volatile", "Kernel module absent from /sys/module",
				fmt.Sprintf("Module '%s' in /proc/modules but absent from /sys/module — verify manually", m.Name))
		}
	}
	if unusualCount == 0 {
		w.Write("  None detected.\n")
	}
}

func volatileMasqueradeDetector(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "08_process_masquerade.txt",
		"Process Name Masquerade Detector",
		"/proc/<pid>/status, /proc/<pid>/exe, /proc/<pid>/environ")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	hits := 0
	for _, p := range procs {
		if !strings.HasPrefix(p.Name, "[") || !strings.HasSuffix(p.Name, "]") {
			continue
		}
		hasExe := p.Exe != "" && !strings.HasPrefix(p.Exe, "[")
		hasEnviron := len(p.Environ) > 0
		if !hasExe && !hasEnviron {
			continue
		}
		hits++
		w.Write("═══ [MASQUERADE] PID %d — Name: %s ═══\n", p.PID, p.Name)
		if hasExe {
			w.Write("  EXE (unexpected for kernel thread): %s\n", p.Exe)
		}
		if hasEnviron {
			w.Write("  ENVIRON keys: %d (unexpected — real kernel threads have none)\n", len(p.Environ))
		}
		w.Write("  CMDLINE: %s\n\n", p.Cmdline)
		ctx.Registry.Add(output.HIGH, "volatile", "Process masquerading as kernel thread",
			fmt.Sprintf("PID %d name '%s' mimics kernel thread but has exe='%s' — process masquerade (BPFDoor/Symbiote pattern)",
				p.PID, p.Name, p.Exe))
	}

	if hits == 0 {
		w.Write("No process name masquerade detected.\n")
		output.Ok("Process masquerade: clean")
	} else {
		output.Warn(fmt.Sprintf("Process masquerade suspects: %d", hits))
	}
}

func classifyDeletedFDs(fds []procfs.OpenFD) (suspicious, benign []procfs.OpenFD) {
	for _, fd := range fds {
		if ioc.IsInMalwareDir(fd.Target) {
			suspicious = append(suspicious, fd)
		} else {
			benign = append(benign, fd)
		}
	}
	return
}

func volatileDeletedFilesOpen(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "21_deleted_files_open.txt",
		"Deleted Files Still Held Open", "/proc/<pid>/fd (symlink targets with '(deleted)')")
	defer w.Close()

	fds, err := procfs.FindDeletedFDs()
	if err != nil {
		w.Write("ERROR: %v\n", err)
		ctx.Registry.Add(output.MEDIUM, "volatile", "Deleted FD enumeration failed",
			fmt.Sprintf("Could not enumerate deleted file descriptors: %v", err))
		return
	}

	if len(fds) == 0 {
		w.Write("None detected.\n")
		output.Ok("No deleted file descriptors open")
		return
	}

	w.Write("%-8s %-6s %s\n", "PID", "FD", "TARGET")
	w.Write("%s\n", strings.Repeat("─", 80))
	for _, fd := range fds {
		w.Write("%-8d %-6s %s\n", fd.PID, fd.FD, fd.Target)
	}
	suspFDs, otherFDs := classifyDeletedFDs(fds)

	if len(suspFDs) > 0 {
		ctx.Registry.Add(output.HIGH, "volatile", "Deleted file descriptor still open",
			fmt.Sprintf("%d deleted FD(s) open from high-risk staging path(s) — see 21_deleted_files_open.txt",
				len(suspFDs)))
	}
	if len(otherFDs) > 0 {
		ctx.Registry.Add(output.INFO, "volatile", "Deleted file descriptor still open",
			fmt.Sprintf("%d deleted FD(s) open from standard path(s) — see 21_deleted_files_open.txt",
				len(otherFDs)))
	}
	output.Warn(fmt.Sprintf("%d deleted FDs still open (%d high-risk, %d benign)",
		len(fds), len(suspFDs), len(otherFDs)))
}

func volatileMissingStandardEnv(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "14_missing_standard_env.txt",
		"Shell Processes Missing Standard Environment Variables",
		"/proc/<pid>/environ — PATH, HOME, USER absence in shell/interpreter processes")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No processes in snapshot.\n")
		return
	}

	hits := 0
	for _, p := range procs {
		baseName := filepath.Base(p.Exe)
		if !ioc.ShellNames[baseName] && !ioc.ShellNames[p.Name] {
			continue
		}

		var missing []string
		for _, varName := range ioc.StandardEnvVars {
			if _, ok := p.Environ[varName]; !ok {
				missing = append(missing, varName)
			}
		}
		if len(missing) == 0 {
			continue
		}

		hits++
		w.Write("  PID %-7d  NAME %-16s  UID %-6d  EXE %s\n",
			p.PID, p.Name, p.UID, p.Exe)
		w.Write("    Missing vars : %s\n", strings.Join(missing, ", "))
		w.Write("    Cmdline      : %s\n\n", p.Cmdline)
		ctx.Registry.Add(output.MEDIUM, "volatile", "Shell process missing standard env vars",
			fmt.Sprintf("Shell process PID %d (%s) missing env vars [%s] — possible exploit spawn or webshell",
				p.PID, p.Name, strings.Join(missing, ",")))
	}

	if hits == 0 {
		w.Write("All shell/interpreter processes have standard environment variables.\n")
		output.Ok("No shell processes with missing standard env vars")
	} else {
		output.Warn(fmt.Sprintf("Shell processes with missing env vars: %d", hits))
	}
}

func volatileCPUMemAnomalies(ctx *ModuleContext, snap *volatileSnapshot) {
	w := newSectionWriter(ctx, ctx.Dirs.Volatile, "10_cpu_mem_anomalies.txt",
		"CPU and Memory Anomalies",
		"/proc/<pid>/stat (utime+stime), /proc/<pid>/statm (RSS), /proc/uptime")
	defer w.Close()

	procs := snap.Procs
	if len(procs) == 0 {
		w.Write("No CPU or memory anomalies detected.\n")
		output.Ok("CPU/memory anomalies: clean")
		ctx.Log.Log("volatile", "cpu_mem", "hits=0")
		return
	}

	const cpuThresholdPct = 80.0
	const rssThresholdKB = 500 * 1024 // 500 MB

	hits := 0
	for _, p := range procs {
		if cpuMemSuppressedProcs[p.Name] || (p.Exe != "" && cpuMemSuppressedProcs[filepath.Base(p.Exe)]) {
			continue
		}
		cpuPct, rssKB, err := procfs.ReadProcessCPUMem(p.PID, p.StartTime)
		if err != nil {
			continue
		}
		flagCPU := cpuPct > cpuThresholdPct
		flagRSS := rssKB > rssThresholdKB
		if !flagCPU && !flagRSS {
			continue
		}
		hits++
		w.Write("═══ PID %d — %s (UID %d) ═══\n", p.PID, p.Name, p.UID)
		w.Write("  EXE: %s\n  CMD: %s\n", p.Exe, p.Cmdline)
		if flagCPU {
			w.Write("  [HIGH-CPU] Lifetime avg CPU: %.1f%%\n", cpuPct)
			ctx.Registry.Add(output.MEDIUM, "volatile", "High CPU usage (cryptominer heuristic)",
				fmt.Sprintf("PID %d (%s) lifetime avg CPU %.1f%% -- cryptominer heuristic",
					p.PID, p.Name, cpuPct))
		}
		if flagRSS {
			w.Write("  [HIGH-RSS] Resident set: %d MB\n", rssKB/1024)
			ctx.Registry.Add(output.MEDIUM, "volatile", "High memory usage",
				fmt.Sprintf("PID %d (%s) RSS %d MB exceeds 500 MB threshold",
					p.PID, p.Name, rssKB/1024))
		}
	}

	if hits == 0 {
		w.Write("No CPU or memory anomalies detected.\n")
		output.Ok("CPU/memory anomalies: clean")
	} else {
		output.Warn(fmt.Sprintf("CPU/memory anomalies: %d process(es) flagged", hits))
	}
	ctx.Log.Log("volatile", "cpu_mem", fmt.Sprintf("hits=%d", hits))
}
