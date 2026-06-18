package modules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindUntaggedRepos_OnlyDigest(t *testing.T) {
	repos := map[string]map[string]string{
		"nginx": {"nginx@sha256:abc123": "sha256:abc123"},
	}
	result := findUntaggedRepos(repos)
	if len(result) != 1 || result[0] != "nginx" {
		t.Errorf("want [nginx], got %v", result)
	}
}

func TestFindUntaggedRepos_HasNamedTag(t *testing.T) {
	repos := map[string]map[string]string{
		"nginx": {
			"nginx:latest":        "sha256:abc123",
			"nginx@sha256:abc123": "sha256:abc123",
		},
	}
	result := findUntaggedRepos(repos)
	if len(result) != 0 {
		t.Errorf("want [], got %v", result)
	}
}

func TestFindUntaggedRepos_Mixed(t *testing.T) {
	repos := map[string]map[string]string{
		"nginx": {"nginx:latest": "sha256:abc"},
		"evil":  {"evil@sha256:bad": "sha256:bad"},
	}
	result := findUntaggedRepos(repos)
	if len(result) != 1 || result[0] != "evil" {
		t.Errorf("want [evil], got %v", result)
	}
}

func TestFindUntaggedRepos_Empty(t *testing.T) {
	result := findUntaggedRepos(map[string]map[string]string{})
	if len(result) != 0 {
		t.Errorf("want [], got %v", result)
	}
}

func TestFindUntaggedRepos_EmptyRefs(t *testing.T) {
	repos := map[string]map[string]string{
		"ghost": {},
	}
	result := findUntaggedRepos(repos)
	if len(result) != 0 {
		t.Errorf("want [] for empty refs, got %v", result)
	}
}

func TestParseDangerousCapabilities_SysAdmin(t *testing.T) {
	// CAP_SYS_ADMIN = bit 21 = 0x200000
	highCaps, medCaps, err := parseDangerousCapabilities("200000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(highCaps) != 1 || highCaps[0] != "CAP_SYS_ADMIN" {
		t.Errorf("want [CAP_SYS_ADMIN] high, got high=%v med=%v", highCaps, medCaps)
	}
	if len(medCaps) != 0 {
		t.Errorf("want no medium caps, got %v", medCaps)
	}
}

func TestParseDangerousCapabilities_NetRaw(t *testing.T) {
	// CAP_NET_RAW = bit 13 = 0x2000
	highCaps, medCaps, err := parseDangerousCapabilities("2000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(medCaps) != 1 || medCaps[0] != "CAP_NET_RAW" {
		t.Errorf("want [CAP_NET_RAW] medium, got high=%v med=%v", highCaps, medCaps)
	}
	if len(highCaps) != 0 {
		t.Errorf("want no high caps, got %v", highCaps)
	}
}

func TestParseDangerousCapabilities_None(t *testing.T) {
	highCaps, medCaps, err := parseDangerousCapabilities("0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(highCaps) != 0 || len(medCaps) != 0 {
		t.Errorf("want empty slices, got high=%v med=%v", highCaps, medCaps)
	}
}

func TestParseDangerousCapabilities_InvalidHex(t *testing.T) {
	_, _, err := parseDangerousCapabilities("ZZZZ")
	if err == nil {
		t.Error("want error for invalid hex, got nil")
	}
}

func TestParseDangerousCapabilities_SysAdminAndNetRaw(t *testing.T) {
	// CAP_SYS_ADMIN (bit 21) | CAP_NET_RAW (bit 13) = 0x200000 | 0x2000 = 0x202000
	highCaps, medCaps, err := parseDangerousCapabilities("202000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(highCaps) != 1 || highCaps[0] != "CAP_SYS_ADMIN" {
		t.Errorf("want [CAP_SYS_ADMIN] high, got %v", highCaps)
	}
	if len(medCaps) != 1 || medCaps[0] != "CAP_NET_RAW" {
		t.Errorf("want [CAP_NET_RAW] medium, got %v", medCaps)
	}
}

func TestOCIStateFlags_SysAdmin(t *testing.T) {
	state := runcState{}
	state.Config.Process.Capabilities.Effective = []string{"CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"}
	highCaps, hostNSPaths := ociStateFlags(state)
	if len(highCaps) != 1 || highCaps[0] != "CAP_SYS_ADMIN" {
		t.Errorf("want [CAP_SYS_ADMIN], got %v", highCaps)
	}
	if len(hostNSPaths) != 0 {
		t.Errorf("want no host NS paths, got %v", hostNSPaths)
	}
}

func TestOCIStateFlags_SysModule(t *testing.T) {
	state := runcState{}
	state.Config.Process.Capabilities.Effective = []string{"CAP_SYS_MODULE"}
	highCaps, _ := ociStateFlags(state)
	if len(highCaps) != 1 || highCaps[0] != "CAP_SYS_MODULE" {
		t.Errorf("want [CAP_SYS_MODULE], got %v", highCaps)
	}
}

func TestOCIStateFlags_HostNamespacePath(t *testing.T) {
	state := runcState{}
	state.Config.Linux.Namespaces = []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}{
		{Type: "pid", Path: "/proc/1/ns/pid"},
		{Type: "net", Path: ""},
	}
	highCaps, hostNSPaths := ociStateFlags(state)
	if len(highCaps) != 0 {
		t.Errorf("want no high caps, got %v", highCaps)
	}
	if len(hostNSPaths) != 1 || hostNSPaths[0] != "pid=/proc/1/ns/pid" {
		t.Errorf("want [pid=/proc/1/ns/pid], got %v", hostNSPaths)
	}
}

func TestOCIStateFlags_EmptyNamespacePath(t *testing.T) {
	state := runcState{}
	state.Config.Linux.Namespaces = []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}{
		{Type: "pid", Path: ""},
		{Type: "net", Path: ""},
	}
	_, hostNSPaths := ociStateFlags(state)
	if len(hostNSPaths) != 0 {
		t.Errorf("want no host NS paths for empty paths, got %v", hostNSPaths)
	}
}

func TestOCIStateFlags_Clean(t *testing.T) {
	state := runcState{}
	state.Config.Process.Capabilities.Effective = []string{"CAP_NET_BIND_SERVICE"}
	highCaps, hostNSPaths := ociStateFlags(state)
	if len(highCaps) != 0 || len(hostNSPaths) != 0 {
		t.Errorf("want clean state, got caps=%v ns=%v", highCaps, hostNSPaths)
	}
}

func TestIsNsenterHostAttach_ShortFlag(t *testing.T) {
	// "nsenter -t 1 -m -u -i -n -p -- su -" → true
	if !isNsenterHostAttach("nsenter -t 1 -m -u -i -n -p -- su -") {
		t.Error("want true for nsenter -t 1")
	}
}

func TestIsNsenterHostAttach_LongFlag(t *testing.T) {
	if !isNsenterHostAttach("nsenter --target 1 --mount --pid") {
		t.Error("want true for nsenter --target 1")
	}
}

func TestIsNsenterHostAttach_CombinedFlag(t *testing.T) {
	if !isNsenterHostAttach("nsenter -t1 -m") {
		t.Error("want true for nsenter -t1 (combined)")
	}
}

func TestIsNsenterHostAttach_EqualsSyntax(t *testing.T) {
	if !isNsenterHostAttach("nsenter --target=1 --mount") {
		t.Error("want true for nsenter --target=1")
	}
}

func TestIsNsenterHostAttach_NonRootTarget(t *testing.T) {
	// Targeting PID 1234, not PID 1 (not a host-namespace attach).
	if isNsenterHostAttach("nsenter -t 1234 -m") {
		t.Error("want false for nsenter targeting non-root PID")
	}
}

func TestIsNsenterHostAttach_NotNsenter(t *testing.T) {
	if isNsenterHostAttach("bash -c nsenter -t 1") {
		t.Error("want false when argv[0] is not nsenter")
	}
}

func TestIsNsenterHostAttach_Empty(t *testing.T) {
	if isNsenterHostAttach("") {
		t.Error("want false for empty cmdline")
	}
}

func TestIsRecentDockerImage_RecentFile(t *testing.T) {
	dir := t.TempDir()
	imgFile := filepath.Join(dir, "abc123def456")
	if err := os.WriteFile(imgFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	// File was just created, so mtime is now, which is within 7 days.
	if !isRecentDockerImage(imgFile, 7*24*time.Hour) {
		t.Error("want true for freshly created image manifest file")
	}
}

func TestIsRecentDockerImage_OldFile(t *testing.T) {
	dir := t.TempDir()
	imgFile := filepath.Join(dir, "abc123def456")
	os.WriteFile(imgFile, []byte("{}"), 0644)
	// Back-date the mtime to 30 days ago
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	os.Chtimes(imgFile, oldTime, oldTime)
	if isRecentDockerImage(imgFile, 7*24*time.Hour) {
		t.Error("want false for 30-day-old image file")
	}
}

func TestBindHostPath_Standard(t *testing.T) {
	cases := []struct {
		bind string
		want string
	}{
		{"/etc/shadow:/etc/shadow", "/etc/shadow"},
		{"/home/alice:/home/alice:ro", "/home/alice"},
		{"/:/", "/"},
		{"/var/run/docker.sock:/var/run/docker.sock", "/var/run/docker.sock"},
		{"/opt/app:/app", "/opt/app"},
	}
	for _, tc := range cases {
		if got := bindHostPath(tc.bind); got != tc.want {
			t.Errorf("bindHostPath(%q) = %q, want %q", tc.bind, got, tc.want)
		}
	}
}

func TestIsBindDangerous_CatchesSubdirMounts(t *testing.T) {
	dangerous := []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		"/:/",
		"/etc/shadow:/etc/shadow",
		"/etc/passwd:/etc/passwd",
		"/proc/sysrq-trigger:/proc/sysrq-trigger",
		"/sys/kernel/debug:/sys/kernel/debug",
		"/etc:/etc",
	}
	for _, bind := range dangerous {
		if !isBindDangerous(bind) {
			t.Errorf("isBindDangerous(%q) should be true", bind)
		}
	}
}

func TestIsBindDangerous_LeavesNonDangerousAlone(t *testing.T) {
	safe := []string{
		"/home/alice:/home/alice",
		"/var/lib/mysql:/data",
		"/opt/app:/app",
	}
	for _, bind := range safe {
		if isBindDangerous(bind) {
			t.Errorf("isBindDangerous(%q) should be false", bind)
		}
	}
}

func TestIsBindSensitive_CatchesSubdirMounts(t *testing.T) {
	sensitive := []string{
		"/home/alice:/home/alice",
		"/home/alice/.ssh:/home/alice/.ssh",
		"/root/.aws:/root/.aws",
		"/var/lib/mysql:/var/lib/mysql",
	}
	for _, bind := range sensitive {
		if !isBindSensitive(bind) {
			t.Errorf("isBindSensitive(%q) should be true", bind)
		}
	}
}

func TestIsBindSensitive_LeavesNonSensitiveAlone(t *testing.T) {
	notSensitive := []string{
		"/opt/app:/app",
		"/etc/shadow:/etc/shadow",
	}
	for _, bind := range notSensitive {
		if isBindSensitive(bind) {
			t.Errorf("isBindSensitive(%q) should be false", bind)
		}
	}
}
