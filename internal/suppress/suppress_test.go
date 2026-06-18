package suppress

import (
	"testing"
)

func TestNew_UnknownDistro(t *testing.T) {
	e, err := New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(e.rules) == 0 {
		t.Error("expected universal rules to be loaded")
	}
}

func TestNew_UbuntuLoadsExtraRules(t *testing.T) {
	eUniversal, _ := New("", nil)
	eUbuntu, _ := New("ubuntu", nil)
	if len(eUbuntu.rules) <= len(eUniversal.rules) {
		t.Error("ubuntu engine should have more rules than universal-only")
	}
}

func TestNew_RHELLoadsExtraRules(t *testing.T) {
	eUniversal, _ := New("", nil)
	eRHEL, _ := New("rhel", nil)
	if len(eRHEL.rules) <= len(eUniversal.rules) {
		t.Error("rhel engine should have more rules than universal-only")
	}
}

func TestCheck_BuiltInKernelModule(t *testing.T) {
	e, _ := New("", nil)
	suppressed, src := e.Check("volatile", "Hidden kernel module", "Hidden kernel module: crypto_simd (built-in)")
	if !suppressed {
		t.Error("expected built-in kernel module to be suppressed")
	}
	if src != "profile" {
		t.Errorf("want src=profile, got %q", src)
	}
}

func TestCheck_PathInMatch(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/ssh/ssh_host_rsa_key (line 1) — SH006: suspicious embedded key")
	if !suppressed {
		t.Error("expected SSH host key deepscan finding to be suppressed")
	}
}

func TestCheck_PathInNoMatch(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/ssh/sshd_config (line 5) — SH001: eval usage")
	if suppressed {
		t.Error("sshd_config should NOT be suppressed")
	}
}

func TestCheck_PathGlob(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/grub.d/40_custom")
	if !suppressed {
		t.Error("expected grub.d file to be suppressed via glob")
	}
}

func TestCheck_ProcessInExact(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Packet sniffer detected",
		"Packet sniffer detected PID 1234 (NetworkManager)")
	if !suppressed {
		t.Error("expected NetworkManager sniffer finding to be suppressed")
	}
}

func TestCheck_ProcessInPrefix(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"Process in non-host network namespace PID 999 (power-profiles-daemon)")
	if !suppressed {
		t.Error("expected power-profiles-daemon (prefix match) to be suppressed")
	}
}

func TestCheck_ProcessInPrefixNoMatch(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"Process in non-host network namespace PID 999 (malware-daemon)")
	if suppressed {
		t.Error("malware-daemon should NOT be suppressed")
	}
}

func TestCheck_UserRuleAddsNewSuppression(t *testing.T) {
	userRules := []SuppressRule{
		{Module: "audit", RuleID: "NOPASSWD sudo entry", Reason: "approved"},
	}
	e, _ := New("", userRules)
	suppressed, src := e.Check("audit", "NOPASSWD sudo entry", "NOPASSWD sudo entry: ops-user")
	if !suppressed {
		t.Error("expected user rule to suppress this finding")
	}
	if src != "user" {
		t.Errorf("want src=user, got %q", src)
	}
}

func TestCheck_UserRuleCancelsProfileRule(t *testing.T) {
	f := false
	userRules := []SuppressRule{
		{
			Suppress:        &f,
			Module:          "volatile",
			RuleID:          "Hidden kernel module",
			MessageContains: "(built-in",
		},
	}
	e, _ := New("", userRules)
	suppressed, _ := e.Check("volatile", "Hidden kernel module", "Hidden kernel module: crypto_simd (built-in)")
	if suppressed {
		t.Error("user suppress:false rule should cancel the profile rule")
	}
}

func TestCounts(t *testing.T) {
	e, _ := New("", nil)
	e.Check("volatile", "Hidden kernel module", "Hidden kernel module: crypto_simd (built-in)")
	e.Check("volatile", "Hidden kernel module", "Hidden kernel module: crypto_simd (built-in)")
	p, u := e.Counts()
	if p != 2 {
		t.Errorf("want 2 profile suppressions, got %d", p)
	}
	if u != 0 {
		t.Errorf("want 0 user suppressions, got %d", u)
	}
}

func TestExtractPath(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		// bodyfile/persist-unit format: "label: /path"
		{"FHS violation: executable in non-exec directory: /etc/grub.d/40_custom", "/etc/grub.d/40_custom"},
		// deepscan string-hunt format: "String match in /path (line N) — ID: desc"
		{"String match in /etc/ssh/ssh_host_rsa_key (line 1) — SH006: suspicious key", "/etc/ssh/ssh_host_rsa_key"},
		// persist MotD scan format: "Suspicious command in MotD/profile script /path (line N) — ..."
		{"Suspicious command in MotD/profile script /etc/profile.d/lang.sh (line 3) — SH001: eval", "/etc/profile.d/lang.sh"},
		{"No path here", ""},
	}
	for _, tc := range cases {
		if got := extractPath(tc.msg); got != tc.want {
			t.Errorf("extractPath(%q): want %q, got %q", tc.msg, tc.want, got)
		}
	}
}

func TestExtractProcess(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"Packet sniffer detected PID 1234 (NetworkManager)", "NetworkManager"},
		{"Process in non-host network namespace PID 999 (power-profiles-daemon)", "power-profiles-daemon"},
		{"No process here", ""},
	}
	for _, tc := range cases {
		if got := extractProcess(tc.msg); got != tc.want {
			t.Errorf("extractProcess(%q): want %q, got %q", tc.msg, tc.want, got)
		}
	}
}

func TestMatchGlob_SingleStar(t *testing.T) {
	cases := []struct {
		pat  string
		path string
		want bool
	}{
		{"/etc/grub.d/*", "/etc/grub.d/40_custom", true},
		{"/etc/grub.d/*", "/etc/grub.d/subdir/file", false},
		{"/etc/network/if-*.d/*", "/etc/network/if-up.d/resolved", true},
		{"/etc/network/if-*.d/*", "/etc/cron.daily/apt", false},
	}
	for _, tc := range cases {
		got := matchGlob(tc.pat, tc.path)
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q): want %v, got %v", tc.pat, tc.path, tc.want, got)
		}
	}
}

func TestMatchGlob_Doublestar(t *testing.T) {
	cases := []struct {
		pat  string
		path string
		want bool
	}{
		{"/tmp/pathfinder-*/**", "/tmp/pathfinder-myhost-20260428/trace/01.txt", true},
		{"/tmp/pathfinder-*/**", "/tmp/pathfinder-myhost-20260428/scan/mem.bin", true},
		{"/tmp/pathfinder-*/**", "/tmp/other-dir/file.txt", false},
		{"/home/*/snap/firefox/**", "/home/alice/snap/firefox/common/cache/file", true},
		{"/home/*/snap/firefox/**", "/home/bob/snap/chromium/cache/file", false},
	}
	for _, tc := range cases {
		got := matchGlob(tc.pat, tc.path)
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q): want %v, got %v", tc.pat, tc.path, tc.want, got)
		}
	}
}

func TestCheck_GnomeSessionIAnonExec(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Anonymous executable memory region",
		"PID 3128 (gnome-session-i) has 1 anonymous executable memory region(s) — injected shellcode possible")
	if !suppressed {
		t.Error("gnome-session-i anon exec should be suppressed (JIT runtime)")
	}
}

func TestCheck_GnomeSessionIRWX(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "RWX memory region",
		"PID 3128 (gnome-session-i) has 1 RWX memory region(s) — suspicious permission combination")
	if !suppressed {
		t.Error("gnome-session-i RWX should be suppressed (JIT runtime)")
	}
}

func TestCheck_BwrapNetNS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"PID 3579 (bwrap) in non-host network namespace net:[4026533048]")
	if !suppressed {
		t.Error("bwrap net namespace should be suppressed (Flatpak sandboxing)")
	}
}

func TestCheck_GlycinNetNS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"PID 3601 (glycin-image-rs) in non-host network namespace net:[4026533048]")
	if !suppressed {
		t.Error("glycin-image-rs net namespace should be suppressed (GNOME image sandbox)")
	}
}

func TestCheck_SystemdLocaledNetNS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"PID 3663 (systemd-localed) in non-host network namespace net:[4026532927]")
	if !suppressed {
		t.Error("systemd-localed net namespace should be suppressed (standard systemd sandboxing)")
	}
}

func TestCheck_UdevWorkerBinaryMismatch(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("audit", "Process binary mismatch",
		"Process name mismatch: _COMM=(udev-worker) does not match executable /usr/bin/udevadm")
	if !suppressed {
		t.Error("udev-worker/udevadm mismatch should be suppressed (udevadm forks via prctl)")
	}
}

func TestCheck_UbuntuIPv6HostsEntry(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("baseline", "Non-loopback /etc/hosts entry",
		"Non-loopback /etc/hosts entry: fe00::0 ip6-localnet — potential DNS redirect")
	if !suppressed {
		t.Error("fe00::0 ip6-localnet should be suppressed on Ubuntu (standard IPv6 hosts entry)")
	}
}

func TestCheck_ApportAutoreportPath(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "Systemd .path unit found",
		"Systemd .path unit found: /etc/systemd/system/paths.target.wants/apport-autoreport.path — filesystem-triggered persistence")
	if !suppressed {
		t.Error("apport-autoreport.path should be suppressed on Ubuntu")
	}
}

func TestCheck_TpmUdevPath(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "Systemd .path unit found",
		"Systemd .path unit found: /etc/systemd/system/paths.target.wants/tpm-udev.path — filesystem-triggered persistence")
	if !suppressed {
		t.Error("tpm-udev.path should be suppressed on Ubuntu")
	}
}

func TestCheck_SpiceVdagentModprobe(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "insmod/modprobe in persistence script",
		"insmod/modprobe call in persistence script /etc/init.d/spice-vdagent (line 40): modprobe uinput > /dev/null 2>&1")
	if !suppressed {
		t.Error("spice-vdagent modprobe should be suppressed on Ubuntu (VM guest agent)")
	}
}

func TestCheck_KdumpToolsSuspiciousExecPath(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "Suspicious systemd exec path",
		"Systemd unit kdump-tools.service ExecStart= points to suspicious path: /etc/init.d/kdump-tools")
	if !suppressed {
		t.Error("kdump-tools exec path should be suppressed on Ubuntu")
	}
}

func TestCheck_MotdNewsSuspiciousExecPath(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "Suspicious systemd exec path",
		"Systemd unit motd-news.service ExecStart= points to suspicious path: /etc/update-motd.d/50-motd-news")
	if !suppressed {
		t.Error("motd-news.service exec path should be suppressed on Ubuntu")
	}
}

func TestCheck_RcLocalSuspiciousExecPath(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("persistence", "Suspicious systemd exec path",
		"Systemd unit rc-local.service ExecStart= points to suspicious path: /etc/rc.local")
	if !suppressed {
		t.Error("/etc/rc.local exec path should be suppressed on Ubuntu")
	}
}

func TestCheck_BrlttyDeepscan(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/brltty/Contraction/de-wort.cti (line 1007) — SH016: Proxy/tunnel tool reference")
	if !suppressed {
		t.Error("brltty contraction file deepscan should be suppressed on Ubuntu")
	}
}

func TestCheck_AppArmorAbstractionsDeepscan(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/apparmor.d/abstractions/audio (line 62) — SH004: File reference under /dev/shm — in-memory staging")
	if !suppressed {
		t.Error("apparmor abstractions deepscan should be suppressed on Ubuntu (glob must cover subdirectories)")
	}
}

func TestCheck_FirefoxESRAnonExec(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Anonymous executable memory region",
		"PID 2363 (firefox-esr) has 12 anonymous executable memory region(s) — injected shellcode possible")
	if !suppressed {
		t.Error("firefox-esr anonymous exec should be suppressed (JIT runtime, Debian package name)")
	}
}

func TestCheck_GnomeTerminalAnonExec(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Anonymous executable memory region",
		"PID 2899 (gnome-terminal-) has 3 anonymous executable memory region(s) — injected shellcode possible")
	if !suppressed {
		t.Error("gnome-terminal- anonymous exec should be suppressed (VTE terminal, comm truncated)")
	}
}

func TestCheck_GnomeTerminalRWX(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "RWX memory region",
		"PID 2899 (gnome-terminal-) has 3 RWX memory region(s) — suspicious permission combination")
	if !suppressed {
		t.Error("gnome-terminal- RWX should be suppressed (VTE terminal)")
	}
}

func TestCheck_PPPSubdirFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/ppp/ip-down.d/0000usepeerdns")
	if !suppressed {
		t.Error("/etc/ppp/ip-down.d/ files should be suppressed via ** glob")
	}
}

func TestCheck_AcpiShFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/acpi/undock.sh")
	if !suppressed {
		t.Error("/etc/acpi/*.sh should be suppressed via glob (ACPI event handler)")
	}
}

func TestCheck_MissingMntNamespace_Universal(t *testing.T) {
	e, _ := New("", nil)
	cases := []string{
		"kdevtmpfs",
		"systemd-timesyn",
		"systemd-udevd",
		"switcheroo-cont",
		"systemd-logind",
		"NetworkManager",
		"ModemManager",
		"upowerd",
		"colord",
		"low-memory-moni",
		"systemd-userdbd",
		"systemd-userwor",
		"fwupd",
	}
	for _, comm := range cases {
		msg := "PID 1000 (" + comm + ") in non-host MNT namespace mnt:[4026532999]"
		suppressed, _ := e.Check("volatile", "Process in non-host mount namespace", msg)
		if !suppressed {
			t.Errorf("process %q should be suppressed for MNT namespace (standard systemd sandboxing)", comm)
		}
	}
}

func TestCheck_AvahiAutoipdActionFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/avahi/avahi-autoipd.action")
	if !suppressed {
		t.Error("/etc/avahi/avahi-autoipd.action should be suppressed (avahi-autoipd event script)")
	}
}

func TestCheck_DhclientEnterHookFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/dhcp/dhclient-enter-hooks.d/resolved")
	if !suppressed {
		t.Error("/etc/dhcp/dhclient-enter-hooks.d/* should be suppressed via glob")
	}
}

func TestCheck_DhclientExitHookFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/dhcp/dhclient-exit-hooks.d/zzz_avahi-autoipd")
	if !suppressed {
		t.Error("/etc/dhcp/dhclient-exit-hooks.d/* should be suppressed via glob")
	}
}

func TestCheck_UbuntuNMDispatcherFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/NetworkManager/dispatcher.d/01-ifupdown")
	if !suppressed {
		t.Error("/etc/NetworkManager/dispatcher.d/01-ifupdown should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuCronDailyBsdmainutilsFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/cron.daily/bsdmainutils")
	if !suppressed {
		t.Error("/etc/cron.daily/bsdmainutils should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuCronWeeklyUpdateNotifierFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/cron.weekly/update-notifier-common")
	if !suppressed {
		t.Error("/etc/cron.weekly/update-notifier-common should be suppressed on Ubuntu")
	}
}

func TestCheck_DebianAddUserPreinstDPKG(t *testing.T) {
	e, _ := New("debian", nil)
	suppressed, _ := e.Check("persistence", "Malicious DPKG lifecycle script",
		`DPKG lifecycle script /var/lib/dpkg/info/adduser.preinst contains [pipe-to-shell execution]: AUCSHA="$(< /etc/adduser.conf grep -v '^DIR_MODE' | sha512sum -)"`)
	if !suppressed {
		t.Error("adduser.preinst pipe-to-shell false positive should be suppressed on Debian (| sha512sum matches | sh substring bug)")
	}
}

func TestCheck_DebianAddUserPreinstNotUniversal(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("persistence", "Malicious DPKG lifecycle script",
		`DPKG lifecycle script /var/lib/dpkg/info/adduser.preinst contains [pipe-to-shell execution]: AUCSHA="$(< /etc/adduser.conf grep -v '^DIR_MODE' | sha512sum -)"`)
	if suppressed {
		t.Error("adduser.preinst should NOT be suppressed by universal profile (Debian-specific rule)")
	}
}

func TestCheck_UbuntuGdm3InitDefaultFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/gdm3/Init/Default")
	if !suppressed {
		t.Error("/etc/gdm3/Init/Default should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuInitdAcpidFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/init.d/acpid")
	if !suppressed {
		t.Error("/etc/init.d/acpid should be suppressed on Ubuntu")
	}
}

func TestCheck_MissingUtsNamespace_Universal(t *testing.T) {
	e, _ := New("", nil)
	cases := []string{
		"polkitd",
		"irqbalance",
		"power-profiles-",
		"systemd-timesyn",
		"systemd-udevd",
		"systemd-logind",
		"colord",
		"systemd-userdbd",
		"systemd-userwor",
	}
	for _, comm := range cases {
		msg := "PID 1000 (" + comm + ") in non-host UTS namespace uts:[4026532999]"
		suppressed, _ := e.Check("volatile", "Process in non-host uts namespace", msg)
		if !suppressed {
			t.Errorf("process %q should be suppressed for UTS namespace (systemd PrivateHostname)", comm)
		}
	}
}

func TestCheck_UbuntuInitdUdevFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/init.d/udev")
	if !suppressed {
		t.Error("/etc/init.d/udev should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuXinitrcFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/X11/xinit/xinitrc")
	if !suppressed {
		t.Error("/etc/X11/xinit/xinitrc should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuPmSleepGrubFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/pm/sleep.d/10_grub-common")
	if !suppressed {
		t.Error("/etc/pm/sleep.d/10_grub-common should be suppressed on Ubuntu")
	}
}

func TestCheck_UbuntuMotd88EsmAnnounceFHS(t *testing.T) {
	e, _ := New("ubuntu", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/update-motd.d/88-esm-announce")
	if !suppressed {
		t.Error("/etc/update-motd.d/88-esm-announce should be suppressed on Ubuntu")
	}
}

func TestCheck_DbusFiUniversal(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("persistence", "Non-standard systemd unit",
		"Non-standard systemd unit: dbus-fi.w1.wpa_supplicant1.service in /etc/systemd/system")
	if !suppressed {
		t.Error("dbus-fi.w1.wpa_supplicant1.service should be suppressed universally (standard D-Bus alias)")
	}
}

func TestNew_DebianLoadsExtraRules(t *testing.T) {
	eUniversal, _ := New("", nil)
	eDebian, _ := New("debian", nil)
	if len(eDebian.rules) <= len(eUniversal.rules) {
		t.Error("debian engine should have more rules than universal-only")
	}
}

func TestCheck_DebianRcLocalSuspiciousExecPath(t *testing.T) {
	e, _ := New("debian", nil)
	suppressed, _ := e.Check("persistence", "Suspicious systemd exec path",
		"Systemd unit rc-local.service ExecStart= points to suspicious path: /etc/rc.local")
	if !suppressed {
		t.Error("/etc/rc.local exec path should be suppressed on Debian")
	}
}

func TestCheck_DebianAppArmorDeepscan(t *testing.T) {
	e, _ := New("debian", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/apparmor.d/abstractions/audio (line 62) — SH004: File reference under /dev/shm — in-memory staging")
	if !suppressed {
		t.Error("apparmor abstractions deepscan should be suppressed on Debian")
	}
}

func TestCheck_DebianDictionaryDeepscan(t *testing.T) {
	e, _ := New("debian", nil)
	suppressed, _ := e.Check("deepscan", "Suspicious string match in config/script",
		"String match in /etc/dictionaries-common/words (line 77121) — SH026: Known open-source LKM rootkit name")
	if !suppressed {
		t.Error("/etc/dictionaries-common/words deepscan should be suppressed on Debian")
	}
}

func TestCheck_DebianBodyfileFHS(t *testing.T) {
	e, _ := New("debian", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/init.d/networking")
	if !suppressed {
		t.Error("/etc/init.d/networking should be suppressed on Debian")
	}
}

func TestCheck_GnomeSessionNetNS(t *testing.T) {
	e, _ := New("", nil)
	cases := []string{
		"dbus-daemon", "pipewire", "pipewire-pulse", "wireplumber", "mpris-proxy",
		"gnome-keyring-d", "gcr-ssh-agent", "gnome-session-b", "gnome-session-c",
		"gnome-session-s", "gnome-session-i", "gdm-wayland-ses",
		"gnome-shell", "gnome-shell-cal", "gjs", "mutter-x11-fram", "Xwayland",
		"gvfsd", "gvfsd-fuse", "gvfsd-trash", "gvfsd-recent", "gvfsd-network",
		"gvfsd-dnssd", "gvfsd-wsdd", "gvfsd-metadata",
		"gvfs-udisks2-vo", "gvfs-gphoto2-vo", "gvfs-goa-volume", "gvfs-afc-volume", "gvfs-mtp-volume",
		"xdg-desktop-por", "xdg-document-po", "xdg-permission-", "dconf-service",
		"at-spi-bus-laun", "at-spi2-registr",
		"ibus-daemon", "ibus-dconf", "ibus-extension-", "ibus-portal", "ibus-engine-sim", "ibus-x11",
		"gsd-a11y-settin", "gsd-color", "gsd-datetime", "gsd-housekeepin", "gsd-keyboard",
		"gsd-media-keys", "gsd-power", "gsd-print-notif", "gsd-rfkill", "gsd-screensaver",
		"gsd-sharing", "gsd-smartcard", "gsd-sound", "gsd-usb-protect", "gsd-wwan",
		"gsd-disk-utilit", "gsd-printer", "gsd-wacom", "gsd-xsettings",
		"goa-daemon", "goa-identity-se",
		"evolution-alarm", "evolution-sourc", "evolution-calen", "evolution-addre",
		"gnome-software", "gnome-control-c", "update-notifier",
		"localsearch-3", "localsearch-ext", "nautilus", "ptyxis", "ptyxis-agent",
		"snapd-desktop-i", "snap",
		"firefox", "firefox-esr", "crashhelper", "forkserver", "Socket Process",
	}
	for _, comm := range cases {
		msg := "PID 1234 (" + comm + ") in non-host network namespace net:[4026531833]"
		suppressed, _ := e.Check("volatile", "Process in non-host network namespace", msg)
		if !suppressed {
			t.Errorf("GNOME desktop process %q should be suppressed for network namespace finding", comm)
		}
	}
}

func TestCheck_FirefoxLDPreload_Suppressed(t *testing.T) {
	e, _ := New("", nil)
	cases := []struct {
		process string
		msg     string
	}{
		{"Socket Process", "PID 2030 (Socket Process) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"WebExtensions", "PID 2092 (WebExtensions) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"RDD Process", "PID 2097 (RDD Process) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"Privileged Cont", "PID 2128 (Privileged Cont) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"Utility Process", "PID 2226 (Utility Process) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"Isolated Servic", "PID 2263 (Isolated Servic) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"Isolated Web Co", "PID 2282 (Isolated Web Co) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
		{"Web Content", "PID 2344 (Web Content) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"},
	}
	for _, c := range cases {
		suppressed, _ := e.Check("volatile", "Suspicious process environment variable", c.msg)
		if !suppressed {
			t.Errorf("process %q: Firefox LD_PRELOAD finding should be suppressed", c.process)
		}
	}
}

func TestCheck_NonFirefoxLDPreload_NotSuppressed(t *testing.T) {
	e, _ := New("", nil)
	msg := "PID 1234 (evil-process) suspicious env var LD_PRELOAD: LD_PRELOAD points to non-standard library path — possible library injection"
	suppressed, _ := e.Check("volatile", "Suspicious process environment variable", msg)
	if suppressed {
		t.Error("non-Firefox LD_PRELOAD finding must not be suppressed")
	}
}

func TestCheck_PathfinderSudoUserSuppressed(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Suspicious process environment variable",
		"PID 3735 (pathfinder_v1.53) suspicious env var SUDO_USER: SUDO_USER present — original low-privileged user who escalated to root")
	if !suppressed {
		t.Error("SUDO_USER in pathfinder process should be suppressed (self-artifact from sudo invocation)")
	}
}

func TestCheck_PathfinderSudoUserSuppressed_PlainName(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Suspicious process environment variable",
		"PID 1234 (pathfinder) suspicious env var SUDO_USER: SUDO_USER present — original low-privileged user who escalated to root")
	if !suppressed {
		t.Error("SUDO_USER in plain 'pathfinder' process should be suppressed")
	}
}

func TestCheck_PathfinderSudoUserNotSuppressedForOtherProcess(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Suspicious process environment variable",
		"PID 1234 (evil-backdoor) suspicious env var SUDO_USER: SUDO_USER present — original low-privileged user who escalated to root")
	if suppressed {
		t.Error("SUDO_USER in non-pathfinder process must NOT be suppressed")
	}
}

func TestCheck_X11LockFile(t *testing.T) {
	e, _ := New("", nil)
	for _, name := range []string{".X0-lock", ".X1-lock", ".X1024-lock", ".X1025-lock"} {
		suppressed, _ := e.Check("bodyfile", "Recent activity in volatile/hidden path",
			"Recent activity in volatile/hidden path: /tmp/"+name)
		if !suppressed {
			t.Errorf("/tmp/%s should be suppressed (X11 display lock file)", name)
		}
	}
}

func TestCheck_VMwareToolsDeepFHS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "FHS violation: executable in non-exec directory",
		"FHS violation: executable in non-exec directory: /etc/vmware-tools/scripts/vmware/network")
	if !suppressed {
		t.Error("/etc/vmware-tools/scripts/vmware/network should be suppressed (VMware Tools script, deep path)")
	}
}

func TestCheck_RHELKdumpGenerator(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("persistence", "Non-standard systemd generator",
		"Non-standard systemd generator in /usr/lib/systemd/system-generators: kdump-dep-generator.sh")
	if !suppressed {
		t.Error("kdump-dep-generator.sh should be suppressed on RHEL (standard kdump generator)")
	}
}

func TestCheck_RHELPodmanGenerator(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("persistence", "Non-standard systemd generator",
		"Non-standard systemd generator in /usr/lib/systemd/system-generators: podman-system-generator")
	if !suppressed {
		t.Error("podman-system-generator should be suppressed on RHEL (standard podman generator)")
	}
}

func TestCheck_SystemdUdevdUdevadmMismatch(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("audit", "Process binary mismatch",
		"Process name mismatch: _COMM=systemd-udevd does not match executable /usr/bin/udevadm")
	if !suppressed {
		t.Error("systemd-udevd/udevadm mismatch should be suppressed (systemd >= v249 merged udevd into udevadm)")
	}
}

func TestCheck_RHELSELinuxGenerator(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("persistence", "Non-standard systemd generator",
		"Non-standard systemd generator in /usr/lib/systemd/system-generators: selinux-autorelabel-generator.sh")
	if !suppressed {
		t.Error("selinux-autorelabel-generator.sh should be suppressed on RHEL (standard SELinux generator)")
	}
}

func TestCheck_RHELCockpitMOTD(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("persistence", "Recently added executable MOTD script",
		"Executable MOTD script added within 72h: /etc/motd.d/cockpit")
	if !suppressed {
		t.Error("/etc/motd.d/cockpit should be suppressed on RHEL (cockpit package MOTD script)")
	}
}

func TestCheck_RHELUnknownGeneratorNotSuppressed(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("persistence", "Non-standard systemd generator",
		"Non-standard systemd generator in /usr/lib/systemd/system-generators: evil-backdoor-generator")
	if suppressed {
		t.Error("unknown generator must NOT be suppressed — only named RHEL generators are allowed")
	}
}

func TestCheck_LowMemoryMonitorNetNS(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process in non-host network namespace",
		"PID 799 (low-memory-moni) in non-host NET namespace net:[4026532692]")
	if !suppressed {
		t.Error("low-memory-moni should be suppressed for NET namespace (GNOME low-memory-monitor private netns)")
	}
}

func TestCheck_FirefoxSubprocessCWDProc(t *testing.T) {
	e, _ := New("", nil)
	cases := []struct {
		comm string
		exe  string
	}{
		{"Socket Process", "/usr/lib/firefox-esr/firefox-esr"},
		{"Privileged Cont", "/usr/lib/firefox-esr/firefox-esr"},
		{"RDD Process", "/usr/lib/firefox-esr/firefox-esr"},
		{"WebExtensions", "/usr/lib/firefox-esr/firefox-esr"},
		{"Utility Process", "/usr/lib/firefox-esr/firefox-esr"},
		{"Isolated Servic", "/usr/lib/firefox-esr/firefox-esr"},
		{"Isolated Web Co", "/usr/lib/firefox-esr/firefox-esr"},
		{"Web Content", "/usr/lib/firefox-esr/firefox-esr"},
	}
	for _, c := range cases {
		msg := "PID 2406 (" + c.comm + ") CWD=/proc/2407/fdinfo exe=" + c.exe
		suppressed, _ := e.Check("volatile", "Process CWD in staging directory", msg)
		if !suppressed {
			t.Errorf("Firefox subprocess %q with CWD=/proc/*/fdinfo should be suppressed (sandbox IPC)", c.comm)
		}
	}
}

func TestCheck_RtkitDaemonCWDProc(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process CWD in staging directory",
		"PID 973 (rtkit-daemon) CWD=/proc exe=/usr/libexec/rtkit-daemon")
	if !suppressed {
		t.Error("rtkit-daemon CWD=/proc should be suppressed (reads RT scheduling info from procfs)")
	}
}

func TestCheck_FirefoxCWDProc_NotSuppressedForMalwareDir(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("volatile", "Process CWD in staging directory",
		"PID 1234 (evil-shell) CWD=/tmp/staging exe=/tmp/evil")
	if suppressed {
		t.Error("non-Firefox process in /tmp staging dir must not be suppressed")
	}
}

func TestCheck_LttngUstWaitShmFile(t *testing.T) {
	e, _ := New("", nil)
	for _, name := range []string{
		"lttng-ust-wait-8",
		"lttng-ust-wait-8-1000",
		"lttng-ust-wait-8-110",
	} {
		suppressed, _ := e.Check("bodyfile", "Recent activity in volatile/hidden path",
			"Recent activity in volatile/hidden path: /dev/shm/"+name)
		if !suppressed {
			t.Errorf("/dev/shm/%s should be suppressed (LTTng userspace tracer IPC semaphore)", name)
		}
	}
}

func TestCheck_FirefoxMozillaExecutableBit(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "Executable in volatile/hidden path",
		"Executable in volatile/hidden path: /home/conan/.mozilla/firefox/5jczsw8g.default-esr/times.json")
	if !suppressed {
		t.Error("Firefox profile data file with execute bit under .mozilla/ should be suppressed")
	}
}

func TestCheck_LttngShmNotSuppressedOutsideDevShm(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "Recent activity in volatile/hidden path",
		"Recent activity in volatile/hidden path: /tmp/lttng-ust-wait-8")
	if suppressed {
		t.Error("lttng file in /tmp (not /dev/shm) must not be suppressed")
	}
}

func TestCheck_RHELMissingMntNamespace(t *testing.T) {
	e, _ := New("rhel", nil)
	cases := []string{
		"dbus-broker",
		"dbus-broker-lau",
		"chronyd",
		"firewalld",
		"rsyslogd",
	}
	for _, comm := range cases {
		msg := "PID 1000 (" + comm + ") in non-host MNT namespace mnt:[4026532999]"
		suppressed, _ := e.Check("volatile", "Process in non-host mount namespace", msg)
		if !suppressed {
			t.Errorf("RHEL process %q should be suppressed for MNT namespace", comm)
		}
	}
}

func TestCheck_RHELMissingUtsNamespace(t *testing.T) {
	e, _ := New("rhel", nil)
	cases := []string{"chronyd", "firewalld"}
	for _, comm := range cases {
		msg := "PID 1000 (" + comm + ") in non-host UTS namespace uts:[4026532999]"
		suppressed, _ := e.Check("volatile", "Process in non-host uts namespace", msg)
		if !suppressed {
			t.Errorf("RHEL process %q should be suppressed for UTS namespace", comm)
		}
	}
}

func TestCheck_RHELLibpodLock(t *testing.T) {
	e, _ := New("rhel", nil)
	suppressed, _ := e.Check("bodyfile", "Recent activity in volatile/hidden path",
		"Recent activity in volatile/hidden path: /dev/shm/libpod_lock")
	if !suppressed {
		t.Error("/dev/shm/libpod_lock should be suppressed on RHEL (podman container state lock)")
	}
}

func TestCheck_RHELLibpodLockNotUniversal(t *testing.T) {
	e, _ := New("", nil)
	suppressed, _ := e.Check("bodyfile", "Recent activity in volatile/hidden path",
		"Recent activity in volatile/hidden path: /dev/shm/libpod_lock")
	if suppressed {
		t.Error("/dev/shm/libpod_lock should NOT be suppressed by universal profile (RHEL-specific rule)")
	}
}

func TestExtractPath_TrimsReasonSuffix(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"Suspicious unit: /etc/systemd/system/x.service — installed today", "/etc/systemd/system/x.service"},
		{"backdoor: /usr/local/bin/evil", "/usr/local/bin/evil"},
		{"label: /path more words", "/path"},
	}
	for _, c := range cases {
		if got := extractPath(c.msg); got != c.want {
			t.Errorf("extractPath(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}
