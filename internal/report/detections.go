package report

// Detection defines a finding type with its analyst context.
type Detection struct {
	Category   string
	WhyFlagged string
	NextSteps  string
}

// Detections maps label keys (used as the label arg in Registry.Add) to their
// category and analyst guidance. The report writer derives grouping and tips
// from this map. Any label missing from this map will render without tips and
// emit a warning to stderr.
var Detections = map[string]Detection{

	"User crontab found": {
		Category:   "persistence",
		WhyFlagged: "User crontabs run arbitrary code on a schedule without requiring root.",
		NextSteps:  "Review each entry's command and schedule, then correlate them with the applications you know are installed.",
	},
	"Non-standard systemd unit": {
		Category:   "persistence",
		WhyFlagged: "A systemd unit in /etc/systemd/system that package management never installed usually means someone added persistence by hand.",
		NextSteps:  "Diff it against your authorized unit-file baseline, then audit the ExecStart path and the install timestamp.",
	},
	"Systemd .path unit found": {
		Category:   "persistence",
		WhyFlagged: ".path units trigger a service whenever a file changes. That makes them a quiet way to keep code running across reboots.",
		NextSteps:  "Identify the service it activates, trace the full ExecStart execution chain, then check for file-drop patterns.",
	},
	"Non-standard systemd generator": {
		Category:   "persistence",
		WhyFlagged: "Generators run very early at boot and can inject arbitrary units before normal policy ever applies.",
		NextSteps:  "Read the generator script, then audit what units it creates and whether they existed before the incident window.",
	},
	"User-level systemd persistence unit": {
		Category:   "persistence",
		WhyFlagged: "Per-user systemd units persist across logins for that one user, which makes them handy for targeted backdoors.",
		NextSteps:  "Enumerate all user unit directories, then cross-reference them with account creation timestamps.",
	},
	"Suspicious udev rule": {
		Category:   "persistence",
		WhyFlagged: "udev RUN+= and IMPORT{program} directives run arbitrary code the moment a device event fires.",
		NextSteps:  "Inspect the rule's RUN= target, then verify it matches authorized hardware management software.",
	},
	"XDG autostart entries": {
		Category:   "persistence",
		WhyFlagged: "Desktop autostart .desktop entries run arbitrary binaries when a user logs in.",
		NextSteps:  "Inspect each .desktop file's Exec= field, then validate it against installed applications.",
	},
	"Malicious XDG autostart entry": {
		Category:   "persistence",
		WhyFlagged: "This XDG .desktop Exec= field points at a malware staging path, a shell interpreter with an inline payload, or a hidden directory. That is a common way for non-root attackers to persist through user login.",
		NextSteps:  "Inspect the Exec= field, confirm the binary exists and is known-good, then cross-reference with the file timeline and process execution logs.",
	},
	"Suspicious XDG autostart entry": {
		Category:   "persistence",
		WhyFlagged: "This XDG .desktop Exec= references a binary that is not on disk. That can mean a dropped payload was cleaned up, or the entry is just misconfigured.",
		NextSteps:  "Confirm whether the referenced binary was ever present, then check the bodyfile timeline for the path.",
	},
	"insmod/modprobe in persistence script": {
		Category:   "persistence",
		WhyFlagged: "Loading a kernel module from a persistence script or a staging path can install a rootkit at boot.",
		NextSteps:  "Identify the module being loaded, check its signing status with modinfo, then compare it against a known-good module list.",
	},
	"Suspicious systemd exec path": {
		Category:   "persistence",
		WhyFlagged: "When a systemd ExecStart points at a staging or non-standard path, the service has usually been backdoored.",
		NextSteps:  "Hash the binary at the exec path, check threat intel, then review the service creation timestamp.",
	},
	"Suspicious MotD/profile script command": {
		Category:   "persistence",
		WhyFlagged: "Commands in MotD or profile scripts run on every user login, which is a common persistence vector.",
		NextSteps:  "Review the full script content for network calls, file drops, or encoded payloads.",
	},
	"Executable in staging directory": {
		Category:   "persistence",
		WhyFlagged: "Executables in /tmp, /dev/shm, or /var/tmp slip past application-whitelist controls, and that usually means malware is being staged.",
		NextSteps:  "Hash the binary and check it against threat intel, then capture it for forensic analysis before you remediate.",
	},
	"Suspicious shell history match": {
		Category:   "persistence",
		WhyFlagged: "Shell history entries that match known-malicious patterns point to commands the attacker ran in the past.",
		NextSteps:  "Review the full history context around the match, then correlate it with authentication events and filesystem changes.",
	},
	"Triple-dot hidden persistence directory": {
		Category:   "persistence",
		WhyFlagged: "/etc/... is a hidden triple-dot directory that attackers use to store backdoor components out of sight.",
		NextSteps:  "List every file inside /etc/..., hash each one, then cross-reference them with known threat IOC lists.",
	},
	"Suspicious sshd_config directive": {
		Category:   "persistence",
		WhyFlagged: "This sshd_config directive looks like a persistence or privilege-escalation mechanism.",
		NextSteps:  "Diff sshd_config against a known-good baseline, then check whether ForceCommand points to a staging-dir binary.",
	},
	"sshd_config recently modified": {
		Category:   "persistence",
		WhyFlagged: "An sshd_config change outside a change window can mean a backdoor was just installed.",
		NextSteps:  "Review the diff of the modified config, then verify it against change management records.",
	},
	"passwd/group file modified": {
		Category:   "persistence",
		WhyFlagged: "New or removed lines in /etc/passwd or /etc/group since the last backup point to account manipulation.",
		NextSteps:  "Validate every change against the HR/AD roster, then check the timestamps against known admin windows.",
	},
	"Malicious cron job": {
		Category:   "persistence",
		WhyFlagged: "A cron entry carries a known reverse-shell or download-and-execute payload, which is direct evidence of scheduled malicious execution.",
		NextSteps:  "Identify the cron file and the entry owner, cross-reference the creation time with the incident timeline, then remove the entry and audit the remaining crontabs.",
	},
	"Malicious cron script": {
		Category:   "persistence",
		WhyFlagged: "A script in /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, or /etc/cron.monthly carries a known reverse-shell or download-and-execute payload, and it runs as root on a recurring schedule.",
		NextSteps:  "Read the full script, remove or quarantine it, then audit the other scripts in the same cron directory for similar insertions.",
	},
	"Recently added cron script": {
		Category:   "persistence",
		WhyFlagged: "A script in a system cron directory appeared or changed within 72 hours. Cron drop-ins run as root automatically, so this is a common persistence mechanism.",
		NextSteps:  "Review the script content, confirm it is expected (for example, installed by a package), then check the ownership and timestamps against the incident window.",
	},
	"Malicious anacron job": {
		Category:   "persistence",
		WhyFlagged: "An /etc/anacrontab entry carries a known reverse-shell or download-and-execute payload, and anacron runs missed jobs as root once the system comes back up.",
		NextSteps:  "Read the flagged anacrontab line, remove the malicious command, then check /var/spool/anacron for job state files.",
	},
	"Malicious systemd ExecStart": {
		Category:   "persistence",
		WhyFlagged: "A user-level systemd service unit's ExecStart= carries a reverse-shell or staged-binary command, so attacker code runs on user login or on a timer.",
		NextSteps:  "Read the full unit file, disable and mask the service, then trace when the unit was created using file timestamps.",
	},
	"Malicious shell profile command": {
		Category:   "persistence",
		WhyFlagged: "A shell startup file (for example, .bash_profile or .bashrc) carries a network reverse-shell or download-and-execute payload, and it runs on every interactive login.",
		NextSteps:  "Review the full profile file, remove the malicious line, then check /etc/profile and all user dotfiles for similar insertions.",
	},
	"Malicious legacy init script": {
		Category:   "persistence",
		WhyFlagged: "A legacy init script (for example, /etc/rc.local) carries a known reverse-shell or download-and-execute payload, so attacker code runs at system startup.",
		NextSteps:  "Review the flagged line, check file ownership and timestamps, then diff it against a known-good backup or package baseline.",
	},
	"VMware service modification": {
		Category:   "persistence",
		WhyFlagged: "A recent change to a VMware service init script (for example, vami-lighttp) is a known persistence indicator.",
		NextSteps:  "Hash the modified script, compare it against VMware vendor checksums, then check for ExecStart path changes.",
	},
	"Recently modified legacy init file": {
		Category:   "persistence",
		WhyFlagged: "A legacy init file changed within 72 hours, and unexpected edits to init scripts are a common persistence technique.",
		NextSteps:  "Diff the file against a known-good backup or package baseline, then check who last modified it and correlate that with auth logs.",
	},
	"Malicious init.d script": {
		Category:   "persistence",
		WhyFlagged: "An /etc/init.d service script carries a known reverse-shell or download-and-execute payload, so attacker code runs on service start or system boot.",
		NextSteps:  "Read the full script, disable the service, then check file timestamps and owner against the incident window.",
	},
	"Recently added init.d script": {
		Category:   "persistence",
		WhyFlagged: "An /etc/init.d script appeared or changed within 72 hours, and an unexpected init.d addition usually means planted persistence.",
		NextSteps:  "Read the script content, verify it against the expected package, then check when the associated service was enabled.",
	},
	"Malicious udev RUN command": {
		Category:   "persistence",
		WhyFlagged: "A udev rule's RUN+= or IMPORT{program} directive carries a known malicious payload, and it runs as root whenever the matching device event fires.",
		NextSteps:  "Read the full udev rule file, remove the malicious RUN+= or IMPORT{program} line, then check when the rule was created and which device event triggers it.",
	},
	"Recently added udev rule": {
		Category:   "persistence",
		WhyFlagged: "A udev rule file appeared or changed within 72 hours. udev rules run code as root on device events, which makes them a stealthy persistence vector.",
		NextSteps:  "Review the rule file contents, confirm it is authorized hardware management, then check the file timestamps against the incident window.",
	},
	"Recently added executable MOTD script": {
		Category:   "persistence",
		WhyFlagged: "An executable MOTD script appeared or changed within 72 hours. MOTD scripts run on every SSH login, which makes them a common persistence vector.",
		NextSteps:  "Read the script for network calls or payloads, verify it against the expected MOTD package, then check file ownership.",
	},
	"Malicious APT hook command": {
		Category:   "persistence",
		WhyFlagged: "An APT hook configuration holds a command that matches known malicious patterns, and it runs as root during any apt install, update, or remove.",
		NextSteps:  "Review the full APT hook config file, then remove the malicious command before running any further apt operations.",
	},
	"Recently added APT hook config": {
		Category:   "persistence",
		WhyFlagged: "An APT hook configuration file appeared or changed within 72 hours. APT hooks run arbitrary commands as root during package operations.",
		NextSteps:  "Read the hook config content, confirm it is authorized tooling (for example, unattended-upgrades), then check the file timestamps against the incident window.",
	},
	"Malicious yum plugin": {
		Category:   "persistence",
		WhyFlagged: "A yum plugin script carries a known malicious payload, and yum plugins run as root during any package manager operation.",
		NextSteps:  "Read the full plugin file, disable or remove the malicious plugin, then verify whether it came from an authorized repository.",
	},
	"Malicious dnf plugin": {
		Category:   "persistence",
		WhyFlagged: "A dnf plugin script carries a known malicious payload, and dnf plugins run as root during any package manager operation.",
		NextSteps:  "Read the full plugin file, disable or remove the malicious plugin, then verify whether it came from an authorized repository.",
	},
	"Malicious git hook": {
		Category:   "persistence",
		WhyFlagged: "A git hook carries a known malicious payload, and hooks run automatically on git operations (commit, push, merge) for everyone who uses the repository.",
		NextSteps:  "Read the hook script, remove the malicious lines, then audit the other hooks in the same repository and any global git hook directory.",
	},
	"Recently added git hook": {
		Category:   "persistence",
		WhyFlagged: "An executable git hook appeared or changed within 72 hours. git hooks run on developer operations, which makes them a covert persistence vector in shared repositories.",
		NextSteps:  "Review the hook content, confirm with the repository owner that it is authorized, then check the hook's mtime against the incident window.",
	},
	"Malicious gitconfig hook": {
		Category:   "persistence",
		WhyFlagged: "A gitconfig core.pager or core.editor value carries a known malicious payload, and it runs whenever the configured git operation runs.",
		NextSteps:  "Read the gitconfig file, remove or reset the malicious directive, then check all user gitconfig files (~/.gitconfig and /etc/gitconfig) for similar tampering.",
	},
	"Suspicious gitconfig hooksPath": {
		Category:   "persistence",
		WhyFlagged: "A gitconfig core.hooksPath points to a non-standard directory, and git hooks in that directory run automatically on commit, push, and merge for everyone who uses the repository.",
		NextSteps:  "Inspect the hooksPath directory contents, confirm each hook script is authorized, then check when the core.hooksPath directive was added.",
	},
	"Malicious gitconfig hooksPath": {
		Category:   "persistence",
		WhyFlagged: "A gitconfig core.hooksPath points to a known malware staging directory. The hooks there run as the developer on every git operation, which gives persistent code execution without ever touching the repository's own .git/hooks.",
		NextSteps:  "Remove the core.hooksPath directive, inspect and quarantine the scripts in the staging directory, then audit all user and system gitconfig files for similar redirections.",
	},
	"Malicious web shell": {
		Category:   "persistence",
		WhyFlagged: "A file in a web server root directory carries a known reverse-shell or command-execution payload, which points to a web shell backdoor.",
		NextSteps:  "Take the file offline immediately, hash it for threat intel, audit web server access logs for requests to this path, then check for other dropped files in the web root.",
	},
	"Recently added web script": {
		Category:   "persistence",
		WhyFlagged: "A script file in a web root appeared within 72 hours with execute permissions or inside a cgi-bin directory, which can mean a freshly deployed web shell.",
		NextSteps:  "Review the file content, confirm it matches a known application deployment, then correlate it with deployment records and web server logs.",
	},
	"Shared object in staging directory": {
		Category:   "persistence",
		WhyFlagged: "A .so shared library in /tmp, /dev/shm, or /var/tmp usually means a compiled LD_PRELOAD backdoor has been staged for injection.",
		NextSteps:  "Hash the file and check threat intel, determine whether /etc/ld.so.preload references it, then capture it for forensic analysis.",
	},
	"LD_PRELOAD rootkit indicator": {
		Category:   "persistence",
		WhyFlagged: "/etc/ld.so.preload is non-empty. Any content there forces every subsequent process to load the listed libraries, which is the defining characteristic of an LD_PRELOAD rootkit.",
		NextSteps:  "Hash each listed library, check whether the file was recently modified (see the 'Recently modified LD_PRELOAD config' finding), then look for matching .so files in staging directories (see the 'Shared object in staging directory' finding).",
	},
	"Malicious LD_PRELOAD entry": {
		Category:   "persistence",
		WhyFlagged: "An /etc/ld.so.preload entry resolves to a known malware staging path (/tmp, /dev/shm, /var/tmp).",
		NextSteps:  "Remove the entry, delete or quarantine the library, then check which processes have it loaded via /proc/*/maps.",
	},
	"Missing LD_PRELOAD library": {
		Category:   "persistence",
		WhyFlagged: "An /etc/ld.so.preload entry references a file that does not exist. The library may have been removed after rootkit persistence was established, or the entry could be a denial-of-service artifact.",
		NextSteps:  "Remove the entry, then check filesystem timestamps and auth.log around the time the entry was created.",
	},
	"Malicious ld.so.conf entry": {
		Category:   "persistence",
		WhyFlagged: "An /etc/ld.so.conf or included conf file specifies a library search path inside a known malware staging directory (/tmp, /dev/shm, /var/tmp), so any .so dropped there is loaded by every subsequent process.",
		NextSteps:  "Remove the malicious path entry, run `ldconfig` to rebuild the cache, then check for .so files in the staging directory.",
	},
	"Recently modified ld.so.conf": {
		Category:   "persistence",
		WhyFlagged: "/etc/ld.so.conf or an included conf file changed within 72 hours. This file controls the system-wide library search paths, so a change outside package management points to tampering.",
		NextSteps:  "Review all entries in /etc/ld.so.conf and /etc/ld.so.conf.d/, cross-reference with LD_PRELOAD rootkit indicators, then run `ldconfig -p` to inspect the current cache.",
	},
	"Recently modified LD_PRELOAD config": {
		Category:   "persistence",
		WhyFlagged: "/etc/ld.so.preload changed within 72 hours. This file has no legitimate reason to change outside a deliberate rootkit installation.",
		NextSteps:  "Review the file contents, then cross-reference with the 'LD_PRELOAD rootkit indicator' and 'Malicious LD_PRELOAD entry' findings.",
	},

	"Malicious at/batch job": {
		Category:   "persistence",
		WhyFlagged: "An at/batch spool file carries a known reverse-shell or download-and-execute payload, and it runs once at the scheduled time as the job owner.",
		NextSteps:  "Read the job content with `at -c <job_id>`, remove it with `atrm <job_id>`, then check for additional jobs queued by the same user.",
	},

	"at/batch job queued": {
		Category:   "scheduled-tasks",
		WhyFlagged: "at/batch jobs are single-execution scheduled tasks, which attackers often use for delayed payload execution.",
		NextSteps:  "List the queue with `atq`, read each job's content with `at -c <job_id>`, then check the job owner.",
	},

	"Deleted file descriptor still open": {
		Category:   "volatile",
		WhyFlagged: "A deleted binary still mapped in memory usually means the executable was removed to dodge disk scanning.",
		NextSteps:  "Capture the file via /proc/<PID>/fd/<n> before the process exits, then submit it for analysis.",
	},
	"Shell process missing standard env vars": {
		Category:   "volatile",
		WhyFlagged: "Shell processes spawned by web shells or exploits often lack PATH, HOME, and USER, which are telltale signs of non-interactive execution.",
		NextSteps:  "Trace the process parent chain, then correlate it with web server access logs for the spawn timestamp.",
	},
	"Orphan process detected": {
		Category:   "volatile",
		WhyFlagged: "An orphan process whose parent no longer exists can mean a rootkit reparented it to hide its lineage.",
		NextSteps:  "Capture /proc/<PID>/status, exe, and maps, then correlate the parent PID's disappearance with other events.",
	},
	"Running deleted binary": {
		Category:   "volatile",
		WhyFlagged: "A process whose on-disk binary was deleted is a classic in-memory implant evasion technique.",
		NextSteps:  "Dump the process image via /proc/<PID>/exe, hash it and check threat intel, then escalate to IR.",
	},
	"Suspicious memory map": {
		Category:   "volatile",
		WhyFlagged: "Memory maps that reference deleted paths, memfd: anonymous execs, malware staging directories, or user-home executable libraries point to in-memory execution or dropped-file techniques.",
		NextSteps:  "Capture /proc/<PID>/maps and /proc/<PID>/mem for the flagged regions, then correlate them with the file timeline.",
	},
	"Anonymous executable memory region": {
		Category:   "volatile",
		WhyFlagged: "An anonymous executable memory region with no backing file points to injected shellcode.",
		NextSteps:  "Dump the anonymous region using /proc/<PID>/mem, then submit it to a sandbox for behavioral analysis.",
	},
	"RWX memory region": {
		Category:   "volatile",
		WhyFlagged: "Memory that is writable and executable at the same time is what shellcode loaders and in-memory implants rely on.",
		NextSteps:  "Identify the region's backing file (or confirm there is none), then cross-reference it with the loaded module list.",
	},
	"RWX file-backed memory region": {
		Category:   "volatile",
		WhyFlagged: "A named file is loaded into memory with read, write, and execute permissions all at once. That is what shellcode loaders and in-memory implants use, and it is distinct from anonymous RWX shellcode.",
		NextSteps:  "Identify the backing file, check whether it was legitimately linked rwxp, then hash it and submit for threat intel.",
	},
	"Process in non-host network namespace": {
		Category:   "volatile",
		WhyFlagged: "A process in a non-host network namespace can have hidden network connectivity that host-level monitoring never sees.",
		NextSteps:  "Inspect the namespace with `nsenter`, then check for listening services or established connections inside it.",
	},
	"Process in non-host mount namespace": {
		Category:   "volatile",
		WhyFlagged: "The process runs in a mount namespace different from PID 1, which means private filesystem isolation. This is common with systemd unit sandboxing (PrivateMounts=yes) and container runtimes, so correlate with section 14 to confirm whether this is a known container before you escalate.",
		NextSteps:  "Check section 14 (container analysis) to see whether this is a legitimate container process. If it is not, inspect the mount namespace via /proc/<pid>/mounts for unusual bind mounts or hidden filesystems.",
	},
	"Process in non-host uts namespace": {
		Category:   "volatile",
		WhyFlagged: "The process runs with a different UTS (hostname/domain) namespace than PID 1. That is normal for containers but rare for host processes, and a host process with a private UTS namespace may be hiding its hostname from detection tools.",
		NextSteps:  "Check section 14 (container analysis) first. If the process is not a known container, inspect /proc/<pid>/uts for the hostname and correlate it with the process binary and parent chain.",
	},
	"Suspicious process environment variable": {
		Category:   "volatile",
		WhyFlagged: "Suspicious environment variables (LD_PRELOAD, HISTFILE=/dev/null, SSH_ORIGINAL_COMMAND) point to attacker activity.",
		NextSteps:  "Capture the full environment from /proc/<PID>/environ, then trace how the variable was set.",
	},
	"Hidden process detected": {
		Category:   "volatile",
		WhyFlagged: "A process you can find by brute-force PID walk but that is missing from the /proc listing is being hidden by a kernel-level rootkit.",
		NextSteps:  "Capture all available /proc/<PID>/* data immediately. This is strong evidence of a kernel rootkit.",
	},
	"Process holding BPF program FDs": {
		Category:   "volatile",
		WhyFlagged: "An unexpected process holding BPF program file descriptors may be using eBPF for kernel-level hooking.",
		NextSteps:  "Use `bpftool prog show` to enumerate the programs, then check for kprobe or tracepoint hooks on sensitive syscalls.",
	},
	"VFS hook suspected (inode discrepancy)": {
		Category:   "volatile",
		WhyFlagged: "Inode discrepancies between ReadDir and Lstat point to a VFS-level hook hiding files, which is a rootkit indicator.",
		NextSteps:  "Cross-reference with a clean liveCD, then capture filesystem images before remediation.",
	},
	"Service crash loop": {
		Category:   "volatile",
		WhyFlagged: "A service crashing in rapid succession can mean someone is throwing exploits at a vulnerable service.",
		NextSteps:  "Review the service logs and core dumps for the crash window, then check for exploit-pattern input.",
	},
	"Recent activity in volatile/hidden path": {
		Category:   "volatile",
		WhyFlagged: "Recent file activity in /tmp, /dev/shm, or hidden paths within 72 hours points to active staging. An executable in /var/run/ is anomalous regardless of age, because that directory never legitimately holds executable files.",
		NextSteps:  "Hash the file, check its mtime/ctime against other events, then capture it before the contents change.",
	},
	"Executable in volatile/hidden path": {
		Category:   "volatile",
		WhyFlagged: "An executable in /tmp, /dev/shm, a hidden directory, or another volatile path is a strong sign of attacker staging. Legitimate software does not run from these locations.",
		NextSteps:  "Hash the binary and search threat intel, check the parent process and network connections, then capture and preserve it before it is deleted.",
	},
	"Process running outside safe directory": {
		Category:   "volatile",
		WhyFlagged: "A process executing from a non-standard directory (outside /bin, /usr, /sbin, and the like) is a common sign of a staged or relocated binary.",
		NextSteps:  "Hash the binary, check the parent process lineage, then verify it against your installed software baseline.",
	},
	"Suspicious process cmdline": {
		Category:   "volatile",
		WhyFlagged: "A process command line that matches known-malicious string patterns points to attacker tooling in use.",
		NextSteps:  "Capture the full cmdline and parent chain, then correlate it with network connections from the same PID.",
	},
	"High CPU usage (cryptominer heuristic)": {
		Category:   "volatile",
		WhyFlagged: "The process has sustained high CPU usage over its lifetime, which is consistent with cryptomining or other compute-intensive malware. Known heavy processes (databases, compilers, media encoders) are suppressed from this check.",
		NextSteps:  "Identify the binary path and parent process, correlate with section 06 (network connections) for outbound traffic to known mining pool ports (3333, 4444, 14444, 45560), then hash the binary and check threat intel.",
	},
	"High memory usage": {
		Category:   "volatile",
		WhyFlagged: "The process resident set is over 500MB, which can mean a memory-resident implant, a large dataset staged for exfiltration, or an injected process carrying extra payloads in its heap.",
		NextSteps:  "Cross-reference with section 04 (memory maps) for anonymous executable regions or deleted-binary mappings, check the binary path against safe directories, then review the parent process chain.",
	},
	"Process CWD in staging directory": {
		Category:   "volatile",
		WhyFlagged: "The process working directory is a known malware staging path (/tmp, /dev/shm, /var/tmp, /proc). Legitimate software does not operate from these directories, and when this pairs with a deleted or staging-dir executable it is a strong sign of active malware.",
		NextSteps:  "Correlate with section 03 (process binaries) for the executable hash, check section 04 (memory maps) for in-memory execution artifacts, then review the parent process chain in section 02 (process tree).",
	},
	"Suspicious strings in process binary": {
		Category:   "volatile",
		WhyFlagged: "Known-malicious IOC signature strings (C2 infrastructure patterns, reverse shell indicators, known malware artifacts) turned up in the binary image of a process that other checks already flagged. The binary was read directly from /proc/<pid>/exe.",
		NextSteps:  "Hash the binary and submit it to threat intel, preserve the binary for forensic analysis before any remediation, then if HIGH-severity strings match, treat it as confirmed malware and escalate per the IR plan.",
	},
	"Compressed file in staging directory": {
		Category:   "volatile",
		WhyFlagged: "Compressed archives in staging directories are used to stage and exfiltrate data or to deliver payloads.",
		NextSteps:  "List the archive contents without extracting, then check the file owner and creation time against the incident timeline.",
	},

	"SSH tunnel/proxy directive": {
		Category:   "lateral-movement",
		WhyFlagged: "ProxyJump, ProxyCommand, or DynamicForward in SSH configs let traffic tunnel through this host.",
		NextSteps:  "Identify the tunnel destination, then review outbound network flows from this host to that target.",
	},
	"Established connection on non-standard port": {
		Category:   "lateral-movement",
		WhyFlagged: "An established connection on a non-standard port can mean C2 beaconing or a data exfiltration channel.",
		NextSteps:  "Correlate the remote IP with threat intel, then check which process owns the socket.",
	},
	"Network interface in promiscuous mode": {
		Category:   "lateral-movement",
		WhyFlagged: "Promiscuous mode captures all network traffic on the segment, which points to an active packet sniffer.",
		NextSteps:  "Identify the process holding the raw socket, then check for credential capture tools.",
	},
	"Packet sniffer detected": {
		Category:   "lateral-movement",
		WhyFlagged: "An active packet sniffer can capture credentials and session tokens in transit.",
		NextSteps:  "Identify the sniffer binary and its owner, then check for output files containing captured data.",
	},
	"USB/mass storage insertion": {
		Category:   "lateral-movement",
		WhyFlagged: "USB storage inserted outside expected maintenance windows can mean physical data exfiltration.",
		NextSteps:  "Correlate the USB insertion timestamps with user session events, then check for large file copies.",
	},
	"Non-loopback /etc/hosts entry": {
		Category:   "lateral-movement",
		WhyFlagged: "Custom /etc/hosts entries can redirect DNS resolution for specific domains, which is used in credential theft and C2.",
		NextSteps:  "Verify each non-loopback entry is authorized, then check whether it redirects any sensitive service hostname.",
	},

	"Non-root UID-0 account": {
		Category:   "users",
		WhyFlagged: "More than one UID-0 account gives persistent root-equivalent access without ever touching the root account directly.",
		NextSteps:  "Validate every UID-0 account against the HR/AD roster, then check the account creation timestamp and shell history.",
	},
	"Account creation event": {
		Category:   "users",
		WhyFlagged: "An account created outside a provisioning window can be an attacker-added backdoor account.",
		NextSteps:  "Verify the new account against HR/AD, then check the creating process and its UID.",
	},
	"Account deletion event": {
		Category:   "users",
		WhyFlagged: "An account deletion can cover an attacker's tracks by removing evidence of temporary access.",
		NextSteps:  "Check what the deleted account last accessed, then review auth logs for its session activity.",
	},
	"Sensitive group membership change": {
		Category:   "users",
		WhyFlagged: "Adding users to sudo, wheel, shadow, or docker groups grants elevated privileges that persist.",
		NextSteps:  "Verify the change was authorized, then identify which process ran the group modification.",
	},
	"Privilege escalation event": {
		Category:   "users",
		WhyFlagged: "sudo or pkexec invocations from non-root UIDs point to privilege escalation activity.",
		NextSteps:  "Review the full command that was escalated, then check for unusual patterns in the escalation window.",
	},
	"NOPASSWD sudo entry": {
		Category:   "audit",
		WhyFlagged: "A NOPASSWD sudoers entry allows privilege escalation without a password, which is a persistent escalation path.",
		NextSteps:  "Verify the entry is authorized, then check when it was added against change management records.",
	},
	"NOPASSWD binary in volatile path": {
		Category:   "audit",
		WhyFlagged: "A sudoers NOPASSWD rule grants password-free root execution to a binary in /tmp, /dev/shm, or another volatile path, so any user with write access can replace it.",
		NextSteps:  "Identify which sudoers file holds the entry, remove or restrict the NOPASSWD rule, then hash the binary before any further use.",
	},
	"Sudo binary hijacking": {
		Category:   "audit",
		WhyFlagged: "A NOPASSWD sudoers binary is shadowed by an earlier entry in PATH, so an attacker can place a malicious binary earlier in PATH to intercept the privileged execution.",
		NextSteps:  "Identify the shadowing binary, verify it is authorized, then use full absolute paths in sudoers to block PATH-based hijacking.",
	},
	"Binary PATH hijacking": {
		Category:   "audit",
		WhyFlagged: "A system binary is shadowed by an earlier entry in a user's PATH. Attackers use this to swap in malicious binaries for commands run by privileged users or automated tasks.",
		NextSteps:  "Inspect the shadowing binary for tampering, check when it was placed there, then audit other system binary names in the same override directory.",
	},
	"Dangerous process capability": {
		Category:   "audit",
		WhyFlagged: "A process holds a Linux capability (for example, CAP_SYS_ADMIN, CAP_SYS_PTRACE, or CAP_NET_RAW) that enables privilege escalation, rootkit loading, or host-level access from a container.",
		NextSteps:  "Verify why the capability was granted, confirm the binary is authorized to hold it, then correlate with container configuration if the process is containerized.",
	},
	"Recently modified authorized_keys": {
		Category:   "users",
		WhyFlagged: "An authorized_keys file changed within the last 72 hours. This is a common SSH backdoor technique that survives reboots and password changes.",
		NextSteps:  "Review the file contents, remove any keys you do not recognize, audit /var/log/auth.log for the time of modification, then correlate with account activity.",
	},
	"SSH authorized_keys found": {
		Category:   "persistence",
		WhyFlagged: "SSH authorized_keys files were found on this host, and each key grants passwordless SSH access as the owning user.",
		NextSteps:  "Review all listed keys, remove any that are unrecognized or no longer needed, then correlate them with account activity and recent auth.log entries.",
	},
	"Recently modified SSH authorized_keys": {
		Category:   "persistence",
		WhyFlagged: "An SSH authorized_keys file changed within 72 hours. Attackers add their public key here to keep SSH access that survives password rotation.",
		NextSteps:  "Diff the file against a known-good backup, remove unrecognized keys, then check /var/log/auth.log for successful logins using the added key.",
	},
	"Sudoers NOPASSWD:ALL grant": {
		Category:   "persistence",
		WhyFlagged: "A sudoers rule grants NOPASSWD:ALL, so any command can run as root with no password. That is a complete privilege escalation backdoor.",
		NextSteps:  "Identify who added the entry and when, verify it is authorized, remove it if not, then audit every account that can use it.",
	},
	"Sudoers NOPASSWD grant": {
		Category:   "persistence",
		WhyFlagged: "A sudoers rule grants NOPASSWD for a specific command, which is password-free root execution that survives reboots.",
		NextSteps:  "Verify the entry matches an authorized application, check when it was added, then confirm the target binary has not been replaced.",
	},
	"Recently modified sudoers drop-in": {
		Category:   "persistence",
		WhyFlagged: "A file in /etc/sudoers.d/ changed within the last 72 hours, which is a common privilege escalation persistence technique.",
		NextSteps:  "Diff it against an authorized baseline, then correlate the modification timestamp with user login and file activity around the same window.",
	},

	"Suspicious system user shell": {
		Category:   "persistence",
		WhyFlagged: "A system user (UID 1 to 999) has a shell field in /etc/passwd that is not /sbin/nologin, /bin/false, or equivalent. Attackers change system user shells to open an SSH backdoor.",
		NextSteps:  "Verify the shell path exists and is expected, cross-reference with /etc/shells integrity findings, then check authorized_keys in the user's home directory.",
	},
	"Malformed /etc/shells entry": {
		Category:   "persistence",
		WhyFlagged: "An /etc/shells entry has trailing whitespace. The PANIX SSH backdoor technique adds 'nologin ' (with a trailing space) to pass PAM validation while mapping to a copied shell binary.",
		NextSteps:  "View the raw /etc/shells bytes, cross-reference them with the /etc/passwd shell fields for system users, then remove the malformed entry.",
	},
	"Staging-path shell in /etc/shells": {
		Category:   "persistence",
		WhyFlagged: "An /etc/shells entry references a path inside a known malware staging directory (/tmp, /dev/shm, /var/tmp). Attackers add these to enable PAM shell validation for backdoored accounts.",
		NextSteps:  "Remove the entry, check /etc/passwd for accounts using this shell path, then investigate how the entry was added.",
	},
	"Non-existent shell in /etc/shells": {
		Category:   "persistence",
		WhyFlagged: "An /etc/shells entry references a path that is not on disk, which can mean a dropped shell binary that was removed or a misconfigured entry.",
		NextSteps:  "Use the bodyfile timeline to verify whether the binary was ever present, then check whether any accounts reference this shell in /etc/passwd.",
	},
	"Recently modified /etc/shells": {
		Category:   "persistence",
		WhyFlagged: "/etc/shells changed within the past 72 hours. This file is static on a clean system, so a change points to account backdooring.",
		NextSteps:  "Diff the current content against a known-good backup, identify which entry was added, then correlate with /etc/passwd changes.",
	},
	"Unpackaged PAM module": {
		Category:   "persistence",
		WhyFlagged: "A PAM .so module in a system library directory is not owned by any installed DPKG package. Attackers replace or add PAM modules to intercept every authentication attempt.",
		NextSteps:  "Hash the file and check threat intel, compare it against a clean system image, then use the bodyfile timeline to determine how the file was placed there.",
	},
	"Suspicious PAM module": {
		Category:   "persistence",
		WhyFlagged: "A PAM .so module is both unpackaged and recently modified, which matches the PANIX PAM backdoor fingerprint precisely.",
		NextSteps:  "Treat it as a confirmed PAM backdoor. Capture the file, restore from a known-good package, then rotate all credentials that authenticated through PAM on this host.",
	},
	"Recently modified PAM module": {
		Category:   "persistence",
		WhyFlagged: "A PAM .so module changed within the past 72 hours. PAM modules are static after package installation, so an unexpected change points to tampering.",
		NextSteps:  "Verify the module's SHA256 against the package checksum in /var/lib/dpkg/info/*.md5sums. If it does not match, treat it as backdoored.",
	},
	"Malicious pam_exec.so script": {
		Category:   "persistence",
		WhyFlagged: "A pam_exec.so directive in /etc/pam.d/ references a script in a staging directory or one that holds a known reverse-shell payload, and it runs on every authentication event.",
		NextSteps:  "Remove the pam_exec.so line, capture the script for analysis, then audit /var/log/auth.log for authentication events since the script was placed.",
	},
	"Missing pam_exec.so script": {
		Category:   "persistence",
		WhyFlagged: "A pam_exec.so directive in /etc/pam.d/ references a script path that does not exist, which can mean a cleaned-up payload or a misconfigured backdoor attempt.",
		NextSteps:  "Review the pam.d config file, check the bodyfile timeline for the missing script path, then remove the orphaned pam_exec.so directive.",
	},
	"Recently modified PAM config": {
		Category:   "persistence",
		WhyFlagged: "/etc/pam.d/ configuration files are static after package installation, so a recent change points to an attacker adding pam_exec.so or modifying authentication rules.",
		NextSteps:  "Diff the modified file against the package-shipped version, check for new pam_exec.so or include directives, then correlate with authentication log anomalies.",
	},
	"Malicious DPKG lifecycle script": {
		Category:   "persistence",
		WhyFlagged: "A DPKG package lifecycle script (postinst/preinst/prerm/postrm) in /var/lib/dpkg/info/ carries a known reverse-shell or command-execution payload, and it runs automatically during package operations.",
		NextSteps:  "Identify which package owns the script, remove the malicious package, then audit the package installation logs in /var/log/dpkg.log for when it was installed.",
	},
	"Recently modified DPKG lifecycle script": {
		Category:   "persistence",
		WhyFlagged: "A DPKG lifecycle script changed within 72 hours. These scripts run as root during package install and remove, and they should not change outside package management operations.",
		NextSteps:  "Compare the current content against the package's original script, check /var/log/dpkg.log for recent package operations, then verify the owning package is legitimate.",
	},
	"Host namespace attach via nsenter": {
		Category:   "volatile",
		WhyFlagged: "A process is running nsenter targeting PID 1 (the host init process). This is the PANIX container escape technique that attaches a container process to all host namespaces.",
		NextSteps:  "Identify the parent container, terminate the nsenter process, then audit /etc/sudoers for NOPASSWD nsenter entries used to enable this escape.",
	},
	"Recently created Docker image": {
		Category:   "volatile",
		WhyFlagged: "A Docker image was created within the past 7 days. Attackers build or pull malicious images as the first step in container-based persistence.",
		NextSteps:  "Inspect the image with `docker inspect <sha256>`, check its creation provenance, then compare it against authorized CI/CD image builds.",
	},

	"Plaintext credential file": {
		Category:   "credentials",
		WhyFlagged: "Plaintext credentials in .netrc, .pgpass, or AWS credentials files let an attacker move laterally right away.",
		NextSteps:  "Rotate all affected credentials immediately, then audit access logs since the earliest indicator.",
	},
	"Credential/shell tampering": {
		Category:   "credentials",
		WhyFlagged: "Password changes or shell swaps (nologin to bash) point to backdoor account preparation.",
		NextSteps:  "Identify who ran the passwd or chsh command, then verify it against authorized change records.",
	},
	"Cloud credential in process environment": {
		Category:   "credentials",
		WhyFlagged: "Cloud credentials (AWS keys, GCP, Azure) sitting in a process environment can be scraped for a cloud pivot.",
		NextSteps:  "Rotate the exposed cloud credentials immediately, then review cloud access logs for unauthorized API calls.",
	},
	"Cloud credential file open": {
		Category:   "credentials",
		WhyFlagged: "An unexpected process with open file descriptors to credential files may be harvesting cloud access keys.",
		NextSteps:  "Identify the process and its parent, rotate exposed credentials, then check cloud audit logs.",
	},

	"Failed login attempts in btmp": {
		Category:   "auth",
		WhyFlagged: "A high volume of failed logins in btmp points to an ongoing or completed brute-force attack.",
		NextSteps:  "Check for successful logins after the failure window, then review /var/log/auth.log for accepted sessions.",
	},
	"SSH brute-force attack": {
		Category:   "auth",
		WhyFlagged: "High SSH failure counts in journal logs point to automated credential stuffing or a brute-force attack.",
		NextSteps:  "Check for successful logins in the same window, then review the source IPs and block them if appropriate.",
	},
	"Auth log brute-force": {
		Category:   "auth",
		WhyFlagged: "Elevated authentication failures in auth.log point to credential attacks against this host.",
		NextSteps:  "Identify the attacking source IPs, then check for any successful authentications right after the failure burst.",
	},
	"Journal log gap": {
		Category:   "auth",
		WhyFlagged: "Unexplained gaps in journal timestamps can mean someone deleted logs to cover their activity.",
		NextSteps:  "Cross-reference with other log sources (auth.log, syslog) for the same gap period.",
	},
	"Journal restarted without reboot": {
		Category:   "auth",
		WhyFlagged: "A journal daemon restart with no preceding reboot points to possible log tampering.",
		NextSteps:  "Check the systemd-journald restart time against other system events, then review for gaps.",
	},
	"Journal vacuum event": {
		Category:   "auth",
		WhyFlagged: "systemd-journald vacuum operations delete or rotate journal files. A legitimate vacuum is scheduled or triggered by disk pressure, so a manual vacuum during an incident window is a log-tampering indicator.",
		NextSteps:  "Correlate the vacuum timestamp with the incident window, then cross-reference with 06_auth_log_failures.txt and 07_auth_log_successes.txt for the same period to gauge what may have been deleted.",
	},
	"Suspicious PAM entry": {
		Category:   "auth",
		WhyFlagged: "pam_exec or staging-path references in PAM config can run arbitrary code on every authentication.",
		NextSteps:  "Identify the suspicious PAM module, then verify it against the installed package and check its hash.",
	},
	"Shadow file access attempt": {
		Category:   "auth",
		WhyFlagged: "Not being able to read /etc/shadow can mean it was made inaccessible to hide modified password hashes.",
		NextSteps:  "Check the shadow file permissions and ownership, then verify its integrity with package manager checksums.",
	},

	"Timestomped binary: future mtime": {
		Category:   "filesystem",
		WhyFlagged: "A system binary has a modification timestamp set in the future. That is a classic anti-forensics trick to hide when a file was modified or replaced.",
		NextSteps:  "Hash the binary and compare it against known-good package checksums, then check btime/ctime for the real modification window.",
	},
	"SUID binary in non-standard path": {
		Category:   "filesystem",
		WhyFlagged: "An unexpected SUID bit on a binary outside safe directories allows privilege escalation to the file owner.",
		NextSteps:  "Verify the binary is legitimate, remove the SUID bit if it is not required, then hash it and check threat intel.",
	},
	"System binary replacement heuristic": {
		Category:   "filesystem",
		WhyFlagged: "A system binary with a recent mtime but an older birth time suggests it was replaced, which can mean trojanization.",
		NextSteps:  "Verify the hash against known-good package checksums (`rpm -V` or `dpkg --verify`).",
	},
	"FHS violation: executable in non-exec directory": {
		Category:   "filesystem",
		WhyFlagged: "Executable files in /etc, /boot, or man pages directories violate FHS and point to tampering.",
		NextSteps:  "Hash the binary, then trace its origin via shell history and file timestamps.",
	},
	"World-writable SUID binary": {
		Category:   "filesystem",
		WhyFlagged: "A SUID binary that is world-writable can be overwritten by any user to gain elevated privileges.",
		NextSteps:  "Remove the world-writable bit immediately, then verify whether the binary content has been tampered with.",
	},
	"Suspicious SUID binary": {
		Category:   "audit",
		WhyFlagged: "SUID is set on a binary listed in GTFOBins as commonly abused for privilege escalation. If it is unexpected, this is a trivial root escalation path.",
		NextSteps:  "Verify whether SUID was set on purpose, remove it with `chmod u-s <path>` if not, then check the file modification timestamp against known admin windows.",
	},
	"Immutable files detected": {
		Category:   "filesystem",
		WhyFlagged: "An immutable flag on a system file prevents modification, and attackers set it to protect their backdoor files.",
		NextSteps:  "Check which files are immutable, then verify them against your authorized hardening policy.",
	},
	"Package integrity failure": {
		Category:   "filesystem",
		WhyFlagged: "The package manager reports files that differ from their installed checksums, which points to binary tampering.",
		NextSteps:  "Reinstall the affected packages from a trusted source after you capture the modified binaries for analysis.",
	},
	"File integrity check skipped": {
		Category:   "filesystem",
		WhyFlagged: "No package integrity tool was available, so binary tampering cannot be ruled out.",
		NextSteps:  "Install debsums or run rpm -Va from a clean environment, then compare the binaries against vendor checksums.",
	},
	"Deleted artifact in sensitive path": {
		Category:   "filesystem",
		WhyFlagged: "A file was created and then deleted in /tmp, /dev/shm, or /var/spool. Malware commonly stages payloads in volatile directories and deletes them to dodge disk scanning while staying loaded in memory.",
		NextSteps:  "Check whether the deleted path is still held open by any process via /proc/<PID>/fd, then correlate the creation and deletion timestamps with process execution events in the incident window.",
	},

	"sshd LD_PRELOAD injection": {
		Category:   "malware",
		WhyFlagged: "sshd running with LD_PRELOAD from a staging directory points to active library injection.",
		NextSteps:  "Capture the preloaded library via /proc/<PID>/fd, isolate the host, then escalate to IR immediately.",
	},
	"Hidden kernel module": {
		Category:   "malware",
		WhyFlagged: "A kernel module present in /sys/module but missing from /proc/modules points to rootkit-level hiding.",
		NextSteps:  "Capture the kernel module metadata, consider a memory forensic image, then do not reboot until it is imaged.",
	},
	"Process masquerading as kernel thread": {
		Category:   "malware",
		WhyFlagged: "A user-space process using kernel thread name formatting (the BPFDoor and Symbiote pattern) slips past a cursory process review.",
		NextSteps:  "Capture /proc/<PID>/exe and maps, isolate the host, then submit the binary to a sandbox.",
	},
	"ELF binary with disguised extension": {
		Category:   "malware",
		WhyFlagged: "An ELF binary with a non-ELF extension (.jpg, .png) in a staging dir is disguised to dodge name-based detection.",
		NextSteps:  "Hash the binary, check threat intel, then capture it before the execution context changes.",
	},
	"Suspicious string match in config/script": {
		Category:   "malware",
		WhyFlagged: "A config file or script that holds known-malicious string patterns points to planted backdoor code.",
		NextSteps:  "Review the full file context around the match, then verify file integrity against the original package.",
	},
	"Data exfil pattern in config/script": {
		Category:   "malware",
		WhyFlagged: "A config file or script holds data exfiltration patterns, such as cloud storage uploads (S3/GitHub/GDrive/Telegram/Discord), SSH/SCP/rsync/sftp transfers, or archive-to-network streams.",
		NextSteps:  "Review the full file context, correlate it with outbound network connections and recently modified files, then check cron jobs for scheduled exfiltration.",
	},

	"Raw ICMP socket detected": {
		Category:   "malware",
		WhyFlagged: "An unexpected raw ICMP socket is used by backdoors for covert port-knocking and C2.",
		NextSteps:  "Identify the process holding the socket, capture it for analysis, then check for ICMP-based beaconing.",
	},
	"Process binary mismatch": {
		Category:   "malware",
		WhyFlagged: "_COMM not matching the basename of _EXE means a process renamed itself via prctl(PR_SET_NAME). That is the primary technique BPFDoor and Symbiote use to masquerade as kernel threads or innocuous system processes.",
		NextSteps:  "Check the _EXE path against safe directories. If it is in /tmp, /dev/shm, or /var/tmp, treat it as confirmed staging. Correlate with SCAN 08_process_masquerade.txt and SCAN 01_running_processes.txt.",
	},
	"Kernel taint flags": {
		Category:   "malware",
		WhyFlagged: "Kernel taint bits for unsigned or force-loaded modules point to rootkit-level kernel tampering.",
		NextSteps:  "Identify which modules are causing the taint, then capture the kernel module list before any remediation.",
	},
	"BPF write-to-userspace helper": {
		Category:   "malware",
		WhyFlagged: "The kernel logs unconditionally when bpf_probe_write_user is called. This helper writes kernel memory into a user-space process's address space, and eBPF rootkits (ebpfkit, Boopkit) use it to tamper with getdents64 and read() results, hiding files, processes, and network connections from inspection tools.",
		NextSteps:  "The kernel log entry includes the process name and PID, so correlate it with SCAN 01_running_processes.txt and SCAN 08_process_masquerade.txt. If the process is no longer running, check VOLATILE 21_deleted_files_open.txt for open FDs.",
	},
	"BPF override-return helper": {
		Category:   "malware",
		WhyFlagged: "bpf_override_return forces a kernel function to return an attacker-controlled value, which suppresses syscalls entirely. It needs a non-default kernel build option (CONFIG_BPF_KPROBE_OVERRIDE) and has no legitimate production use.",
		NextSteps:  "Identify the process from the kernel log entry. Combined with other eBPF indicators, this should be treated as confirmed rootkit activity.",
	},
	"BPF verifier failure": {
		Category:   "malware",
		WhyFlagged: "BPF program load attempts rejected by the kernel verifier can mean an attacker is probing the system with malformed or experimental BPF programs. A standalone failure can also be a benign misconfigured monitoring tool, so weight it against other eBPF or staging-dir indicators.",
		NextSteps:  "Check the timestamp against the incident window, then correlate with SCAN 18_ebpf_programs.txt sections 1 and 2 for related program activity.",
	},

	"Container environment detected": {
		Category:   "container",
		WhyFlagged: "Scanning from inside a container means host-level artifacts may be incomplete or out of reach.",
		NextSteps:  "Re-run from the host or from a privileged container with host filesystem access for complete coverage.",
	},
	"Docker socket exposed": {
		Category:   "container",
		WhyFlagged: "Access to docker.sock gives root-equivalent host control to any process that can reach it.",
		NextSteps:  "Restrict the socket permissions immediately, then audit recent container operations in the Docker event log.",
	},
	"Privileged container configuration": {
		Category:   "container",
		WhyFlagged: "Privileged containers, or host network and PID mode sharing, give container processes near-full host access.",
		NextSteps:  "Verify the container configuration is authorized, then review what the container process is executing.",
	},
	"Dangerous container bind mount": {
		Category:   "container",
		WhyFlagged: "Bind mounts that expose /etc, /proc, or docker.sock to a container open the door to container escape attacks.",
		NextSteps:  "Audit who deployed this container, then verify the bind mounts are operationally required.",
	},
	"Container runtime socket exposed": {
		Category:   "container",
		WhyFlagged: "containerd, CRI-O, and Podman sockets give the same container escape primitive as docker.sock, because any process that can reach the socket can launch privileged containers with host filesystem access.",
		NextSteps:  "Restrict the socket permissions, audit which processes hold file descriptors to the socket via `lsof`, then verify the runtime is required on this host.",
	},
	"Dangerous container process capabilities": {
		Category:   "container",
		WhyFlagged: "Linux capabilities in a container context enable well-documented escape techniques. CAP_SYS_ADMIN enables mount-based escapes, CAP_SYS_MODULE enables rootkit loading from inside the container, and CAP_SYS_PTRACE enables attaching to host processes via /proc.",
		NextSteps:  "Identify which container was granted these capabilities, review its deployment configuration, correlate with the `20_container_analysis.txt` container inventory, then check for associated exploitation tools in the DEEPSCAN string hunt output.",
	},
	"Untagged container image": {
		Category:   "container",
		WhyFlagged: "Images pulled by digest only (with no human-readable tag) leave no obvious name in the image registry or `docker images` output. That is a common way to run a malicious image while dodging name-based detection.",
		NextSteps:  "Identify the image by its SHA256 digest against threat intelligence, inspect the image layers, then determine when and by whom the image was pulled from the Docker event logs.",
	},
	"Container namespace escape": {
		Category:   "container",
		WhyFlagged: "A container process sharing the host's PID, mount, or network namespace has the same visibility as a host process. That means a successful namespace isolation bypass or a deliberate misconfiguration equivalent to running without containerization.",
		NextSteps:  "Identify the container via the PID in `01_running_processes.txt`, determine which namespace is shared, then treat it as equivalent to a host-level compromise and escalate to IR.",
	},
	"Privileged OCI runtime state": {
		Category:   "container",
		WhyFlagged: "The runc state file shows the configuration as actually applied at container start, which can differ from what `docker inspect` reports if the container was manipulated after creation. CAP_SYS_ADMIN in effective capabilities or host namespace paths in the runtime state are confirmed escape primitives.",
		NextSteps:  "Compare the runc state against `docker inspect` output for the same container ID, where a discrepancy indicates tampering. Hash the container's root filesystem via the overlay path.",
	},

	"External IP in persistence mechanism": {
		Category:   "persistence",
		WhyFlagged: "A public IP address is embedded in a persistence script, cron job, or config file, which points to a C2 callback or a staged download hardcoded into a persistence mechanism.",
		NextSteps:  "Check the IP against threat intel, identify which persistence file holds it, then review outbound connections to that IP in network logs.",
	},
	"External domain in persistence mechanism": {
		Category:   "persistence",
		WhyFlagged: "An external domain is embedded in a persistence script, cron job, or config file, which is a common technique for C2 callbacks or download-cradle persistence.",
		NextSteps:  "Resolve the domain and check it against threat intel, identify which persistence file holds it, then correlate with DNS query logs for the incident window.",
	},

	"Custom IOC match": {
		Category:   "ioc-match",
		WhyFlagged: "A custom IOC from the operator's IOC file matched a system artifact.",
		NextSteps:  "Correlate with the specific IOC context from the IOC file, then escalate per the case IR plan.",
	},
	"Custom IOC IP match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious IP from the IOC file turned up in log files or active connections.",
		NextSteps:  "Check for active connections to the IP, then review all network sessions to and from this address.",
	},
	"Custom IOC command match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious command pattern from the IOC file turned up in a running process cmdline.",
		NextSteps:  "Capture the process and its full execution context, then correlate it with file and network events.",
	},
	"Custom IOC process match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious process name from the IOC file is running on this host.",
		NextSteps:  "Capture the process binary and memory, then isolate the host per the IR plan.",
	},
	"Custom IOC filename match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious filename from the IOC file turned up in a staging directory.",
		NextSteps:  "Hash the file and check it against threat intel, then capture it before any remediation.",
	},
	"Custom IOC hash match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious file hash from the IOC file matched on this host.",
		NextSteps:  "Isolate the host, capture all artifacts tied to the matched binary, then escalate to IR.",
	},
	"Custom IOC domain match": {
		Category:   "ioc-match",
		WhyFlagged: "A known-malicious domain from the IOC file turned up in log files or active connections.",
		NextSteps:  "Check for active DNS queries and connections to this domain, then review all outbound network sessions.",
	},
	"Out-of-tree or unsigned kernel module": {
		Category:   "persistence",
		WhyFlagged: "A loaded kernel module carries taint flags O (out-of-tree) or E (unsigned/forced) and is not a known DKMS module. Malicious LKMs are always out-of-tree.",
		NextSteps:  "Run `modinfo <name>` to inspect the module, check its .ko path and signer, then correlate with /etc/modules-load.d/ config changes.",
	},
	"Recently added kernel module": {
		Category:   "persistence",
		WhyFlagged: "A .ko kernel module file was added to /lib/modules within the past 72 hours, outside the DKMS package directories (updates/, extra/), which suggests a manually dropped LKM.",
		NextSteps:  "Inspect the .ko file with `modinfo`, check whether it is loaded via /proc/modules, then capture it for analysis before remediation.",
	},
	"Suspicious kernel module": {
		Category:   "persistence",
		WhyFlagged: "A kernel module is both recently added and carrying out-of-tree or unsigned taint flags, which matches the PANIX LKM persistence technique precisely.",
		NextSteps:  "Treat it as a confirmed malicious LKM. Capture the .ko file, collect dmesg output, then remove it with `rmmod` before rebooting.",
	},
}
