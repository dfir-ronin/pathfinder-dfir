# PATHFINDER: Technical Documentation

> v1.0.0-beta · DFIR Live Triage Engine · "Drop in. Hunt down. Collect artifacts. Get out."

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [CLI Flags](#cli-flags)
4. [Modules](#modules)
5. [Suppression Engine](#suppression-engine)
6. [Output Structure](#output-structure)
7. [Report.md Structure](#reportmd-structure)
8. [IOC Signatures](#ioc-signatures)
9. [IOC File Format](#ioc-file-format)
10. [Severity & Verdict Logic](#severity--verdict-logic)
11. [Build System](#build-baseline)
12. [Azure Upload](#azure-upload)
13. [Architecture](#architecture)
14. [Privilege Requirements](#privilege-requirements)
15. [Testing](#testing)

---

## Overview

PATHFINDER is a single-binary Linux DFIR tool written in Go that collects volatile and persistent forensic artifacts, runs inline threat detection, and produces a timestamped evidence archive (ZIP + SHA-256) with an analyst-facing scorecard.

**Design goals:**

- Evidence integrity: `O_NOATIME` on all reads to preserve access timestamps
- Single static binary: no dependencies on target system
- Non-destructive: read-only except for its own output directory
- Operator ergonomics: stealth mode for scripted pipeline integration; machine-readable JSON output


> **Limitations of Use** 
This tool is strictly intended as a **companion** to the responder, not a substitute for comprehensive forensic analysis. It focuses on rapid identification of obvious indicators to save time; it does not replace the need for deep-dive investigation and human intuition.
---

## Quick Start

```bash
# Full scan (all modules, root recommended)
sudo ./pathfinder-linux-amd64

# Quick mode (10s timeouts, skip deep walks)
sudo ./pathfinder-linux-amd64 -mode quick

# Specific modules only
sudo ./pathfinder-linux-amd64 -volatile -users

# Custom case ID and output directory
sudo ./pathfinder-linux-amd64 -case-id IR-2026-001 -report-dir /mnt/usb

# Stealth mode for pipeline integration (VERDICT, ARCHIVE, ELAPSED, MANIFEST)
sudo ./pathfinder-linux-amd64 -stealth

# Custom breach threshold
sudo ./pathfinder-linux-amd64 -breach-threshold 3

# With Azure upload (container-scoped SAS URL)
sudo ./pathfinder-linux-amd64 -azure-sas-url 'https://acct.blob.core.windows.net/evidence?sr=c&sp=cw&sv=2022-11-02&sig=...'

# Custom artifact collection — single manifest
sudo ./pathfinder-linux-amd64 -sse-package /path/to/manifest.yaml

# Custom artifact collection — directory of manifests (recursive)
sudo ./pathfinder-linux-amd64 -sse-package /path/to/manifests/

# SSE-PACKAGE collection only (no detection modules, no main zip)
sudo ./pathfinder-linux-amd64 -sse-only -sse-package /path/to/manifest.yaml

# Load a custom IOC file (incident-specific indicators)
sudo ./pathfinder-linux-amd64 -ioc /path/to/iocs.txt

# IOC with custom hash size cap (default 100 MB)
sudo ./pathfinder-linux-amd64 -ioc /path/to/iocs.txt -ioc-max-hash-mb 50

```

Output is written to: `<report-dir>/pathfinder-<hostname>-<YYYYMMDD_HHmmss>/`  
Archive: `<report-dir>/pathfinder-<hostname>-<YYYYMMDD_HHmmss>.zip`

Both files and directories inside the ZIP carry their actual modification timestamps. File mtimes are copied from the source using `O_NOATIME` reads and `os.Chtimes`. Directory entry mtimes reflect when each output directory was last written.

---

## CLI Flags


| Flag                 | Type   | Default             | Description                                                                 |
| -------------------- | ------ | ------------------- | --------------------------------------------------------------------------- |
| `-volatile`          | bool   | —                   | Volatile process & memory artifacts                                         |
| `-users`             | bool   | —                   | User artifacts, credentials, shell history                                  |
| `-baseline`          | bool   | —                   | System baseline and network config                                          |
| `-persistence`       | bool   | —                   | Persistence mechanisms and scheduled tasks                                  |
| `-audit`             | bool   | —                   | Security config and auth logs                                               |
| `-bodyfile`          | bool   | —                   | Filesystem timeline analysis (default: on in full mode, off in quick mode)  |
| `-journal`           | bool   | —                   | Systemd journal collection & analysis                                       |
| `-deepscan`          | bool   | —                   | Threat hunting (default: on in full mode, off in quick mode)                |
| `-mode`              | string | `full`              | Scan mode: `full` (default) or `quick`                                      |
| `-output`            | string | `text`              | Output format: `text` (default). `json` is deprecated (prints a notice to stderr, otherwise behaves like default) |
| `-breach-threshold`  | int    | `50`                | HIGH finding count that triggers HOSTILE verdict                             |
| `-compromise-threshold` | int | `10`               | Minimum HIGH finding count to trigger RISK DETECTED verdict                   |
| `-stealth`           | bool   | false               | Suppress all stdout; prints `VERDICT`, `ARCHIVE`, `ELAPSED`, `SSE` (if collected), `MANIFEST` |
| `-case-id`           | string | `PF-YYYYMMDDHHmmss` | Incident identifier embedded in output paths                                |
| `-report-dir`        | string | `/tmp`              | Parent directory for output                                                 |
| `-sse-package` / `-m`   | string | —                | Path to SSE-Package manifest file **or directory of manifests** (recursive) |
| `-sse-only`          | bool   | false               | Run SSE-PACKAGE collection only; skip all detection modules and main zip. Requires `-sse-package` / `-m`. |
| `-sse-walk-timeout`  | duration | `5m`              | Per-directory walk deadline for SSE-PACKAGE directory collection. On expiry the walk stops and the truncation is recorded in the SSE log. `0` disables the deadline. |
| `-ioc`               | string | —                   | Path to custom IOC file (see [IOC File Format](#ioc-file-format))           |
| `-ioc-max-hash-mb`   | int    | `100`               | Max file size in MB for hash computation during IOC scan                    |
| `-suppress-config`   | string | —                   | Path to user suppression rules YAML file                                    |
| `-show-suppressed`   | bool   | false               | Print suppressed findings tagged `[SUPPRESSED]`                             |
| `-azure-sas-url`     | string | —                   | Azure container-scoped SAS URL (or set `PATHFINDER_AZ_SAS_URL` env var)     |


**Default behavior (no flags):** All modules run sequentially in order of volatility (DFIR acquisition mode). In full mode: VOLATILE → AUDIT → JOURNAL → USERS → PERSISTENCE → BASELINE → BODYFILE → DEEPSCAN. In quick mode: same but without BODYFILE or DEEPSCAN. Use `-stealth` to run the first six modules concurrently (parallel execution is an internal consequence of stealth mode).

**`-sse-only` mode:** When set, only SSE-PACKAGE runs. All detection modules, the main zip archive, `Report.md`, and the scorecard terminal output are skipped. The acquisition manifest records SSE fields only. Exits with a fatal error if `-sse-package` / `-m` is not also supplied.

**Timeouts:**

- Quick: `CmdTimeout=10s`, `FindTimeout=30s`
- Full (default): `CmdTimeout=60s`, `FindTimeout=120s`

**Stealth mode output** (one line per item):

```
VERDICT=HOSTILE INDICATORS DETECTED — IMMEDIATE ACTION REQUIRED
ARCHIVE=/tmp/pathfinder-host-20260418_120000.zip
ELAPSED=56s
SSE=/tmp/pathfinder-host-20260418_120000-sse.zip      (only when -sse-package collected)
MANIFEST=/tmp/pathfinder-host-20260418_120000-manifest.txt
```

**JSON output:** `findings_summary.json` is written to the output directory on every run. It contains the full `FindingsReport` struct: host metadata, verdict, and all findings with severity, module, label, message, and timestamp fields. The legacy `-output json` flag (which wrote an identical `findings.json`) is deprecated and prints a notice to stderr; otherwise it behaves like the default.

---

## Modules

Modules run sequentially in order of volatility by default (DFIR acquisition mode):

**Default (OOV):** VOLATILE → AUDIT → JOURNAL → USERS → PERSISTENCE → BASELINE → BODYFILE → SSE-PACKAGE → DEEPSCAN → IOC (if `-ioc` provided)

In `-stealth` mode, the first six modules (VOLATILE, USERS, BASELINE, PERSISTENCE, AUDIT, JOURNAL) run concurrently via goroutines, followed by BODYFILE → SSE-PACKAGE → DEEPSCAN → IOC sequentially.

---

### VOLATILE: Volatile Memory & Processes

Captures ephemeral evidence that disappears on reboot.


| File                              | Content                                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| `01_running_processes.txt`        | All `/proc/<pid>/status` + cmdline (truncated): PID, PPID, UID, state, start time, exe            |
| `02_cmdlines_full.txt`            | Full untruncated cmdlines for all running processes, sorted by PID                                |
| `03_process_tree.txt`             | Parent-child hierarchy; flags orphaned processes                                                  |
| `04_unmasked_processes.txt`       | Brute-force PID walk 1→pid_max; detects hidden processes via three methods: lstat+listing (both hidden), lstat-only (getdents64 hook), listing-only (lstat hook) |
| `05_hidden_kernel_modules.txt`    | Modules in `/sys/module/` absent from `/proc/modules` (HIGH/MEDIUM); modules in `/proc/modules` absent from `/sys/module` (LOW, unusual -- verify manually); HIGH for loaded modules without `.ko` file on disk (rootkit); MEDIUM for built-in kernel modules (no `.ko` file by design) |
| `06_inode_discrepancy.txt`        | ReadDir vs Lstat inode mismatch in staging dirs (VFS hook detection)                              |
| `07_process_binaries.txt`         | SHA-256 of all running executables; flags deleted binaries                                        |
| `08_process_masquerade.txt`       | `[kernel-thread-name]` processes with actual exe or environ (BPFDoor/Symbiote pattern)            |
| `09_process_anomalies.txt`        | Processes outside safe directories; cmdline IOC pattern matches; CWD in staging directories (MEDIUM/HIGH compound); IOC string scan of flagged process binaries via `/proc/<pid>/exe` (capped at 10 MB, 20 hits per process) |
| `10_cpu_mem_anomalies.txt`        | Processes with lifetime avg CPU > 80% (cryptominer heuristic) or RSS > 500 MB; known heavy processes (mysqld, postgres, java, node, python3, python, ffmpeg, make, gcc, cc1, bazel, cargo) are suppressed |
| `11_memory_maps.txt`              | `/proc/<pid>/maps` for suspicious PIDs; typed classifier: deleted mappings, `memfd:` exec, staging dirs, file-backed `rwxp`, user-home exec |
| `12_unbacked_exec_memory.txt`     | Anonymous executable memory regions (shellcode injection); anonymous RWX pages (file-backed RWX is covered by `11_memory_maps.txt`) |
| `13_suspicious_environ.txt`       | Per-process env var analysis (33 rules: history evasion, LD_PRELOAD staging path HIGH / non-standard lib path MEDIUM, CGI, SSH, cloud credentials); `SuppressionComms` skips `faketime`/`libeatmydata`/`valgrind`/`ltrace` for LD_PRELOAD rules |
| `14_missing_standard_env.txt`     | Shell/interpreter processes missing PATH/HOME/USER (webshell indicator)                           |
| `15_network_connections.txt`      | `/proc/net/{tcp,tcp6,udp,udp6}`; flags non-standard listening ports                               |
| `16_firewall_rules.txt`           | `iptables -L -vn` and `nft list ruleset` (both run independently; "Not available" written if tool absent) |
| `17_packet_sniffers.txt`          | Promiscuous interfaces + AF_PACKET sockets + known sniffer binary names                           |
| `18_ebpf_programs.txt`            | `/sys/fs/bpf/` pinned objects + `/proc/<pid>/fdinfo` prog-ids + `/dev/kmsg` BPF kernel events     |
| `19_namespace_anomalies.txt`      | Processes in non-host network, mount, or UTS namespaces. **Note:** mount and UTS namespace differences are common on systemd and container hosts -- treat these findings as starting points for correlation with `20_container_analysis.txt`, not standalone HIGH-confidence indicators. |
| `20_container_analysis.txt`       | Container self-detection, Docker/CRI enumeration, privilege & bind mount audit, runtime socket exposure, process capability audit, untagged image detection, OCI runtime state, namespace isolation, nsenter host-namespace attach, recently created Docker images |
| `21_deleted_files_open.txt`       | `/proc/<pid>/fd` symlinks containing "(deleted)"                                                  |


`**02_cmdlines_full.txt`** reads `/proc/<pid>/cmdline` for every running process and replaces null bytes with spaces, providing full argument strings without truncation. Useful for detecting long encoded payloads or obfuscated arguments truncated in the standard process list.

`**20_container_analysis.txt**` covers:

- Self-detection: checks `/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup` for Docker/Podman/Kubernetes indicators
- Docker socket exposure: `/var/run/docker.sock` readable by non-root (HIGH)
- Container config parsing: `/var/lib/docker/containers/*/config.v2.json`; flags privileged containers (HIGH), host network/PID mode (HIGH), dangerous bind mounts (`/`, `/etc/`, `/proc/`, docker socket -- including subdirectory mounts like `/etc/shadow`) (HIGH), sensitive bind mounts (`/home/`, `/root/` -- including subdirectory mounts) (MEDIUM)
- CRI enumeration: `crictl ps -o json` (if available)
- containerd enumeration: `ctr containers list` (if available)
- Runtime socket exposure: `/run/containerd/containerd.sock`, `/run/crio/crio.sock`, `/var/run/podman/podman.sock`, `/run/podman/podman.sock`; HIGH if world/group-writable, MEDIUM if present
- Process capabilities: scans `/proc/<pid>/cgroup` to identify container PIDs, parses `CapEff:` hex bitmask; HIGH for CAP_SYS_ADMIN/CAP_SYS_MODULE, MEDIUM for CAP_SYS_PTRACE/CAP_NET_ADMIN/CAP_NET_RAW/CAP_SYS_RAWIO/CAP_DAC_READ_SEARCH/CAP_BPF
- Untagged images: parses `/var/lib/docker/image/overlay2/repositories.json`; flags repositories where all refs are digest-only (no human-readable tag) (LOW)
- OCI runtime state: walks `/run/docker/runtime-runc/moby/*/state.json`; flags CAP_SYS_ADMIN/CAP_SYS_MODULE in effective capabilities or host namespace paths (HIGH); returns init PIDs for namespace check
- Namespace isolation: compares container init PID namespace symlinks (`/proc/<pid>/ns/{pid,mnt,net}`) against host PID 1; flags shared namespaces (HIGH); falls back to cgroup walk to discover container PIDs when no OCI state files are present (containerd, CRI-O, Podman)
- nsenter host-namespace attach: scans `/proc/*/cmdline` for `nsenter` processes targeting PID 1 (`-t 1`, `--target 1`, `-t1`, `--target=1`); PANIX escape technique (`nsenter -t 1 -m -u -i -n -p -- su -`) (HIGH)
- Recently created Docker images: walks `/var/lib/docker/image/overlay2/imagedb/content/sha256/` for manifest files with mtime < 7 days; includes truncated SHA256 digest in finding message (MEDIUM)

**Findings:** Deleted binaries (HIGH), anonymous exec memory (HIGH), suspicious memory map (HIGH/MEDIUM, includes deleted mappings, `memfd:` exec, staging dirs, file-backed `rwxp`, user-home exec; severity by worst anomaly kind), RWX file-backed memory region (MEDIUM, when `rwxpFileBacked` is the sole kind), hidden PIDs (HIGH), promiscuous NICs (HIGH), RWX anonymous regions (MEDIUM), namespace anomalies (MEDIUM), privileged containers (HIGH), docker socket exposed (HIGH), container runtime socket exposed (HIGH/MEDIUM), dangerous process capabilities (HIGH/MEDIUM), untagged container image (LOW), privileged OCI runtime state (HIGH), container namespace escape (HIGH), host namespace attach via nsenter (HIGH, `nsenter` targeting host init PID 1), recently created Docker image (MEDIUM, manifest mtime < 7 days), BPF write-to-userspace helper (HIGH), BPF override-return helper (HIGH), BPF verifier failure (INFO), process running outside safe directory (MEDIUM), suspicious process cmdline (varies), hidden kernel modules (HIGH for loaded; MEDIUM for built-in), unusual kernel module absent from /sys/module (LOW), process masquerade (HIGH), deleted FDs from staging paths (HIGH), deleted FDs from standard paths (INFO), shell process missing standard env vars (MEDIUM).

---

### USERS: User Artifacts & Credentials

Captures user-space evidence of attacker activity.


| File                             | Content                                                                                                      |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `01_users_sessions.txt`          | `/etc/passwd`, utmp (active), wtmp (last 40), btmp (last 30 failures)                                        |
| `02_shell_history.txt`           | `~/.bash_history`, `~/.zsh_history`, `~/.dash_history` for all users                                         |
| `03_ssh_keys_config.txt`         | `~/.ssh/authorized_keys`, `~/.ssh/config`; flags tunnel directives                                           |
| `04_credential_files.txt`        | `.netrc`, `.pgpass`, `.aws/credentials`                                                                      |
| `05_shell_startup_files.txt`     | `/etc/profile`, `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `/etc/environment`                               |
| `06_staging_dirs.txt`            | `/tmp`, `/var/tmp`, `/dev/shm` with SHA-256; flags executables, hidden ELF binaries, and compressed archives |
| `07_recently_modified_files.txt` | Files modified in last 24h (full mode + root only)                                                           |
| `08_bash_history_suspicious.txt` | 39 bash history signature matches (see IOC Signatures)                                                       |
| `09_passwd_group_diff.txt`       | diff `/etc/passwd-` vs `/etc/passwd`; flags account additions/removals                                       |
| `10_sshd_config_analysis.txt`    | sshd LD_PRELOAD injection, sshd_config directive scan, triple-dot dir `/etc/...` |
| `11_system_user_shells.txt`      | System users (UID 1–999) with non-nologin/non-false shells; per-user allowlist for `sync`, `halt`, `shutdown`, `operator`                                                                                                                           |
| `12_etc_shells_integrity.txt`    | `/etc/shells` entries checked for trailing-whitespace trick (PANIX SSH backdoor), staging paths, missing files, recency (mtime < 72h)                                                                                                               |


**Findings:** Plaintext credentials (HIGH), executable in staging (HIGH), UID-0 backdoor accounts (HIGH), suspicious history (HIGH), SSH tunnels (MEDIUM), sshd LD_PRELOAD injection (HIGH), triple-dot persistence dir (HIGH), dangerous sshd_config directives (HIGH), recently modified authorized_keys (HIGH, mtime within 72h), compressed archive in staging directory (MEDIUM), system user with interactive shell (HIGH, UID 1–999 with non-nologin/non-false shell), malformed /etc/shells entry (HIGH, trailing whitespace trick), suspicious shell path (HIGH, staging path in /etc/shells), missing /etc/shells entry (MEDIUM, listed shell absent from disk), recently modified /etc/shells (MEDIUM, mtime < 72h).

---

### BASELINE: System Baseline

Captures static system configuration for baseline comparison.


| File                        | Content                                                                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `01_system_info.txt`        | `/proc/version`, `/etc/os-release`, uptime, hostname                                                                    |
| `02_network_interfaces.txt` | All NICs via `/sys/class/net/`; flags promiscuous mode                                                                   |
| `03_routing_arp.txt`        | `/proc/net/route` + `/proc/net/arp`                                                                                      |
| `04_dns_hosts.txt`          | `/etc/resolv.conf`, `/etc/hosts`; RFC1918 redirects flagged LOW, public-IP redirects flagged MEDIUM                     |
| `05_kernel_modules.txt`     | `/proc/modules`: name, size, usage count, `.ko` path from `/sys/module/<name>/filename`; per-module taint analysis      |
| `06_installed_packages.txt` | Last 30 installs from `dpkg.log` (backfills from `dpkg.log.1` when fewer than 30 entries) or `rpm -qa --last`           |
| `07_kernel_taint.txt`       | `/proc/sys/kernel/tainted` with all 18 flag meanings and severity; unknown bits escalated to MEDIUM                     |
| `08_cmdline.txt`            | `/proc/cmdline`; flags non-standard `init=`/`rdinit=` (HIGH), LSM disable (HIGH), recovery params and hardening disable (MEDIUM) |


**Findings:** Non-standard or unsigned modules (HIGH), module loaded from non-standard path (HIGH), LSM disabled via cmdline (HIGH), non-standard init override (HIGH), promiscuous NIC (HIGH), public-IP hosts redirect (MEDIUM), forcibly-loaded module (HIGH), kernel taint with unsigned/forced bits (HIGH), out-of-tree/livepatch taint (MEDIUM), RFC1918 hosts redirect (LOW).

---

### PERSISTENCE: Persistence Mechanisms

Captures all execution paths that survive reboot.


| File                                  | Content                                                                                                      |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `01_cron_jobs.txt`                    | `/etc/crontab`, `/etc/cron.d/`*, `/var/spool/cron/*`                                                         |
| `02_at_queue.txt`                     | `/var/spool/at/*`, `/var/spool/cron/atjobs/*`                                                                |
| `03_systemd_services.txt`             | `/etc/systemd/system/`, `/lib/systemd/system/`, timers, path units, generators, user units                   |
| `04_legacy_init.txt`                  | `/etc/rc.local`, `/etc/rc.d/rc.local`, `/etc/rc.common`, `/etc/inittab`, `/etc/init.d/*`; content analysed line-by-line with `classifyShellCommand`; recency-flagged if mtime < 72h |
| `05_udev_rules.txt`                   | `/etc/udev/rules.d/*`, `/run/udev/rules.d/*`; `RUN+=` and `IMPORT{program}` commands extracted via regex and passed to `classifyShellCommand`; new rule files flagged if mtime < 72h |
| `06_xdg_autostart.txt`                | `/etc/xdg/autostart/*`, `~/.config/autostart/*`                                                              |
| `07_insmod_boot_persistence.txt`      | `insmod`/`modprobe` calls in boot scripts, cron, profile.d, staging dirs                                     |
| `08_suspicious_systemd_execstart.txt` | Units with `ExecStart=`, `ExecStartPost=`, `ExecStartPre=`, `ExecStop=`, or `ExecReload=` containing reverse-shell payloads or pointing outside safe directories; scans `/etc/systemd/system/`, `/lib/systemd/system/`, `/run/systemd/system/`, `/usr/lib/systemd/system/`, `/usr/local/lib/systemd/system/` including `.wants/`/`.requires/` subdirs |
| `09_motd_persistence.txt`             | `/etc/motd`, `/etc/update-motd.d/*`, `/etc/motd.d/*`, `/etc/profile.d/*` scanned with `classifyShellCommand`; executable MOTD scripts added within 72h flagged |
| `10_shell_profile_analysis.txt`       | `/etc/profile`, `/etc/bashrc`, `/etc/bash.bashrc`, and per-user `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.bash_logout` scanned with `classifyShellCommand`; one highest-severity hit reported per file |
| `11_pkg_manager_hooks.txt`            | `/etc/apt/apt.conf`, `/etc/apt/apt.conf.d/*`; `Pre-Invoke`/`Post-Invoke` commands extracted and classified; `/usr/lib/yum-plugins/*.py`, `/usr/lib/python3*/site-packages/dnf-plugins/*.py` scanned line-by-line; `/var/lib/dpkg/info/*.{postinst,preinst,prerm,postrm}` lifecycle scripts classified with `classifyFileLines` (skips `dpkg.*`) |
| `12_git_hooks.txt`                    | `.git/hooks/` directories up to 5 levels deep below user homes, `/var/www`, `/srv`, `/opt`; executable non-`.sample` hooks analysed with `classifyShellCommand`; `~/.gitconfig` and `/etc/gitconfig` `core.pager`/`core.editor` values classified |
| `13_staging_shared_objects.txt`       | `/tmp`, `/dev/shm`, `/var/tmp` scanned for `.so`/`.so.N` shared objects via `soFileRegexp`; `.so.bak` and similar backup files excluded                                                                                                            |
| `14_ld_preload.txt`                   | `/etc/ld.so.preload` contents written verbatim; entries classified per-line by `classifyLDPreloadEntries`: staging paths → HIGH `"Malicious LD_PRELOAD entry"`, missing files → MEDIUM `"Missing LD_PRELOAD library"`; non-empty file → HIGH `"LD_PRELOAD rootkit indicator"`; mtime < 72h → MEDIUM `"Recently modified LD_PRELOAD config"` |
| `15_kernel_module_analysis.txt`       | `/proc/modules` taint flags (`O`=out-of-tree, `E`=unsigned) via `classifyKernelModuleTaint`; `/lib/modules/` walked for `.ko` files modified within 72h; tainted names cross-correlated with recently-added `.ko` paths; DKMS paths suppressed     |
| `16_web_shells.txt`                   | Web roots discovered from running web-server process CWDs plus static paths; PHP/ASP/ASPX/JSP/CGI/Python/Perl/Ruby/Shell (`.sh`) files scanned with `classifyFileLines` (1 MB cap); dpkg-owned files skipped on Debian/Ubuntu; capped at 20 findings per root |
| `17_pam.txt`                          | PAM library dirs scanned for `.so` files; path resolved via `filepath.EvalSymlinks` before ownership lookup; call site tries resolved path first, falls back to original if only the original is in `ownedFiles` (Ubuntu records `/lib/...`, Debian 13+ records canonical `/usr/lib/...`); when DPKG is available (Ubuntu/Debian): `.so` not owned by any package → `"Unpackaged PAM module"` (HIGH); unpackaged + mtime < 72h → `"Suspicious PAM module"` (HIGH); packaged + mtime < 72h → `"Recently modified PAM module"` (MEDIUM); when DPKG is unavailable (RHEL/Oracle: `/var/lib/dpkg/info` absent): ownership check skipped, only recency applied; recently modified `.so` → `"Recently modified PAM module"` (MEDIUM); every `/etc/pam.d/` file parsed for `pam_exec.so`; script path extracted (first `/`-prefixed token after `pam_exec.so`), classified with `classifyFileLines` or staging-dir check → `"Malicious pam_exec.so script"` (HIGH); script absent from disk → `"Missing pam_exec.so script"` (MEDIUM); any `/etc/pam.d/` file with mtime < 72h → `"Recently modified PAM config"` (MEDIUM) |
| `18_external_network_indicators.txt`  | External IPs and domains extracted from cron jobs, systemd `.service` units, `/etc/init.d/` scripts, `/etc/rc.local`, shell profiles and `profile.d/` scripts, and per-user dotfiles; external IPs → HIGH, external domains → MEDIUM |
| `19_ssh_authorized_keys.txt`          | SSH `authorized_keys` files for all users (root plus passwd entries); counts non-comment key lines; recently modified files → MEDIUM `"Recently modified SSH authorized_keys"`, otherwise → INFO `"SSH authorized_keys found"` |
| `20_sudoers.txt`                      | `/etc/sudoers` (if readable) and all regular files in `/etc/sudoers.d/` (names containing `.` or `~` skipped per `man sudoers`); per-line NOPASSWD analysis with whitespace normalization; `NOPASSWD: ALL` (any case) → HIGH; plain `NOPASSWD:` without ALL → MEDIUM; drop-in file mtime < `persistenceRecentHours` → MEDIUM `"Recently modified sudoers drop-in"` |


**Findings:** insmod in staging dirs (HIGH), malicious udev RUN command (HIGH, `classifyShellCommand` hit on extracted `RUN+=` or `IMPORT{program}` value), suspicious udev rule (MEDIUM, `RUN+=` or `IMPORT{program}` present but no malicious command detected), recently added udev rule (MEDIUM, mtime < 72h), systemd Exec directive in malware dirs (HIGH), non-standard generators (HIGH), malicious XDG autostart entry (HIGH, malware staging path / inline payload / hidden dir), suspicious XDG autostart entry (MEDIUM, non-existent binary reference), malicious cron job (HIGH), malicious systemd ExecStart (HIGH), malicious shell profile command (HIGH), malicious legacy init script (HIGH, `classifyShellCommand` hit in init.d or rc file), recently modified legacy init file (MEDIUM, mtime < 72h), recently added init.d script (MEDIUM, new file with no malicious content), recently added executable MOTD script (MEDIUM, executable + mtime < 72h, no malicious content), malicious APT hook command (HIGH, hook command classified), recently added APT hook config (MEDIUM, mtime < 72h), malicious yum/dnf plugin (HIGH, classified line in plugin .py), malicious git hook (HIGH, classified line), recently added git hook (MEDIUM, executable hook, mtime < 72h), malicious gitconfig hook (HIGH, `core.pager`/`core.editor` classified), shared object in staging directory (HIGH, `.so` file found in `/tmp`, `/dev/shm`, `/var/tmp`), LD_PRELOAD rootkit indicator (HIGH, `/etc/ld.so.preload` is non-empty), malicious LD_PRELOAD entry (HIGH, `/etc/ld.so.preload` entry in staging path), missing LD_PRELOAD library (MEDIUM, entry references non-existent file), recently modified LD_PRELOAD config (MEDIUM, `/etc/ld.so.preload` mtime < 72h), suspicious kernel module (HIGH, tainted module cross-correlated with recently-added `.ko`), out-of-tree or unsigned kernel module (MEDIUM, taint only), recently added kernel module (MEDIUM, recency only), web shell detected (HIGH, `classifyFileLines` match in web root), suspicious web file (MEDIUM, cgi-bin or exec bit with mtime < 72h), unpackaged PAM module (HIGH, `.so` in PAM lib dir not owned by any DPKG package; skipped when DPKG unavailable e.g. RHEL/Oracle), suspicious PAM module (HIGH, unpackaged + mtime < 72h), recently modified PAM module (MEDIUM, packaged `.so` with mtime < 72h; also emitted on RHEL/Oracle when any PAM `.so` has mtime < 72h), malicious pam_exec.so script (HIGH, script in staging path or `classifyFileLines` match), missing pam_exec.so script (MEDIUM, referenced script absent from disk), recently modified PAM config (MEDIUM, `/etc/pam.d/` file with mtime < 72h), malicious DPKG lifecycle script (HIGH, `classifyFileLines` match in `.postinst`/`.preinst`/`.prerm`/`.postrm`), recently modified DPKG lifecycle script (MEDIUM, mtime < 72h, no malicious content), external IP in persistence mechanism (HIGH, external IP hardcoded in a cron/init/systemd/profile script), external domain in persistence mechanism (MEDIUM, external domain referenced in a persistence script), malicious cron script (HIGH, `classifyFileLines` match in cron script directory), recently added cron script (MEDIUM, cron script dir file with mtime < 72h), malicious anacron job (HIGH, `classifyShellCommand` match in `/etc/anacrontab` command field), malicious at/batch job (HIGH, `classifyShellCommand` match in at spool file), suspicious gitconfig hooksPath (MEDIUM, `core.hooksPath` points to non-standard directory), malicious gitconfig hooksPath (HIGH, `core.hooksPath` points to staging path), malicious ld.so.conf entry (HIGH, `/etc/ld.so.conf` or `ld.so.conf.d/` entry in staging path), recently modified ld.so.conf (MEDIUM, conf file with mtime < 72h), recently modified SSH authorized_keys (MEDIUM, `authorized_keys` with mtime < 72h), SSH authorized_keys found (INFO, `authorized_keys` present with no recent modification), sudoers NOPASSWD:ALL grant (HIGH, line in `/etc/sudoers` or drop-in contains `NOPASSWD: ALL` in any case), sudoers NOPASSWD grant (MEDIUM, line contains `NOPASSWD:` without ALL), recently modified sudoers drop-in (MEDIUM, file in `/etc/sudoers.d/` with mtime < `persistenceRecentHours`), user-level persistence (MEDIUM), at jobs (MEDIUM), XDG autostart entries (INFO, clean user-dir entries).

---

### AUDIT: Security Config & Auth Logs

Captures access controls and authentication events.


| File                        | Content                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------- |
| `01_pam_config.txt`         | `/etc/pam.d/`*; flags `pam_exec`, `pam_prelude`, staging dir references                   |
| `02_sudoers.txt`            | `/etc/sudoers`, `/etc/sudoers.d/*`; flags `NOPASSWD`; checks each NOPASSWD binary path for same-named files in `/usr/local/bin`, `/tmp`, `/var/tmp`, `/dev/shm`, `~/bin` |
| `03_suid_sgid.txt`          | All SUID/SGID binaries with SHA-256; flags world-writable SUID and GTFOBins-listed SUID    |
| `04_immutable_files.txt`    | Files with immutable attribute (`FS_IOC_GETFLAGS` ioctl) in `/etc`, `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`; no `chattr` binary required |
| `05_auth_log_failures.txt`  | SSH auth failures from `/var/log/auth.log` and `/var/log/secure` (+ rotations): `Failed password`, `Failed publickey`, `Invalid user`, `authentication failure` |
| `06_auth_log_successes.txt` | SSH auth successes from `/var/log/auth.log` and `/var/log/secure` (+ rotations): `Accepted password`, `Accepted publickey`                                    |
| `07_shadow_hashes.txt`      | `/etc/shadow` users with password hashes (root only)                                      |
| `08_binary_hijacking.txt`   | System binary name set built from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`; scans `/usr/local/bin`, `/usr/local/sbin`, per-user `~/bin`, `~/.local/bin` for name collisions; symlinks to canonical path skipped |
| `09_process_capabilities.txt` | `getcap -r /usr /bin /sbin /usr/local /opt /home`; parses libcap output; applies danger map and known-safe allowlist (`newuidmap` → `cap_setuid` only; `newgidmap` → `cap_setgid` only) |
| `10_file_integrity.txt`     | `debsums -s` or `rpm -Va` output (package file modification detection)                     |


**Findings:** NOPASSWD sudoers (HIGH), sudo binary hijacking (HIGH, NOPASSWD binary shadowed in early-PATH directory), NOPASSWD binary in volatile path (HIGH, NOPASSWD rule points into `/tmp`, `/var/tmp`, `/dev/shm`), world-writable SUID (HIGH), suspicious SUID binary (HIGH, SUID set on GTFOBins-listed binary not in expected-SUID allowlist), suspicious PAM (HIGH), >100 auth failures (HIGH), dangerous process capability (HIGH, `cap_setuid`/`cap_setgid`/`cap_sys_ptrace`/`cap_sys_admin`; MEDIUM, `cap_dac_override`/`cap_net_raw`), binary PATH hijacking (HIGH, collision in user home or mtime < 72h; MEDIUM, collision in system override dir), immutable files (MEDIUM), 20–100 auth failures (MEDIUM), package integrity failures (HIGH), file integrity check skipped (LOW).

---

### JOURNAL: Systemd Journal Collection & Analysis

Collects and analyzes systemd journal logs. Runs independently; `-journal` alone produces only `journal/` output; `-baseline` alone does not trigger journal collection.


| File                      | Content                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `raw/`                    | Raw copy of journal files (root only); probes `/var/log/journal/` (persistent, Debian/Ubuntu default) then `/run/log/journal/` (volatile, RHEL/Oracle Linux default) — files from both paths are collected if present |
| `journal_filtered.json`   | `journalctl -o json` filtered: auth_ssh, sudo, cron, kernel_oom, high_priority, journald_vacuum, account_mgmt (last 30d) |
| `journal_analysis.txt`    | Inline analysis of `journal_filtered.json`, 11 detection rules (see below)                                              |


**Journal analysis rules (`journal_analysis.txt`):**


| Rule                           | Trigger                                                                | Severity                                  |
| ------------------------------ | ---------------------------------------------------------------------- | ----------------------------------------- |
| Account creation/deletion      | `useradd`, `adduser`, `userdel`, `groupadd` in MESSAGE                 | MEDIUM (HIGH for userdel/sensitive group) |
| Sensitive group membership     | `added to group` + `sudo`/`wheel`/`shadow`/`disk`/`docker`/`lxd`/`adm` | HIGH                                     |
| Password/shell tampering       | `_COMM=passwd`, `password changed for`, `/sbin/nologin` or `/usr/sbin/nologin` replaced by any recognized interactive shell, or `chsh` entry with interactive shell path | HIGH |
| SSH brute-force                | > 20 failed auth events (`Failed password`, `Failed publickey`, `Invalid user`) | MEDIUM (HIGH if > 100)         |
| sudo/pkexec from non-root      | `SYSLOG_IDENTIFIER=sudo` or `pkexec` with UID ≠ 0                      | MEDIUM                                    |
| Rapid service crash loop       | Same systemd unit in `Failed`/`killed`/`segfault` ≥ 3× within 60s      | MEDIUM                                    |
| Log time gap                   | Gap between consecutive journal entries > 4h (MED) or > 8h (HIGH)     | LOW                                       |
| Journal restart without reboot | `Journal started` not preceded by shutdown/reboot entry within 5 min   | LOW                                       |
| USB mass storage insertion     | `usb-storage`, `uas`, or `USB Mass Storage` in MESSAGE                 | LOW (informational)                       |
| Journal vacuum event           | systemd-journald `"Vacuuming done"`, `"Deleted archived journal"`, or `"freed"` + `"journal files"` | MEDIUM  |
| Process binary mismatch        | `_COMM` does not match basename of `_EXE` (after 15-char truncation + interpreter allowlist) | MEDIUM     |


**Findings:** Journal anomalies (see table above).

---

### BODYFILE: Filesystem Timeline

Generates a mactime-format timeline and runs inline analysis for filesystem anomalies.

**Format:** `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|btime`

**Scans:** `/bin`, `/usr/bin`, `/etc`, `/home`, `/tmp`, `/var`, `/dev/shm`


| File                             | Content                                                        |
| -------------------------------- | -------------------------------------------------------------- |
| `bodyfile/bodyfile.txt`          | Raw mactime-format body file (one entry per filesystem object) |
| `bodyfile/bodyfile_analysis.txt` | Inline analysis: 6 detection rules (see below)                |


**Note on btime:** Birth time (`btime`) is populated via `unix.Statx` with `STATX_BTIME`. Set to `0` on kernels older than 4.11 or filesystems that do not expose birth time (tmpfs, proc, some NFS mounts). BIN-REPLACE detection is suppressed automatically when `btime == 0`.

**Note on volatile/hidden path cap:** All `Recent activity in volatile/hidden path` detections are stored in `findings_summary.txt` and `Report.md`. The live console caps at 20 printed lines; if more are found, `output.Info` prints `"N more volatile/hidden path detections not shown; see bodyfile_analysis.txt"`. All detections are also written to `bodyfile_analysis.txt`.

**Bodyfile analysis rules (`bodyfile_analysis.txt`):**


| Rule                         | Label                                 | Trigger                                                                                                                                                                                     | Severity                     |
| ---------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Future timestamp             | `TIMESTOMP-FUTURE`                    | Path in `/bin/`, `/sbin/`, `/usr/bin/`, `/usr/sbin/` AND mtime > now + 60s; registry label: `"Timestomped binary: future mtime"`                                                           | HIGH                         |
| Volatile dir activity        | `VOLATILE-ACTIVITY` / `VOLATILE-EXEC` | Regular file in `/tmp/`, `/var/tmp/`, or `/dev/shm/` AND mtime/atime within 72h; registry label: `"Recent activity in volatile/hidden path"` (non-exec) or `"Executable in volatile/hidden path"` (exec) | MEDIUM; HIGH if exec bit set |
| Hidden executable            | `VOLATILE-EXEC`                       | Regular file with a dot-prefix path segment AND exec bit set AND mtime/atime within 72h AND not a known-safe system path (`/etc/skel/`, `/etc/selinux/`, `/etc/.pwd.lock`, `/etc/.updated`) | HIGH                         |
| SUID in non-standard path    | `SUID-NONSTANDARD`                    | `mode & 04000 != 0` AND UID=0 AND path not in safe dirs (`/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/opt/`, `/snap/`)                                                                 | HIGH                         |
| Binary replacement heuristic | `BIN-REPLACE`                         | Path in `/bin/`, `/sbin/`, `/usr/bin/`, `/usr/sbin/` AND mtime within 7 days AND btime ≠ 0 AND btime older than 7 days                                                                      | MEDIUM                       |
| FHS violation                | `FHS-VIOLATION`                       | Execute bit set AND path starts with `/etc/`, `/usr/share/man/`, or `/boot/`                                                                                                                | HIGH                         |
| Deleted artifact             | `DELETED-ARTIFACT`                    | Path contains `(deleted)` or `(realloc)` AND path starts with `/tmp/`, `/dev/shm/`, or `/var/spool/`                                                                                        | HIGH                         |


**Findings:** Timestomped binary: future mtime (HIGH), Recent activity in volatile/hidden path (MEDIUM, non-exec) / Executable in volatile/hidden path (HIGH, exec or hidden-exec), SUID binary in non-standard path (HIGH), System binary replacement heuristic (MEDIUM), FHS violation: executable in non-exec directory (HIGH), Deleted artifact in sensitive path (HIGH, path with `(deleted)` or `(realloc)` under `/tmp/`, `/dev/shm/`, or `/var/spool/`).

---

### IOC: Custom IOC Threat Intelligence

Loads operator-supplied threat indicators from a structured text file and checks them against all DFIR-relevant log sources, live `/proc` telemetry, and file hashes. **No-op when `-ioc` is not provided.** Runs last in Phase 2 (after DEEPSCAN).

**Indicator types:**


| Type                     | Severity | Matched Against                                                                 |
| ------------------------ | -------- | ------------------------------------------------------------------------------- |
| Hashes (SHA-256)         | HIGH     | Running process executables (non-safe dirs), staging dir files, dpkg `.md5sums` |
| IPs (exact or CIDR)      | HIGH     | 15+ log sources, `/proc/net/{tcp,udp}`, auth logs, firewall logs, SSH files     |
| Processes                | HIGH     | Live `/proc/<pid>/comm` + `/proc/<pid>/exe`, plus log sources                   |
| Domains                  | HIGH     | DNS configs, web server access logs, SSH known_hosts, syslog, audit.log         |
| Commands                 | MEDIUM   | Bash/zsh/sh history, cmdlines, cron, systemd, audit.log, syslog, web logs       |
| Filenames                | MEDIUM   | Staging dir files (`/tmp`, `/var/tmp`, `/dev/shm`), plus log sources            |


**Hash computation (full mode only):**

- Scope: running process binaries outside safe dirs, files in `/tmp`, `/var/tmp`, `/dev/shm`, dpkg `.md5sums`
- Computes SHA-256 only
- Skipped in `-mode quick`
- Files over `-ioc-max-hash-mb` (default 100 MB) are skipped with a MEDIUM finding logged
- All reads use `O_NOATIME` to avoid forensic timestamp impact

**Log sources scanned per type:**


| Source                                                                    | Commands | IPs | Processes/Filenames | Domains |
| ------------------------------------------------------------------------- | -------- | --- | ------------------- | ------- |
| `/var/log/audit/audit.log`                                                | ✓        | ✓   | ✓                   | ✓       |
| `/var/log/auth.log`, `/var/log/secure`                                    | ✓        | ✓   | —                   | ✓       |
| `/var/log/syslog`, `/var/log/messages`                                    | ✓        | ✓   | ✓                   | ✓       |
| `/var/log/apache2/access.log`, `/var/log/nginx/access.log`                | ✓        | ✓   | —                   | ✓       |
| `/var/log/dpkg.log`, `/var/log/yum.log`, `/var/log/dnf.log`               | ✓        | —   | ✓                   | —       |
| `/var/log/mail.log`, `/var/log/ufw.log`, `/var/log/firewalld`             | —        | ✓   | —                   | —       |
| `/var/log/exim4/mainlog`                                                  | —        | ✓   | —                   | —       |
| `/var/log/squid/access.log`                                               | —        | —   | —                   | ✓       |
| `/var/lib/unbound/unbound.log`, `/var/log/named/named.log`                | —        | —   | —                   | ✓       |
| `/etc/crontab`, `/etc/cron.d/`*, `/var/spool/cron/crontabs/*`             | ✓        | —   | ✓                   | —       |
| `/etc/systemd/system/*.service`                                           | ✓        | —   | ✓                   | —       |
| `/etc/rc.local`, `/etc/profile`, `/etc/bash.bashrc`                       | ✓        | —   | —                   | —       |
| `/etc/ld.so.preload`, `/etc/ssh/sshd_config`                              | ✓        | —   | ✓                   | —       |
| `/etc/hosts`, `/etc/resolv.conf`                                          | —        | —   | —                   | ✓       |
| `/etc/hosts.allow`, `/etc/hosts.deny`                                     | —        | ✓   | —                   | —       |
| `~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `~/.python_history` | ✓        | —   | ✓                   | —       |
| `~/.bashrc`, `~/.bash_profile`, `~/.profile`                              | ✓        | —   | —                   | —       |
| `~/.ssh/known_hosts`, `~/.ssh/authorized_keys`                            | —        | ✓   | —                   | ✓       |
| `/proc/net/arp`, `/proc/net/tcp`, `/proc/net/udp`                         | —        | ✓   | —                   | —       |
| Live `/proc/<pid>/cmdline`                                                | ✓        | ✓   | ✓                   | —       |


Missing or unreadable files are silently skipped; collection continues.

**Output:**


| File                      | Content                                                                  |
| ------------------------- | ------------------------------------------------------------------------ |
| `ioc/01_ioc_hits.txt` | All custom IOC matches grouped by type, with source path and line number |


**Findings:** Hash match (HIGH), IP/process/domain match (HIGH), command/filename match (MEDIUM), custom IOC domain match (HIGH, domain from IOC file found in a staging directory file), file too large to hash (MEDIUM).

---

### DEEPSCAN: Threat Hunt Engine

Runs after all other modules. Performs string hunting across config/script roots and adversary staging directories.

**String hunt scan roots:**
- Phase 1 (config/script roots): targeted `/etc` paths (see list below), `/usr/local/bin`, `/usr/local/sbin`, `/var/www` (extension-gated `.sh/.py/.pl/.rb/.php/.conf/.cfg`; non-script files capped at 1 MB)
- Phase 2 (staging dirs): `/tmp`, `/var/tmp`, `/dev/shm` (any regular file; `lstat` S_ISREG guard; 100 MB cap; 5 s per-file read timeout; each file logged to `commands.log`)

**Targeted /etc paths (Phase 1):**
- *Specific files:* `/etc/crontab`, `/etc/at.allow`, `/etc/at.deny`, `/etc/rc.local`, `/etc/profile`, `/etc/bash.bashrc`, `/etc/environment`, `/etc/hosts`, `/etc/ssh/sshd_config`, `/etc/ld.so.preload`
- *Glob-expanded:* `/etc/cron.*` (cron.d, cron.daily, cron.hourly, cron.monthly, cron.weekly, etc.)
- *Directories:* `/etc/systemd/system`, `/etc/systemd/system-generators`, `/etc/init.d`, `/etc/profile.d`, `/etc/update-motd.d`, `/etc/apt/apt.conf.d`, `/etc/yum.repos.d`, `/etc/nginx`, `/etc/apache2`, `/etc/sudoers.d`, `/etc/logrotate.d`, `/etc/ld.so.conf.d`, `/etc/network`

| File                                | Content                                                                                                                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01_external_ip_domain.txt`         | Public IPs/domains extracted from `/proc/*/environ`, net tables, `/etc/hosts`, `/etc/resolv.conf`, auth.log, system/user crontabs, `/etc/init.d/` scripts, `/etc/systemd/system/` + `/usr/lib/systemd/system/` + per-user systemd units, `/etc/profile.d/` scripts, system-wide and per-user shell profiles |
| `02_string_hunt_webshells.txt` | PHP exec functions, base64_decode, gzinflate, str_rot13, CGI env vars (REMOTE_ADDR, HTTP_USER_AGENT, REQUEST_URI); SH001–SH005 |
| `03_string_hunt_stagers_c2.txt` | SSH keys in files, paste sites, curl/wget present (SH008 -- LOW), credential env var harvest, DNS exfil API; SH006–SH010 |
| `04_string_hunt_script_exec.txt` | Script execution: obfuscated eval, child_process, execSync, OS fingerprinting, Python subprocess, bash -c; SH011–SH021 |
| `05_string_hunt_data_exfil.txt`     | Data exfiltration: cloud storage/webhook uploads (S3, GitHub API, GDrive, Telegram bot, Discord), curl/wget with upload flags, tar-to-network streams, archive-to-staging, scp/rsync-over-SSH/sftp outbound; SH023–SH029 |

**String hunt finding emission:** One aggregated finding per category per scan (not one per hit). Severity is the worst match seen in that category; message cites hit count, file count, and output filename. Individual hit detail remains in the per-category output file. The `data_exfil` category registers under the distinct label `"Data exfil pattern in config/script"` rather than the shared `"Suspicious string match in config/script"` label used by other categories.

**Findings:** Suspicious string match in config/script: one entry per category with hits (HIGH/MEDIUM at worst-match severity); Data exfil pattern in config/script: one entry when `data_exfil` hits are found. Section 01 (external IPs/domains) is informational only -- no registry entries.

---

### SSE-PACKAGE: Custom Artifact Collection

Operator-defined file collection via YAML manifest or a directory of manifests.

**Input modes:**

- **Single file:** `-sse-package /path/to/manifest.yaml` — loads one manifest exactly as before.
- **Directory:** `-sse-package /path/to/dir/` — walks the directory recursively, loads every `.yaml` and `.yml` file found, and merges their artifact lists into a single collection run. Files that fail to parse are warned and skipped; inaccessible entries are warned and skipped; only an entirely unreadable root directory aborts. Load order is lexicographic within each directory level.

> **Guardrail:** when a directory load yields more than 50 artifacts, a warning is emitted before collection begins — a signal that the collection set is large and runtime will be longer than a targeted triage.

> **Symlink handling:** symlinks discovered by directory traversal or by expanding a glob are contained to the collection root — a link whose target resolves outside that root is skipped and logged. A path the operator names literally may follow cross-tree (so configs like `/etc/localtime → /usr/share/zoneinfo/...` are collected). In all cases the resolved target must be a regular file, so a link to a FIFO or device is never opened. Each followed link's resolved target is recorded in the collection log.

**Manifest format:**

```yaml
version: 1.0
artifacts:
  - description: Collect bash history files
    collector: file
    path: /home/*/.bash_history /root/.bash_history
    output_directory: /files/shell

  - description: Collect SSH authorized keys
    collector: file
    path:
      - /home/*/.ssh/authorized_keys
      - /root/.ssh/authorized_keys
    output_directory: /files/ssh

  - description: Collect auth log with explicit archive name
    collector: file
    path: /var/log/auth.log
    output_directory: /files/logs
    output_file: auth.log

  - description: Collect per-user bash config
    collector: file
    path: "%user_home%/.bashrc %user_home%/.bash_profile"
    output_directory: /files/shell
```

**Artifact fields:**

| field | required | description |
|---|---|---|
| `collector` | yes | Must be `file`. Unknown values are skipped with a warning. |
| `path` | yes | Source path(s). A scalar string is split on spaces (UAC token format), so a path that itself contains spaces must use the YAML list form, where each list item is one complete path. |
| `output_directory` | no | Destination directory within the evidence archive. |
| `output_file` | no | Destination filename (single-file paths only). |
| `description` | no | Human-readable label; logged on collection. |
| `supported_os` | no | List of target OS names. If non-empty and contains neither `"linux"` nor `"all"` (case-insensitive), the artifact is silently skipped. Empty means always collected. |
| `max_depth` | no | Maximum directory traversal depth. `1` = direct children only (matches `find -maxdepth 1`). `0` or absent = no limit. Ignored for single-file paths. |
| `name_pattern` | no | Include-only filename glob list (e.g. `["*.log", "*.conf"]`). Files matching none of the patterns are skipped. Empty means collect all. |
| `exclude_name_pattern` | no | Exclude filename glob list (e.g. `["*.tmp", "*.bak"]`). Files matching any pattern are skipped. |
| `max_file_size` | no | Maximum file size string (e.g. `"10MB"`, `"500k"`, `"2g"`). Files exceeding the limit are skipped with a `[~]` note. Applied to both single-file and directory artifact paths. Invalid format emits a warning and skips the artifact. Supported suffixes (case-insensitive): `b`/`c` ×1, `k`/`kb` ×1024, `m`/`mb` ×1024², `g`/`gb` ×1024³, `t`/`tb` ×1024⁴. |
| `exclude_path_pattern` | no | List of absolute path prefixes to skip during directory walks (e.g. `["/proc", "/sys", "/dev", "/run"]`). When the walk enters a directory whose path matches or is a descendant of any entry, the entire subtree is skipped. Prevents collecting from virtual filesystems or other undesired subtrees. |
| `path_pattern` | no | Shell-glob path filter list (e.g. `["*/.git/hooks/*"]`). Only files whose absolute path matches at least one pattern are collected. `*` matches any character sequence including `/`, matching UAC's `find -path` semantics. Empty means collect all files. Applied after `exclude_path_pattern` and before `max_file_size`. Directories are never pruned — all subtrees are traversed so deep patterns can match. Invalid patterns emit a `[WARN]` and are skipped without aborting the artifact. |
| `file_type` | no | Entry type filter list. Supported values: `f` (regular files), `l` (symbolic links), `d` (directories — no-op). When non-empty, only entries of the listed types are collected. Empty means collect all regular files and symlinks. **Special files (FIFOs, sockets, device files) are always skipped regardless of this setting** — opening them without `O_NONBLOCK` can block indefinitely. Applied before all other per-file filters. |
| `exclude_nologin_users` | no | Parsed but no-op. Pathfinder already excludes nologin/false-shell users in `readHomeDirs`. |
| `ignore_date_range` | no | Parsed but no-op. Pathfinder has no date-range filter. |

**UAC compatibility:**

Pathfinder's SSE-PACKAGE module is compatible with [UAC (Unix Artifact Collector)](https://github.com/tclahr/uac) artifact directories. Point `-sse-package` at a UAC checkout or extracted artifact set:

```bash
sudo ./pathfinder-linux-amd64 -sse-package /path/to/uac/
```

Four compatibility adaptations are applied transparently:

- **Tab indentation:** UAC YAML files use tab-based indentation. Pathfinder replaces tabs with spaces before parsing — no manual conversion needed.
- **`%user_home%` token:** UAC uses `%user_home%` as an unquoted path prefix (e.g. `path: %user_home%/.anydesk`). The `%` character cannot start a plain scalar in Go's YAML parser. Pathfinder replaces the token with an internal placeholder before parsing and expands it to real home directories (from `/etc/passwd`) during collection.
- **`%temp_directory%` token:** UAC's internal placeholder for its own temporary collection directory. This path is meaningless outside UAC. Tokens containing `%temp_directory%` are dropped during path resolution; artifacts whose paths all resolve to this placeholder emit a "no paths resolved" note and are skipped.
- **Version field:** Any `version:` value is accepted. UAC uses `version: 1.0` and `version: 1.1` interchangeably; both load without warning.

Supported UAC collectors and fields:

| UAC field / collector | Pathfinder behavior |
|---|---|
| `collector: file` | Collected with all filter fields applied |
| `collector: command`, `find`, `hash`, `stat` | Warned and skipped (unsupported collector) |
| `supported_os` | Non-Linux artifacts silently skipped |
| `max_depth` | Directory traversal depth limit applied |
| `name_pattern` | Include-only filename glob filter applied |
| `exclude_name_pattern` | Exclude filename glob filter applied |
| `max_file_size` | File size limit applied |
| `exclude_path_pattern` | Path prefix exclusion applied — listed subtrees are skipped entirely |
| `path_pattern` | Shell-glob path filter applied — only files whose absolute path matches at least one glob are collected; `*` matches across `/` (UAC `find -path` semantics) |
| `file_type` | Entry type filter applied — `f` collects regular files, `l` collects symlinks, `d` is no-op; empty collects all regular files and symlinks; FIFOs/sockets/devices always skipped |
| `exclude_nologin_users` | Parsed; no-op (Pathfinder already filters nologin users in `readHomeDirs`) |
| `ignore_date_range` | Parsed; no-op (Pathfinder has no date-range filter) |
| All other UAC fields | Silently ignored |

**Path resolution** (applied in order per token):

1. **`%user_home%` expansion** — replaced with each real user's home directory from `/etc/passwd`. Real user = UID ≥ 1000 with a login shell that is not `/bin/false`, `/usr/sbin/nologin`, `/usr/bin/nologin`, or `/sbin/nologin`. Root (`/root`) is always included. Resolved in Go — no system binary calls.
2. **Glob expansion** — `*` matches within a single path component; `**` matches across components. Resolved via `filepath.Glob` — no shell.
3. **Stat** — each resolved path is `Lstat`'d to determine file vs. directory.

**Archive placement (inside `<case>-sse.zip`):**

- With `output_directory`: entry name is `<output_directory>/<filename>` (e.g. `files/logs/auth.log`).
- With `output_directory` + `output_file` (single file only): destination filename is overridden. On multi-path results `output_file` is warned and ignored.
- Without `output_directory`: full source path with leading `/` stripped (e.g. `/var/log/auth.log` → `var/log/auth.log`).
- Directories: subtree entries use relative filenames under `output_directory/` when set; full path (leading `/` stripped) otherwise.

No `SSE-package/` staging directory is created on disk. Files are streamed directly into the zip using `zip.Writer`, eliminating the 2× disk usage that would otherwise be required.

**Timestamp preservation:** source files opened with `O_NOATIME`; zip entry mtime is set from `zip.FileInfoHeader` (preserves source mtime in the zip header). ctime is not preserved (Linux kernel limitation).

**Terminal output:** SSE-PACKAGE emits only a chapter banner at the start and a single summary line on completion (`SSE-Package: N files collected (M skipped) → path | log → path`). All per-file and per-artifact detail (skips, no-match artifacts, directory traversal progress) is written to the collection log only — not to the terminal.

**Collection log:** after a successful run, `{base}-sse-log.txt` is written alongside the zip. It contains one block per artifact followed by a total summary:

```
=== ARTIFACT: bash_history ===
  Collected : 3
  Skipped   : 0
  Errors    : 0

=== ARTIFACT: system_files ===
  Collected : 1,842
  Skipped   : 299,842
    250000  excluded by path pattern
     49840  excluded by name pattern
         2  exceeds max_file_size
  Errors    : 1
    /etc/shadow — permission denied

[!] artifact "Browser History" — skipped: unsupported collector: browser

=== TOTAL: 1845 collected | 299842 skipped | 1 errors ===
```

Skip counts are grouped by reason and sorted by count descending — no per-file paths are listed for skips, keeping the log compact even on large collections. Only error entries include per-file paths. Artifact-level config failures (unsupported collector, missing path, invalid `max_file_size`, unresolved tokens) appear as inline `[!]`/`[~]` lines outside the artifact block. The log is written incrementally — each artifact block is flushed immediately after that artifact finishes, so the file is partially useful even if the run is interrupted. The log is only written when the zip passes verification — early exits leave no orphaned log file. The terminal summary line includes `| log → {path}`.

If Azure upload is configured, the completed `-sse.zip` is enqueued once after the archive is finalized (not per-file).

### Acquisition Manifest

After both zips are finalized, Pathfinder writes a plain-text acquisition manifest alongside them:

```
pathfinder-<host>-<ts>-manifest.txt
```

The manifest contains:

| Section | Fields |
|---|---|
| `[Case]` | Case ID, Examiner, Notes |
| `[System]` | Hostname, OS, Kernel, Arch, CPU, Memory, Timezone, IPs, Mounts |
| `[Acquisition]` | Started, Completed, Mode, Manifest path, IOC file, Suppress file, Flags (`-stealth`), Artifacts, Collected files, Skipped files, Unreadable files (each listed individually when a source file could not be read into the main zip) |
| `[Archives]` | Main zip: filename, size, MD5, SHA-256; SSE zip: filename, size, MD5, SHA-256 (omitted when no `-sse-package` was supplied) |

The manifest is always written, even when no `-sse-package` is used (the SSE section is simply omitted). MD5 is labeled "for legacy tool compatibility only; SHA-256 is authoritative." A failed manifest write emits a warning but does not abort the run.

---

## Suppression Engine

The suppression engine (`internal/suppress/`) eliminates reproducible false positives on known-clean distro installs without touching module code. It sits inside `output.Registry.Add`, the single choke point where all findings are recorded.

### Architecture

```
Module detectors → Finding → Suppression Engine → output.Registry
                                ├── universal profile rules
                                ├── distro profile rules (ubuntu | debian | rhel/oracle)
                                └── user config rules (-suppress-config)
```

Distro is detected at startup from `/etc/os-release` (`ID` / `ID_LIKE`). Recognized: `ubuntu`, `debian` (and derivatives via `ID_LIKE=debian`, e.g. Raspbian), `rhel`, `ol` (Oracle Linux uses the RHEL profile). Unknown distros load the universal profile only.

### Rule Format

User rules live in a YAML file passed via `-suppress-config`:

```yaml
suppress:
  - module: audit            # volatile|users|baseline|persistence|audit|journal|bodyfile|deepscan
    rule_id: "NOPASSWD sudo entry"
    message_contains: ""       # substring match on finding message
    path_in: []                # exact path match (OR within list)
    path_glob: ""              # fnmatch glob on path field
    process_in: []             # process comm match; entries ending in "-" are prefix-matched
    reason: "Approved sudoers config for ops automation"
```

All specified fields must match (AND logic). A rule with only `module` + `rule_id` suppresses all findings of that type. To cancel a profile rule, add a matching rule with `suppress: false` (override semantics).

### Run Summary

With `-show-suppressed`, suppressed findings print inline with a `[SUPPRESSED]` tag. The verdict line includes:

```
N findings suppressed (distro profile: X, user config: Y)
```

### Distro Profiles

| Profile   | Covers |
| --------- | ------ |
| Universal | Built-in kernel modules, JIT anonymous/RWX memory (Firefox, `firefox-esr`, GNOME Shell, `gnome-session-b`, `gnome-terminal-`, GJS, Nautilus, Ptyxis, Mutter, `gnome-text-edit`), DHCP port 68, NetworkManager raw sockets, standard systemd sandboxing (polkitd, irqbalance, etc.), Flatpak/bwrap sandbox namespaces, GRUB/network/kernel/ppp hook dirs (`/etc/ppp/**`), ACPI event handler scripts (`/etc/acpi/*.sh`), avahi-autoipd action script, DHCP client enter/exit hook dirs, Firefox `~/.mozilla/**` volatile path, `cups.path` .path unit, wpa_supplicant `dbus-fi.*` D-Bus alias, full GNOME desktop session `Process in non-host network namespace` (~60 processes: session core, compositor/Mutter/Xwayland, GVfs/XDG portals, IBus input method, GSD settings daemons, GNOME Online Accounts, Evolution PIM, accessibility stack, Firefox multi-process children), `Suspicious memory map` for Steam (`steam`, `steamwebhelper`, `pressure-vessel`, loads `.so` files from `~/.local/share/Steam/`) and GNOME Shell extensions (`gnome-shell`, `gjs`, loads from `~/.local/share/gnome-shell/extensions/`), `Suspicious process environment variable / LD_PRELOAD` for Firefox multi-process children (`Socket Process`, `WebExtensions`, `RDD Process`, `Privileged Cont`, `Utility Process`, `Isolated Servic`, `Isolated Web Co`, `Web Content`); inherit `LD_PRELOAD` from snap/Flatpak loader; 18 known-benign package-manager/infrastructure domains for `External domain in persistence mechanism` (canonical.com, debian.org, ubuntu.com, systemd.io, www.gnu.org, mit.edu, and 12 others appearing legitimately in dpkg lifecycle scripts); Pathfinder self-exclusion: `SUDO_USER` env var in Pathfinder processes (`process_in: ["pathfinder", "pathfinder_v-"]` — `"pathfinder"` is exact-match for plain binary; `"pathfinder_v-"` prefix-matches any versioned binary); code-level `OutputPrefix` guard (`filepath.Join(cfg.ReportDir, "pathfinder-")`) skips all Pathfinder output files/dirs/archives/manifests in bodyfile walk + analysis, users staging dir scan, and deepscan (1 site -- unified file walk); `isOwnProcess` guard in volatile skips Pathfinder's own binary from the "outside safe dir" and "suspicious cmdlines" loops; X11 display lock files (`/tmp/.X*-lock`); VMware Tools FHS glob deepened to `/**` (covers `/etc/vmware-tools/scripts/vmware/network` and all nested scripts) |
| Ubuntu    | snap units/udev rules, AppArmor `/dev/shm` references, system dictionary, alternatives binary help text (`cpp`, `www-browser`), snap Firefox volatile paths, specific-file allowlist for cron dirs (T1053.003), update-motd.d (reverse shell risk), init.d SysV scripts (T1037.004), gdm3 lifecycle hooks (session persistence risk), NetworkManager dispatcher (T1546.011), X11/xinit scripts, pm/sleep.d hooks; locale fix profile.d eval, `rc-local.service → /etc/rc.local` exec path |
| Debian    | `rc-local.service → /etc/rc.local` exec path, AppArmor `/dev/shm` references, system dictionary + hash file, alternatives binary help text (`cpp`, `www-browser`), Debian-specific bodyfile FHS allowlist (X11 session scripts, console-setup, cron, gdm3, init.d, nftables, update-motd.d, wpa_supplicant) |
| RHEL/OL   | D-Bus unit symlinks, SELinux policy files, nc binary help text, crypto-policies sshd include, RHEL cron/gdm specific-file allowlist, `rc-local.service → /etc/rc.d/rc.local` exec path; standard RHEL systemd generators: kdump (`kdump-dep-generator`), podman (`podman-system-generator`), SELinux autorelabel (`selinux-autorelabel-generator`); Cockpit web console MOTD script (`/etc/motd.d/cockpit`) |

### Out of Scope (never suppressed)

- `audit: NOPASSWD sudo entry`: genuine privilege escalation risk
- `users: passwd/group file modified`: OS install is not a repeatable baseline event
- `volatile: Process running outside safe directory`: informational; Pathfinder's own binary is excluded at the code level via `isOwnProcess` (`ctx.SelfPath` exact match), but other processes outside safe dirs are still flagged

---

## Output Structure

```
pathfinder-<hostname>-<YYYYMMDD_HHmmss>/
├── baseline/                      # System baseline (8 files)
├── volatile/                      # Process & memory (21 files)
│   ├── 01_running_processes.txt
│   ├── 02_cmdlines_full.txt     # Full untruncated cmdlines
│   ├── 03_process_tree.txt
│   ├── ...
│   └── 21_deleted_files_open.txt
├── users/                         # User artifacts (12 files)
├── persistence/                   # Persistence (20 files)
├── audit/                         # Auth & security (10 files)
├── journal/                       # Systemd journal (if -journal)
│   ├── raw/                       # Raw journal files (/var/log/journal/ and /run/log/journal/)
│   ├── journal_filtered.json      # Filtered journal events
│   └── journal_analysis.txt       # Journal anomaly analysis
├── deepscan/                    # Threat hunting (5 files)
├── bodyfile/                    # Filesystem timeline (full mode only)
│   ├── bodyfile.txt             # Raw mactime body file
│   └── bodyfile_analysis.txt    # Inline anomaly analysis
├── ioc/                       # Custom IOC matches (if -ioc provided)
│   ├── 00_ioc_file.*          # Copy of operator IOC file (chain-of-custody)
│   └── 01_ioc_hits.txt        # All matches grouped by indicator type
├── commands.log                 # TSV audit log: timestamp, module, action, detail
├── findings_summary.txt         # All findings (severity + module + label + message)
├── findings_summary.json        # Machine-readable findings + host metadata (always written)
└── Report.md                    # Analyst report: 4-level hierarchy + verdict
```

**Archives (all land in `<report-dir>`):**

| File | Contents |
|---|---|
| `pathfinder-<host>-<ts>.zip` | Module text output (always produced) |
| `pathfinder-<host>-<ts>-sse.zip` | SSE-PACKAGE collected artifacts (when `-sse-package` provided) |
| `pathfinder-<host>-<ts>-sse-log.txt` | SSE-PACKAGE collection log — per-artifact summary (collected count, skip counts by reason, per-file errors) + total line (when `-sse-package` provided and zip passes verification) |
| `pathfinder-<host>-<ts>-manifest.txt` | Acquisition manifest covering both zips (always produced) |

**Integrity:** MD5 + SHA-256 computed in a single pass for both zips; both hashes recorded in the acquisition manifest. MD5 is for legacy tool compatibility (EnCase, FTK); SHA-256 is authoritative. Hashes are no longer printed to the terminal.

**Streaming zip:** In sequential mode (default), module output is written directly into the final zip as each module runs — no intermediate evidence directory is created. In stealth mode (parallel execution), the six concurrent modules write to disk subdirectories which are flushed into the zip after the parallel group completes, then removed; BODYFILE, DEEPSCAN, and IOC stream directly.

**Cleanup:** Source directory deleted after successful archive creation

### Report.md Structure

`Report.md` is a 4-level nested Markdown hierarchy for analyst triage:

```
## 🟠 High Findings  (N)

### [persistence]

#### Non-standard systemd unit
> **Why it was flagged:** A systemd unit in /etc/systemd/system that package management never installed usually means someone added persistence by hand.
> **Next Steps:** Diff it against your authorized unit-file baseline, then audit the ExecStart path and the install timestamp.

- `[15:04:05]` Non-standard systemd unit: foo.service in /etc/systemd/system
- `[15:04:07]` Non-standard systemd unit: bar.service in /run/systemd/system

### [volatile]

#### Running deleted binary
> **Why it was flagged:** …
> **Next Steps:** …

- `[15:04:12]` Running deleted binary: /tmp/.x1 [sha256:…]
```

**Report header fields:**

| Field | Source |
| --- | --- |
| Case ID | `-case-id` flag |
| Host | `os.Hostname()` |
| Operator | `$USER` / `$LOGNAME` / `uid/<n>` |
| IP(s) | Non-loopback, non-link-local interfaces via `net.Interfaces()` |
| OS | `PRETTY_NAME` from `/etc/os-release` |
| Kernel | First line of `/proc/version` up to first ` (` |
| Architecture | `runtime.GOARCH` |
| CPU | Model name from `/proc/cpuinfo` (case-insensitive match) |
| Memory | Total RAM from `/proc/meminfo`, formatted as human-readable (B/KB/MB/GB) |
| Time Zone | Read from `/etc/timezone`; falls back to `time.Now().Local().Zone()` |
| Mount Points | Non-network, non-pseudo mount points from `/proc/mounts` |
| Date UTC | Scan completion time |

All fields except Case ID, Host, Operator, and Date UTC are omitted from the table if unreadable or empty.

**Grouping rules:**

- Severity order: HIGH → MEDIUM → LOW → INFO (empty sections omitted)
- Categories sorted by total finding count descending within each severity
- Labels sorted alphabetically within each category
- All message instances listed individually in timestamp order (no deduplication)
- Category is derived at report-write time from `report.Detections[label].Category`; falls back to module name if label is unregistered
- Why/Next Steps block omitted for unregistered labels; a warning is printed to stderr

---

## IOC Signatures

### Bash History Signatures (39 patterns)




| ID    | Severity | Pattern Description                                                                  |
| ----- | -------- | ------------------------------------------------------------------------------------ |
| BH001 | HIGH     | `curl ... | sh`: pipe to shell                                                      |
| BH002 | HIGH     | `wget ... |`: pipe to shell                                                         |
| BH003 | HIGH     | Python one-liner exec/eval/os                                                        |
| BH004 | HIGH     | Perl one-liner exec/system/socket                                                    |
| BH005 | HIGH     | `base64 -d |`: encoded payload                                                      |
| BH006 | HIGH     | `nc/ncat/netcat -e`: reverse shell                                                  |
| BH007 | HIGH     | `bash -i >& /dev/tcp/`: reverse shell                                               |
| BH008 | HIGH     | `socat ... exec|pty|tcp`: tunnel/PTY                                                |
| BH009 | HIGH     | History evasion (HISTFILE, HISTFILESIZE=0)                                           |
| BH010 | HIGH     | `dd if=/dev/mem|sda`                                                                 |
| BH011 | HIGH     | `iptables -F`: firewall flush                                                       |
| BH012 | MEDIUM   | `useradd/adduser`                                                                    |
| BH013 | HIGH     | `usermod -G sudo|wheel|root`                                                         |
| BH014 | HIGH     | `chmod +s`: SUID/SGID                                                               |
| BH015 | MEDIUM   | `chattr +i`                                                                          |
| BH016 | MEDIUM   | `pkill/kill -9`                                                                      |
| BH017 | MEDIUM   | Unusual mounts (--bind, tmpfs)                                                       |
| BH018 | MEDIUM   | Python HTTP server                                                                   |
| BH019 | HIGH     | Download to /tmp or /dev/shm                                                         |
| BH020 | MEDIUM   | `chmod 777`                                                                          |
| BH021 | MEDIUM   | `crontab -e/-l/-r`                                                                   |
| BH022 | MEDIUM   | `nohup ... &`                                                                        |
| BH023 | HIGH     | `eval $(`: command substitution                                                     |
| BH024 | LOW      | `scp` remote copy                                                                    |
| BH025 | HIGH     | `HISTFILE=/dev/null`                                                                 |
| BH026 | HIGH     | `insmod/modprobe`                                                                    |
| BH027 | MEDIUM   | `strace -p`: process attach                                                         |
| BH028 | MEDIUM   | `tcpdump`                                                                            |
| BH029 | MEDIUM   | `at now` / scheduled at job                                                          |
| BH030 | HIGH     | Direct access to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`                        |
| BH031 | HIGH     | `shopt -ou history`: shell history suppression                                      |
| BH032 | HIGH     | `setenforce 0`: SELinux disabled at runtime                                         |
| BH033 | HIGH     | `systemctl/service stop/disable firewalld/apparmor/ufw`                              |
| BH034 | HIGH     | `finit_module(...)`: fileless kernel module load via syscall                         |
| BH035 | MEDIUM   | `masscan/zgrab/pnscan`: network scanner — lateral movement recon                    |
| BH036 | HIGH     | `curl ... x-aws-ec2-metadata-token`: IMDSv2 metadata token request                   |
| BH037 | HIGH     | `curl ... metadata.google.internal`: GCP metadata API probe                          |
| BH038 | HIGH     | `curl ... 169.254.169.254`: Cloud IMDS endpoint probe — AWS/Azure/Alibaba/Tencent    |
| BH039 | HIGH     | `chmod [2-7][0-7]{3}`: SUID/SGID bit set via octal notation                         |



### String Hunt Signatures (4 active categories)

**Web Shells (02):** `system('/bin/sh')`, passthru/shell_exec/popen, base64_decode, gzinflate/str_rot13/gzuncompress, CGI env vars (REMOTE_ADDR, HTTP_USER_AGENT, REQUEST_URI); SH001–SH005

**Stagers & C2 (03):** SSH RSA key strings, pastebin/hastebin/transfer.sh, curl/wget present (SH008 — LOW), credential env var harvest (GITHUB_TOKEN/NPM_TOKEN/AWS_ACCESS_KEY_ID), DNS exfil API; SH006–SH010

**Script Execution (04):** Obfuscated eval chains (SH011 eval+atob/Buffer.from), Function constructor (SH012), deferred eval via timer (SH013), child_process require (SH014), execSync/spawnSync (SH015), OS fingerprinting (SH016), filesystem ops (SH017), Python os.system (SH018), subprocess (SH019), Python one-liner (SH020), sh/bash -c command substitution (SH021); SH011–SH021. SH030 (wildcard bun runtime execution: `bun run *.js` / `bun run dist/*.ts`) is Layer 2 only, applied in `deepNPMSupplyChain` against lifecycle script values.

**Data Exfiltration (06):** Cloud storage/webhook upload URLs — S3 (`s3.amazonaws.com`), GitHub API contents, GDrive (`googleapis.com/upload`), Telegram bot `send*`, Discord webhooks (SH023 — HIGH); curl/wget with `--upload-file`/`--data-binary`/`--data-raw`/`-T`/`-F @file` (SH024 — HIGH); tar archive piped to curl/nc/socat/openssl/ssh (SH025 — HIGH); compression tool redirected to staging dir (SH026 — MEDIUM); scp outbound `user@host:path` (SH027 — HIGH); rsync over SSH `-e ssh`/`--rsh=ssh` (SH028 — HIGH); sftp `user@host` (SH029 — MEDIUM); SH023–SH029

### Process Environment Variable Signatures (33 rules)


| Category          | Variable                                                                          | Severity |
| ----------------- | --------------------------------------------------------------------------------- | -------- |
| History evasion   | `HISTFILE=/dev/null`                                                              | HIGH     |
| History evasion   | `HISTSIZE=0`, `HISTFILESIZE=0`                                                    | HIGH     |
| History evasion   | `HISTCONTROL=ignorespace`                                                         | MEDIUM   |
| History evasion   | `MYSQL_HISTFILE=/dev/null` (BPFDoor)                                              | HIGH     |
| Rootkit injection | `LD_PRELOAD` non-standard path                                                    | HIGH     |
| Rootkit injection | `LD_PRELOAD` non-standard library path (not staging)                              | MEDIUM   |
| Rootkit injection | `LD_LIBRARY_PATH` non-standard path                                               | HIGH     |
| Library hijack    | `PYTHONPATH`, `PERL5LIB` non-standard                                             | MEDIUM   |
| Access trace      | `REMOTEHOST` present                                                              | LOW      |
| Privilege trace   | `SUDO_USER` present                                                               | MEDIUM   |
| Lateral movement  | `SSH_CONNECTION`, `SSH_CLIENT`, `SSH_TTY`, `SSH_ORIGINAL_COMMAND`                 | MEDIUM   |
| Web shell         | `HTTP_USER_AGENT`, `REMOTE_ADDR`, `REQUEST_URI`, `REQUEST_METHOD`, `QUERY_STRING`, `SCRIPT_NAME`, `HTTP_HOST`, `SERVER_NAME` | MEDIUM   |
| Staging           | `PATH` starts with `.`, `/tmp`, or `/dev/shm`                                     | HIGH     |
| Staging           | `PWD` is `/tmp`, `/dev/shm`, or `/var/tmp`                                        | MEDIUM   |
| Staging           | `OLDPWD` is a staging directory                                                   | MEDIUM   |
| Cloud credentials | `AWS_ACCESS_KEY_ID` non-empty: credential theft / cloud pivot         | HIGH     |
| Cloud credentials | `AWS_SECRET_ACCESS_KEY` non-empty: cloud credential exposure                     | HIGH     |
| Cloud credentials | `AWS_SESSION_TOKEN` non-empty: possible stolen credential use                    | HIGH     |
| Cloud credentials | `GOOGLE_APPLICATION_CREDENTIALS` non-empty: GCP service account path  | HIGH     |
| Cloud credentials | `AZURE_CLIENT_SECRET` non-empty: Azure credential exposure                       | HIGH     |
| Cloud credentials | `KUBECONFIG` pointing to staging directory: Kubernetes pivot                     | HIGH     |


### Malware Directory Prefixes

Known staging and payload directories checked by `ioc.IsInMalwareDir()`:


| Prefix           | Associated Malware            |
| ---------------- | ----------------------------- |
| `/dev/mqueue/`   | POSIX message queue filesystem — used as staging dir by some malware |
| `/run/shm/`      | Legacy shared memory path — alternative to `/dev/shm/` for staging  |
| `/var/tmp/.11/`  | Linux malware staging                                                |
| `/var/tmp/.222/` | Linux malware systemd payload                                        |


Note: `/var/tmp/.dog` (Linux malware infection marker) is a file, not a directory prefix. It is caught by the USERS staging dir scan of `/var/tmp/` which hashes all files.

---

## IOC File Format

The IOC file is a plain text file with section headers and one indicator per line. Pass it via `-ioc /path/to/iocs.txt`.

```
# Lines starting with # are comments
# Blank lines are ignored

[commands]
curl * | bash
HISTFILE=/dev/null
regex:base64\s+-d\s*\|

[filenames]
ld.so.evil
regex:^\.x[0-9]+$
/tmp/.hidden

[processes]
xmrig
kworker/u4:3

[domains]
*.c2.io
regex:^[a-z]{8}\.pw$
evil.actor.net

[ips]
185.220.101.5
10.100.0.0/16
regex:^203\.0\.113\.

[hashes]
d41d8cd98f00b204e9800998ecf8427e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Indicator matching rules:**


| Indicator Type                                          | Matching Logic                                                                |
| ------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Literal string in `[commands]` / `[domains]`            | Case-insensitive substring (`strings.Contains`): fastest path                |
| Literal string in `[filenames]`                         | Case-insensitive match on a path or word boundary (so `sh` matches `/bin/sh`, not `bash`) |
| Literal string in `[processes]`                         | Case-insensitive exact or basename match of the process comm (so `sh` matches `sh` or `/bin/sh`, not `bash`/`ssh`) |
| Glob wildcard (`*` or `?`)                              | Auto-compiled to regex: `*` → `.`*, `?` → `.`                                 |
| Regex (contains `[`, `]`, `^`, `$`, `|`, `\`, `(`, `)`) | Compiled as case-insensitive regexp                                           |
| `regex:` prefix                                         | Forces explicit regex interpretation; `regex:` prefix stripped before compile |
| CIDR (IPs section only, e.g. `10.0.0.0/8`)              | Parsed via `net.ParseCIDR` and matched with `net.IPNet.Contains`              |
| Hash (32/40/64 lowercase hex: MD5/SHA-1/SHA-256)       | Exact map lookup; matching digests computed per scanned file                  |


**Supported hash lengths:** MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex). Values are normalized to lowercase on load. The scanner computes whichever of these digests appear in the loaded IOC set, in a single pass per file, so an MD5 or SHA-1 indicator now matches scanned files (restored in v1.53.38, reversing the SHA-256-only behavior of v1.53.35). dpkg `.md5sums` entries are matched via their pre-stored MD5 values without recomputing them.

**Error handling:**

- Invalid regex entries: warned to stderr with line number and skipped; load continues
- Invalid hash entries (wrong length or non-hex chars): warned and skipped
- Load warning format: `[IOC WARN] line 42: invalid pattern "bad[rx" — skipped`
- Load summary printed via `output.Info` (respects `-stealth`): `198 IOC indicators loaded, 2 skipped (invalid regex/hash)`
- Performance advisory appended to summary if total > 500: `... -- consider splitting IOC file for faster scans`

**Performance characteristics:**

- All matchers are compiled once at load time; no per-event recompile
- Literal matchers use `strings.Contains` (no regex engine overhead)
- Early-exit per line: stops at first match per indicator type
- Hash computation is mode-gated (`-mode full` only) and size-capped (`-ioc-max-hash-mb`, default 100 MB)

---

## Severity & Verdict Logic

**Severities:** `HIGH` · `MEDIUM` · `LOW` · `INFO`

**Terminal output colour coding (Blade Runner 2049 palette):**


| Label            | Colour                          | Meaning                                    |
| ---------------- | ------------------------------- | ------------------------------------------ |
| `[!]`            | Dark amber (`\033[38;5;136m`)   | Warning: anomaly count or partial failure  |
| `[+]`            | Forest green (`\033[38;5;22m`)  | Section completed cleanly                  |
| `[~]`            | Sage (`\033[38;5;64m`)          | Informational note (`Info`)                |
| `[~]`            | Gray (`\033[2;37m`)             | Informational note (`Note`)                |
| `[-] SKIPPED —`  | Gray (`\033[2;37m`)             | Section skipped (missing prerequisite)     |
| Finding `HIGH`   | Deep crimson (`\033[38;5;160m`) | High-severity finding                      |
| Finding `MEDIUM` | Burnt orange (`\033[38;5;166m`) | Medium-severity finding                    |
| Finding `LOW`    | Golden ochre (`\033[38;5;178m`) | Low-severity finding                       |
| Finding `INFO`   | Gray (`\033[2;37m`)             | Observation that changes analyst behavior  |


**Verdict** (printed to stdout and `Report.md`):


| Condition                                                        | Verdict                                                    |
| ---------------------------------------------------------------- | ---------------------------------------------------------- |
| HIGH count ≥ `-breach-threshold` (default 50)                    | `HOSTILE INDICATORS DETECTED — IMMEDIATE ACTION REQUIRED`  |
| HIGH count ≥ `-compromise-threshold` (default 10)                | `RISK DETECTED — HIGH SEVERITY FINDINGS PRESENT`             |
| HIGH count > 0 or MEDIUM count > 0                               | `SUSPICIOUS — INVESTIGATE MEDIUM FINDINGS`                 |
| All zero                                                         | `ALL CLEAR`                                                |


The breach threshold (default 50) is configurable via `-breach-threshold N`. The compromise threshold (default 10) is configurable via `-compromise-threshold N`. HIGH findings below the compromise threshold still produce SUSPICIOUS.

---

## Build System

The output binary runs only on **Linux**. You can build it from Windows, macOS, or Linux; Go handles the translation automatically.

### Step 1: Install Go

Download and install Go 1.24+ from **[https://go.dev/dl/](https://go.dev/dl/)**. Accept all defaults.

Confirm it worked by opening a terminal and running:

```
go version
```

You should see something like `go version go1.24.x ...`

### Step 2: Install Make

`make` is the build tool that runs the build commands.

**Windows:**

1. Install [Git for Windows](https://git-scm.com/download/win) and this also installs Git Bash, which includes `make`.
2. Open **Git Bash** (not Command Prompt or PowerShell) for all commands below.

**macOS:**

```bash
xcode-select --install
```

If that fails, install [Homebrew](https://brew.sh) then run `brew install make`.

**Linux (Debian/Ubuntu):**

```bash
sudo apt-get install -y make
```

### Step 3: Get the source code

```bash
git clone <repo-url> pathfinder
cd pathfinder
```

### Step 4: Download dependencies

```bash
go mod tidy
```

### Step 5: Build

```bash
make linux-amd64
```

This produces `pathfinder-linux-amd64` in the current folder, a single file, ~3.6 MB.

**Other build options:**

```bash
make linux-arm64          # for ARM-based Linux servers (e.g. AWS Graviton)
make all                  # both amd64 and arm64 at once
```

### Step 6: Verify

```bash
ls -lh pathfinder-linux-amd64
```

Expected output: a file around 3–4 MB.

On Linux/macOS you can also confirm it's a valid Linux binary:

```bash
file pathfinder-linux-amd64
# pathfinder-linux-amd64: ELF 64-bit LSB executable, x86-64, statically linked
```

### Step 7: Copy to the target system

```bash
scp pathfinder-linux-amd64 analyst@target:/tmp/
ssh analyst@target "sudo /tmp/pathfinder-linux-amd64"
```

Or copy via USB/shared drive; it's a single self-contained file, no installation needed on the target.

---

### Troubleshooting


| Problem                                       | Fix                                                            |
| --------------------------------------------- | -------------------------------------------------------------- |
| `go: command not found`                       | Go is not installed or not in PATH; reinstall from go.dev/dl  |
| `make: command not found`                     | See Step 2 above                                               |
| `go mod tidy` downloads nothing               | Normal if dependencies are already cached                      |
| Build succeeds but binary won't run on target | Confirm target is Linux x86-64; use `make linux-arm64` for ARM |


**Linker flags applied to all targets:** `-s -w` (strip debug + symbol table) + embedded `GitCommit` and `BuildDate`.


| Target                   | Output                   | Notes                              |
| ------------------------ | ------------------------ | ---------------------------------- |
| `make build`             | `pathfinder`                | Current platform                   |
| `make linux-amd64`       | `pathfinder-linux-amd64`    | Static, CGO_ENABLED=0              |
| `make linux-arm64`       | `pathfinder-linux-arm64`    | Static, CGO_ENABLED=0              |
| `make all`               | amd64 + arm64            | Default production build           |
| `make clean`             | —                        | Remove all binaries                |
| `make test`              | —                        | `go test ./...`                    |
| `make vet`               | —                        | `go vet ./...`                     |
| `make tidy`              | —                        | `go mod tidy`                      |


**Azure upload is compiled into every build** with no external SDK; it uses only the Go standard library (`net/http`), so the default binary stays under 10MB (typical: ~3.6MB stripped). There is no longer an `azure` build tag.

---

## Azure Upload

**Enabled by:** `-azure-sas-url` (or the `PATHFINDER_AZ_SAS_URL` env var). The SAS must be container-scoped (`sr=c`) with create/write permission (`sp=cw` or broader); a blob-scoped SAS is rejected at startup.

**Blob path structure:** `<container>/<case-id>/<artifact-filename>`

**Flow:**

1. Uploader starts a background worker goroutine at program start, after validating the SAS is container-scoped.
2. Only final artifacts are enqueued, in order: the acquisition manifest first (it carries the zip's expected hashes), then the evidence zip, then the SSE zip when present. Upload runs only when the main archive passed verification and hashing; an unverified or corrupt archive is never uploaded and its source directory is kept for recovery.
3. `Wait()` blocks until all uploads finish, then returns the combined error of any that failed or were dropped; the main flow warns on a non-nil result instead of reporting success.
4. Upload queue capacity: 128 files. Overflow is dropped (logged to stderr and recorded in the `Wait()` error) and collection is never blocked.

**Transport:** plain `net/http` PUT, no SDK. Files at or under 256 MiB use a single `Put Blob`; larger files stage `Put Block` chunks (100 MiB each) committed via `Put Block List`. Every PUT carries `Content-MD5` (per-block on the chunked path, plus a whole-file `x-ms-blob-content-md5` on commit) so the service validates the transfer and stores the digest for chain-of-custody. TLS verification is on by default; transient network errors and HTTP 5xx are retried with bounded exponential backoff.

**Auth:** the SAS URL itself. No storage account key is embedded on the host being triaged.

---

## Architecture

### Package Overview

| Package             | Purpose                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------- |
| `main`              | Orchestration, host meta, banner, casebook, impact map, verdict, `writeReport()`        |
| `internal/config`   | CLI flag parsing, mode/timeout/format resolution                                         |
| `internal/modules`  | All collection modules + shared ModuleContext                                            |
| `internal/ioc`      | Signature DB, IP/domain extraction, safe-dir/malware-dir checks, IOC parser + scanner   |
| `internal/output`   | Finding registry, thread-safe file writers, master log, JSON report writer               |
| `internal/report`   | Single source of truth: `Detections` map, label → category + analyst tips               |
| `internal/suppress` | Suppression engine, embedded distro profiles, user-supplied suppress-config rules        |
| `internal/procfs`   | `/proc` parsing: processes, utmp/wtmp/btmp, passwd/group                                 |
| `internal/netfs`    | `/sys/class/net` + `/proc/net` parsing                                                   |
| `internal/osutil`   | `O_NOATIME` file reads, `ReadFileCapped` bounded-read primitive, file-size formatting     |
| `internal/archive`  | ZIP creation (`ZipAndClean`, `FlushDirToZip`), dual-hash (`FileHashes`), acquisition manifest, directory cleanup. Symlinks are stored as links (never followed); non-regular nodes are recorded in the manifest skip list |
| `internal/cloud`    | Azure SAS uploader (`net/http` PUT, no SDK) + `Uploader` interface                       |
| `internal/logutil`  | Command execution logging                                                                |
| `internal/sysfs`    | Immutable file detection via `FS_IOC_GETFLAGS` ioctl; no-op stub for non-Linux builds   |


### Resource Limits & Bounded Reads

Every read of an attacker-influenceable file is size-bounded so a planted oversized file cannot exhaust memory and abort collection. All bounded reads share one primitive, `osutil.ReadFileCapped`, which reads through an `io.LimitReader` (so it also works on `/proc` files that report a zero `st_size`) and preserves `O_NOATIME`. When a cap engages the read is truncated and the event is recorded; it is never silently shortened.

| Source | Cap | Where recorded on truncation |
| ------ | --- | ---------------------------- |
| Config/text evidence (crontabs, `.service`, dotfiles, PAM/ld configs, dpkg lists) | 10 MiB (`readEvidenceFile`) | `commands.log` + console warning |
| `/proc/<pid>/maps`, `environ`, `status` | 16 MiB (`procfs`) | in-band marker line in the saved output |
| Systemd journal collection buffer | 128 MiB | `commands.log` + console warning |
| `/dev/kmsg` drain | 8 MiB or 100k records | section file note + `commands.log` + warning |
| Hidden-process unmasking | 1-byte existence probe per PID | n/a (existence check only) |

These are in addition to the pre-existing feature caps (IOC hash `-ioc-max-hash-mb`, webshell 1 MB, bodyfile size limits, SSE-Package `max_file_size`).


### Execution Flow

```
Parse config → output.SetQuiet(cfg.Stealth) → collectHostMeta()
    │
    ▼
printBanner() (if !stealth)
    │
    ▼
Init ModuleContext (create dirs, open log)
    │
    ▼
Load IOC file (if -ioc provided) → ctx.IOC
    │
    ▼
Load suppress-config rules → init suppress engine → ctx.Registry.SetEngine()
    │
    ▼
Start Azure SAS uploader (if -azure-sas-url set)
    │
    ▼
─── SSE-only early exit (-sse-only) ───────────────────────────────────────
│  RunSSEPackage → write manifest (SSE fields only) → os.Exit(0)          │
────────────────────────────────────────────────────────────────────────────
    │
    ▼
printMetadata() (if !stealth)
    │
    ▼
Open zip file → zip.Writer
    │
    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  Stealth mode (parallel execution)       │  Default OOV mode                │
│  ─────────────────────────────────────── │  ──────────────────────────────── │
│  ctx.ZipWriter = nil (disk)              │  ctx.ZipWriter = zw (streaming)   │
│  PARALLEL (WaitGroup):                   │  Sequential, most ephemeral first: │
│  VOLATILE · USERS · BASELINE             │  VOLATILE → AUDIT → JOURNAL       │
│  PERSISTENCE · AUDIT · JOURNAL           │  USERS → PERSISTENCE → BASELINE   │
│  ↓ wg.Wait()                             │                                   │
│  FlushDirToZip each subdir → RemoveAll   │                                   │
│  ctx.ZipWriter = zw (streaming from here)│                                   │
└──────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
BODYFILE (full mode only) → zip entries directly
    │
    ▼
SSE-PACKAGE (if manifest provided) → own SSE zip (unchanged)
    │
    ▼
DEEPSCAN (if enabled) → zip entries directly
    │
    ▼
IOC (if -ioc provided) → zip entries directly
    │
    ▼
Log suppression counts → ctx.Log.Close()
    │
    ▼
printCasebook() → findings_summary.txt + findings_summary.json + Report.md
    │
    ▼
printImpactMap() (if !stealth)
    │
    ▼
Flush commands.log + Report.md into zip → zw.Close() → FileHashes(zip) → RemoveAll source dir
    │
    ▼
Azure Upload manifest + zip → Azure Wait (if configured)
    │
    ▼
Print verdict
```

### Key Types

`**ModuleContext**`: passed to every module:

- `Cfg *config.Config`: parsed CLI flags
- `Dirs Dirs`: all output subdirectory paths (includes `Dirs.IOC`, `Dirs.Journal`)
- `Registry *output.Registry`: thread-safe finding storage
- `Log *output.MasterLog`: structured TSV audit log
- `Uploader cloud.Uploader`: nil when `-azure-sas-url` is not set
- `IOC *ioc.IOCSet`: nil when `-ioc` not set; all IOC integrations nil-guard on this field
- `ZipWriter *zip.Writer`: nil = module writes output to disk files; non-nil = `newSectionWriter` buffers all writes in a `bytes.Buffer` and flushes the complete buffer to a new zip entry via `CreateHeader` on `Close()`. Deferred `CreateHeader` satisfies `archive/zip`'s sequential-write constraint (calling `CreateHeader` again closes the previous entry's writer). Callers that already maintain an in-process buffer for downstream analysis (e.g. `RunBodyfile`) use `newSectionWriterWithBuf`, passing their own `*bytes.Buffer` as the backing store; this avoids allocating a second buffer and keeps peak memory at 1× the output size. Set before modules run in sequential mode; set after the parallel-group flush in stealth (parallel) mode.
- `SelfPath string`: resolved binary path (`os.Executable()` + `filepath.EvalSymlinks`); all `walkFiles` scans skip the binary itself plus the three operator-supplied input files (`cfg.IOCFile`, `cfg.SuppressFile`, `cfg.ManifestPath`) to prevent false positives from operator input containing IOC strings or rule patterns
- `OutputPrefix string`: `filepath.Join(cfg.ReportDir, "pathfinder-")` — prefix shared by all Pathfinder output files and directories across all runs; bodyfile, users, and deepscan modules skip any path matching this prefix (WalkDir entries use `filepath.SkipDir`; flat loops use `continue`); covers subdirs, archives, and manifest files from previous runs without requiring exact path knowledge; code-level guard skips all Pathfinder output in bodyfile walk + analysis, users staging dir scan, and deepscan (1 site -- unified file walk)

`**config.Config**`:

- `Mode string`: "full" or "quick"
- `OutputFormat string`: "text" or "json"
- `BreachThreshold int`: default 50
- `Stealth bool`: suppress stdout
- `IOCFile string`: path to custom IOC file (empty = disabled)
- `IOCMaxHashMB int`: max file size in MB for hash computation (default 100)
- `SuppressFile string`: path to user suppression rules YAML (empty = disabled)
- `ShowSuppressed bool`: print suppressed findings with `[SUPPRESSED]` tag
- `SSEOnly bool`: run SSE-PACKAGE only; skip all detection modules, main zip, and casebook output
- `CaseID string`: case/incident identifier
- `ManifestPath string`: path to SSE-package manifest (empty = disabled)

`**ioc.IOCSet**`: compiled IOC set loaded from IOC file:

- `Commands`, `Filenames`, `Processes`, `Domains`, `IPs []ioc.Matcher`: compiled indicator lists
- `Hashes map[string]struct{}`: lowercase hex set (MD5/SHA1/SHA256)
- `Loaded int`, `Skipped int`: parse statistics
- Methods: `MatchCommand`, `MatchFilename`, `MatchProcess`, `MatchDomain`, `MatchIP`, `MatchHash`

`**ioc.Matcher**`: single compiled indicator:

- `Raw string`: original entry from IOC file
- `IsLiteral bool`: use `strings.Contains` fast path
- `IsRegex bool`: use compiled `Re`
- `Re *regexp.Regexp`: compiled regex (case-insensitive)
- `CIDR *net.IPNet`: non-nil for IP CIDR entries only

`**output.Finding`:**

- `Severity`: HIGH / MEDIUM / LOW / INFO
- `Module`: volatile, users, baseline, persistence, audit, journal, deepscan, bodyfile
- `Label`: detection key (e.g. `"Non-standard systemd unit"`); maps to `report.Detections`
- `Message`: human-readable description
- `Timestamp`: UTC

`**output.Registry**`: thread-safe (sync.Mutex); methods: `Add(sev, module, label, msg)` (store + print to console), `AddSilent(sev, module, label, msg)` (store only, no console output), `All()`, `Counts() (high, med, low, info int)`, `WriteJSONReport(path, report)`

`**output.Writer**`: wraps `*os.File` with mutex; `SetOnClose(func(string))` flushes the buffered section into the zip writer on section close (zip mode). Azure upload is no longer per-section; only final artifacts are uploaded.

`**output.FindingsReport**`: JSON output structure:

```
CaseID, Host, ScanTime, Verdict
Counts: { High, Medium, Low }
Findings: [ { Severity, Module, Label, Message, Timestamp } ]
OS, Arch, CPU, MemTotal (mem_total), TimeZone (timezone), Mounts, TempDir (temp_dir), Kernel, IPs
```

Host metadata fields are omitted from JSON output (`omitempty`) when empty or unreadable.

`**report.Detection**`: analyst tip entry:

- `Category string`: finding category (e.g. `"persistence"`, `"volatile"`, `"users"`)
- `WhyFlagged string`: risk explanation shown under each label in Report.md
- `NextSteps string`: verification steps shown under each label in Report.md

`**report.Detections**`: `map[string]Detection` keyed by label string; covers all 169 registered detection labels. Any label emitted by a module but absent from this map triggers a warning to stderr at report-write time.

---

## Privilege Requirements


| Module      | Root Required | Impact Without Root                                                                                                            |
| ----------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| VOLATILE    | Partial       | Hidden process detection and unbacked memory analysis degraded                                                                 |
| USERS       | Partial       | Recently modified files section skipped                                                                                        |
| BASELINE    | No            | Full coverage                                                                                                                  |
| PERSISTENCE | No            | `/run/systemd` generators may be unreadable                                                                                    |
| AUDIT       | Yes           | Sudoers, shadow, immutable files all skipped                                                                                   |
| JOURNAL     | Yes           | Raw journal copy and filtered collection skipped; analysis skipped (no data)                                                   |
| BODYFILE    | No            | Limited coverage (user-unreadable paths skipped silently)                                                                      |
| DEEPSCAN    | No            | Full analysis available; file integrity check depends on `debsums`/`rpm`                                                       |
| SSE-PACKAGE | Depends       | Limited to files readable by invoking user                                                                                     |
| IOC         | Partial       | Hash computation of root-owned process binaries requires root; log scanning limited to readable files; other checks unaffected |


Run as root for full evidence coverage. Non-root runs are valid for initial triage.

---

## Testing

Unit tests span multiple packages (`internal/ioc`, `internal/suppress`, `internal/modules`, `internal/procfs`, `internal/osutil`, `internal/archive`). Run with:

```bash
GOOS=linux go test -c -o /dev/null ./internal/modules/...   # compile verify (Windows cross-compile)
go test ./internal/ioc/... -v
go test ./internal/suppress/... -v
make test   # runs go test ./...
```

**Test coverage:**

**`internal/ioc/ioc_test.go`**

| Test                             | Count            | Description                                                                                                      |
| -------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| `TestBashHistorySignatures`      | 78 subtests      | Each BH001–BH039: positive match + negative case                                                                 |
| `TestStringHuntSignatures`       | 42 subtests      | SH001–SH021 (positive match + negative case)                                                                             |
| `TestSH021_CoversBothBashAndSh`  | 4 cases          | SH021 matches both `bash -c` and `sh -c` cmd-substitution patterns; negatives for single-quoted variants                 |
| `TestEnvVarRules_`*              | 5 tests          | HISTFILE, HISTSIZE, LD_PRELOAD, PATH, HISTCONTROL                                                                |
| `TestIsPrivateIP`                | 1 test (9 cases) | RFC-1918 + loopback + link-local detection                                                                       |
| `TestExtractExternalIPs`         | 1 test           | Mixed public/private IP text → only public returned                                                              |
| `TestIsInSafeDir`                | 1 test (8 cases) | Safe system dirs vs staging dirs                                                                                 |
| `TestIsCompressedFile`           | 1 test (8 cases) | Extension-based archive detection                                                                                |
| `TestIsMagicELF`                 | 1 test           | ELF magic bytes (0x7fELF) vs shell script                                                                        |
| `TestScanLines`                  | 1 test           | Line-by-line scanner returns correct sig ID and line number                                                      |
| `TestScanLines_NoFalsePositives` | 1 test           | Benign commands produce no hits                                                                                  |
| `TestScanLines_ReportsAllMatchesPerLine` | 1 test  | Compound attack line (base64-decode + curl-pipe) produces hits for both BH001 and BH005                         |
| `TestExtractDomains`             | 1 test           | Domain extraction excluding localhost                                                                            |
| `TestIsInMalwareDir`             | 1 test (3 cases) | Malware staging dir detection                                                                                    |
| `TestCompileMatcher_GlobPipeIsLiteral` | 1 test   | `\|` in a glob pattern is treated as a literal pipe, not regex alternation                                       |
| `TestCompileMatcher_GlobDotIsLiteral`  | 1 test   | `.` in a literal domain IOC is not interpreted as regex any-char                                                 |
| `TestParseIOCSet_LoadsAllSections`     | 1 test   | File-based parse: all 6 section types load correctly, Loaded count accurate                                      |
| `TestParseIOCSet_InvalidHashSkipped`   | 1 test   | Malformed hash increments Skipped, not Loaded                                                                    |
| `TestParseIOCSet_CommentsAndBlankLinesIgnored` | 1 test | Comments and blank lines do not affect load counts                                                        |
| `TestParseIOCSetFromString_UnknownSectionNotCounted` | 1 test | Indicators under unknown section headers counted as Skipped                                          |
| `TestMatchIP_LiteralNoSubstringMatch`  | 1 test   | Literal IOC `1.1.1.1` does not match superset addresses like `21.1.1.10`                                        |
| `TestMatchIP_CIDRContainment`          | 4 cases  | CIDR range matching via `AppendIPMatcher`; boundary and out-of-range cases                                       |
| `TestIOCScanTextForIPs_MultiLineDedup` | 1 test   | Same IP on three separate lines produces three independent hits                                                  |
| `TestIOCScanTextForIPs_SameLineDedup`  | 1 test   | Same IP appearing twice on one line produces exactly one hit                                                     |
| `TestIOCScanTextForIPs_MatchesPrivateIPInSet` | 1 test | Private IP explicitly loaded as an IOC is correctly matched                                               |
| `TestIOCScanText_Basic`                | 1 test   | Domain IOC found in text; hit has correct LineNum                                                                |
| `TestIOCScanText_EmptyReturnsNil`      | 1 test   | Empty input text returns nil slice                                                                               |
| `TestIOCSet_Match*`                    | —        | Per-type match methods: MatchCommand, MatchFilename, MatchProcess, MatchIP, MatchHash                            |

**`internal/suppress/suppress_test.go` and `distro_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestNew_UnknownDistro` | Universal-only load succeeds with non-zero rule count |
| `TestNew_UbuntuLoadsExtraRules` | Ubuntu engine has more rules than universal-only |
| `TestNew_DebianLoadsExtraRules` | Debian engine has more rules than universal-only |
| `TestNew_RHELLoadsExtraRules` | RHEL engine has more rules than universal-only |
| `TestCheck_BuiltInKernelModule` | `module:volatile` built-in kernel module suppressed |
| `TestCheck_PathInMatch` / `NoMatch` | SSH host key suppressed; `sshd_config` not suppressed |
| `TestCheck_PathGlob` / `Doublestar` | `/etc/grub.d/*` and `pathfinder-*/**` glob matching |
| `TestCheck_ProcessInExact` / `Prefix` / `PrefixNoMatch` | NetworkManager, `power-profiles-daemon` prefix match |
| `TestCheck_FirefoxESRAnonExec` | `firefox-esr` anonymous exec suppressed (universal) |
| `TestCheck_GnomeTerminalAnonExec` / `RWX` | `gnome-terminal-` JIT suppressed (universal) |
| `TestCheck_PPPSubdirFHS` | `/etc/ppp/ip-down.d/` file suppressed via `**` glob |
| `TestCheck_AcpiShFHS` | `/etc/acpi/*.sh` suppressed via glob (universal) |
| `TestCheck_AvahiAutoipdActionFHS` | `/etc/avahi/avahi-autoipd.action` suppressed (universal) |
| `TestCheck_DhclientEnterHookFHS` / `ExitHookFHS` | DHCP enter/exit hook dirs suppressed via glob (universal) |
| `TestCheck_UbuntuNMDispatcherFHS` | `/etc/NetworkManager/dispatcher.d/01-ifupdown` suppressed on Ubuntu |
| `TestCheck_UbuntuCronDailyBsdmainutilsFHS` / `CronWeeklyUpdateNotifierFHS` | Ubuntu cron specific-file suppressions |
| `TestCheck_UbuntuGdm3InitDefaultFHS` | `/etc/gdm3/Init/Default` suppressed on Ubuntu |
| `TestCheck_UbuntuInitdAcpidFHS` / `InitdUdevFHS` | Ubuntu init.d specific-file suppressions |
| `TestCheck_UbuntuXinitrcFHS` | `/etc/X11/xinit/xinitrc` suppressed on Ubuntu |
| `TestCheck_UbuntuPmSleepGrubFHS` | `/etc/pm/sleep.d/10_grub-common` suppressed on Ubuntu |
| `TestCheck_UbuntuMotd88EsmAnnounceFHS` | `/etc/update-motd.d/88-esm-announce` suppressed on Ubuntu |
| `TestCheck_DbusFiUniversal` | `dbus-fi.w1.wpa_supplicant1` suppressed universally |
| `TestCheck_GnomeSessionI*` | `gnome-session-i` comm-truncation JIT suppressed |
| `TestCheck_BwrapNetNS` / `GlycinNetNS` / `SystemdLocaledNetNS` | Flatpak sandbox namespace suppressed |
| `TestCheck_GnomeSessionNetNS` | ~60 GNOME desktop session processes suppressed for `Process in non-host network namespace` |
| `TestCheck_UdevWorkerBinaryMismatch` | udevadm prctl rename suppressed |
| `TestCheck_UbuntuIPv6HostsEntry` | `fe00::0 ip6-localnet` suppressed on Ubuntu |
| `TestCheck_ApportAutoreportPath` / `TpmUdevPath` | Ubuntu `.path` units suppressed |
| `TestCheck_KdumpTools*` / `MotdNews*` / `RcLocal*` | Ubuntu suspicious exec paths suppressed |
| `TestCheck_BrlttyDeepscan` / `AppArmorAbstractionsDeepscan` | Ubuntu deepscan false positives |
| `TestCheck_DebianRcLocalSuspiciousExecPath` | `/etc/rc.local` exec path suppressed on Debian |
| `TestCheck_DebianAppArmorDeepscan` | AppArmor `/dev/shm` reference suppressed on Debian |
| `TestCheck_DebianDictionaryDeepscan` | Dictionary wordlist suppressed on Debian |
| `TestCheck_DebianBodyfileFHS` | `/etc/init.d/networking` FHS violation suppressed on Debian |
| `TestParseOSRelease` | Detects ubuntu, debian, Raspbian (`ID_LIKE=debian`), rhel, oracle, unknown, empty |
| `TestCheck_PathfinderSudoUserSuppressed` / `NotSuppressedForOtherProcess` | SUDO_USER in `pathfinder_v-` process suppressed; non-pathfinder process not suppressed |
| `TestCheck_PathfinderSudoUserSuppressed_PlainName` | SUDO_USER in plain `pathfinder` process name suppressed (exact match, not prefix) |
| `TestCheck_X11LockFile` | `/tmp/.X{0,1,1024,1025}-lock` suppressed (X11 display lock files) |
| `TestCheck_VMwareToolsDeepFHS` | `/etc/vmware-tools/scripts/vmware/network` suppressed via `/**` glob |
| `TestCheck_RHELKdumpGenerator` | `kdump-dep-generator.sh` suppressed on RHEL |
| `TestCheck_RHELPodmanGenerator` | `podman-system-generator` suppressed on RHEL |
| `TestCheck_RHELSELinuxGenerator` | `selinux-autorelabel-generator.sh` suppressed on RHEL |
| `TestCheck_RHELCockpitMOTD` | `/etc/motd.d/cockpit` MOTD script suppressed on RHEL |
| `TestCheck_RHELUnknownGeneratorNotSuppressed` | Unknown generator NOT suppressed on RHEL (allow-list semantics) |
| `TestCheck_MissingMntNamespace_Universal` | 13 systemd/GNOME daemons with private mount namespaces suppressed universally (kdevtmpfs, udevd, logind, timesyncd, NetworkManager, ModemManager, upowerd, colord, switcheroo-control, low-memory-monitor, userdbd, userwork, fwupd) |
| `TestCheck_MissingUtsNamespace_Universal` | 9 systemd/GNOME daemons with private UTS namespaces suppressed universally (polkitd, accounts-daemon, rtkit-daemon, irqbalance, power-profiles-daemon, timesyncd, udevd, logind, colord) |
| `TestCheck_LowMemoryMonitorNetNS` | `low-memory-monitor` NET namespace suppressed universally |
| `TestCheck_FirefoxSubprocessCWDProc` | Firefox sandbox IPC subprocesses with `CWD=/proc/<pid>/fdinfo` suppressed universally (8 subprocess comm names) |
| `TestCheck_RtkitDaemonCWDProc` | `rtkit-daemon` with `CWD=/proc` suppressed universally |
| `TestCheck_FirefoxCWDProc_NotSuppressedForMalwareDir` | Firefox subprocess NOT suppressed when CWD is outside `/proc/` (negative test) |
| `TestCheck_LttngUstWaitShmFile` | LTTng `/dev/shm/lttng-ust-wait-*` semaphore files suppressed universally |
| `TestCheck_FirefoxMozillaExecutableBit` | Firefox profile executables under `/home/*/.mozilla/firefox/**` suppressed universally |
| `TestCheck_LttngShmNotSuppressedOutsideDevShm` | LTTng semaphore NOT suppressed outside `/dev/shm/` (negative test) |
| `TestCheck_SystemdUdevdUdevadmMismatch` | `systemd-udevd` / `udevadm` binary mismatch suppressed universally (systemd >= v249) |
| `TestCheck_RHELMissingMntNamespace` | RHEL daemons with private mount namespaces suppressed on RHEL (dbus-broker, chronyd, firewalld, rsyslogd) |
| `TestCheck_RHELMissingUtsNamespace` | RHEL daemons with private UTS namespaces suppressed on RHEL (chronyd, firewalld) |
| `TestCheck_RHELLibpodLock` | `/dev/shm/libpod_lock` Podman lock file suppressed on RHEL |
| `TestCheck_RHELLibpodLockNotUniversal` | `/dev/shm/libpod_lock` NOT suppressed on unknown distro (RHEL-scoped rule) |
| `TestCheck_DebianAddUserPreinstDPKG` | `adduser.preinst` DPKG lifecycle false positive (pipe-to-shell on `\| sha512sum`) suppressed on Debian |
| `TestCheck_DebianAddUserPreinstNotUniversal` | `adduser.preinst` NOT suppressed on unknown distro (Debian-scoped rule) |

**`internal/modules/context_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestNewModuleContext_SetsSelfPath` | `ctx.SelfPath` is non-empty after `NewModuleContext`; verifies self-scan prevention is armed at startup |
| `TestNewModuleContext_SetsOutputPrefix` | `ctx.OutputPrefix` equals `filepath.Join(cfg.ReportDir, "pathfinder-")`; verifies all-run output prefix is set correctly |
| `TestNewSectionWriter_StreamsToZipWhenZipWriterSet` | Section writer streams to zip entry when `ZipWriter` is set; no disk file created |
| `TestNewSectionWriter_WritesToDiskWhenNoZipWriter` | Section writer writes to disk file when `ZipWriter` is nil |
| `TestNewSectionWriter_MultipleZipWritersAllHaveContent` | Multiple concurrent section writers all retain content when closed against a shared `zip.Writer` |
| `TestWalkFiles_SkipsUserSuppliedFiles` | `walkFiles` visits a normal file but skips the user-supplied IOC file path (`cfg.IOCFile`); verifies operator input files are excluded from scan walks to prevent false positives |

**`internal/modules/journal_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestJournalRaw_VolatileJournal` | Only `/run/log/journal` populated (Oracle Linux / RHEL layout) → journal file copied to `raw/` |
| `TestJournalRaw_PersistentJournal` | Only `/var/log/journal` populated (Ubuntu / Debian layout) → journal file copied to `raw/` |
| `TestIsVacuumMessage` | Journal vacuum message patterns: `Vacuuming done`, `Deleted archived journal`, `Freed … journal files` matched; unrelated journal lines rejected |
| `TestIsBinaryMismatch` | COMM vs EXE basename mismatch detection: exact match, 15-char truncation, known interpreter prefix, masquerade in staging dir |
| `TestExtractUnit` | `"unit foo.service"` extracted correctly; `"service "` marker rejected (was producing false crash-loop unit names); no-match and empty-string cases |
| `TestJournalTS` | Microsecond timestamp string parsed to seconds (`1000000000` → `1000`); invalid and empty strings return `0` |
| `TestFormatGapDuration` | Sub-hour, hour-only, and hours+minutes gap durations formatted correctly |
| `TestJournalAnalyzeAccounts` | Account creation fires MEDIUM; account deletion fires HIGH; unrelated message produces no hit |
| `TestJournalAnalyzeGroupChanges` | `docker` group addition fires HIGH; non-sensitive `users` group addition produces no hit |
| `TestJournalAnalyzeSSHBruteForce` | 25 combined failures (`Failed password` + `Failed publickey` + `Invalid user`) cross the 20-event MEDIUM threshold |
| `TestJournalAnalyzeContinuity` | Sub-test 1: journal start with no preceding reboot fires; sub-test 2: journal start 100s after reboot (entries in non-chronological buffer order) does not fire |
| `TestJournalAnalyzeCredentials_ShellSwap` | `nologin` → `bash` fires; `nologin` → `zsh` fires; `chsh` entry with `/bin/sh` fires; plain PAM session line does not fire |
| `TestJournalAnalyzeTimeGaps` | 3h gap below new 4h MED threshold: no hit; 6h gap between 4h and 8h: 1 hit; 9h gap above 8h HIGH threshold: 1 hit |
| `TestJournalAnalyzeVacuum` | `journald_vacuum` section entry with vacuum message fires MEDIUM; entry from a different section is ignored |
| `TestJournalAnalyzeBinaryMismatch_Dedup` | Two identical `comm|exe` pairs produce exactly one registry add; distinct second pair produces its own add (dedup check) |

**`internal/modules/bodyfile_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestAnalyzeBodyfile_VolatileCappedAt20` | 25 recent /tmp entries → all 25 `"Recent activity in volatile/hidden path"` registry entries stored (first 20 via `Add`, remaining 5 via `AddSilent`) |
| `TestAnalyzeBodyfile_OutputPrefix_Skipped` | Files under `ctx.OutputPrefix` are not flagged by `analyzeBodyfile`; verifies code-level self-exclusion in the analysis loop |
| `TestNewSectionWriterWithBuf_ZipModeSharesBuffer` | In zip mode, caller's `bytes.Buffer` is the backing store: buffer populated before `Close`, zip entry contains written content, no second buffer allocated |
| `TestAnalyzeBodyfile_VolatileExecLabel` | Exec file in `/tmp/` → registry label is `"Executable in volatile/hidden path"`, not the non-exec label |
| `TestBfTime` | ts=0 and ts=-1 → `"N/A"`; valid unix timestamp → expected UTC string |
| `TestBfIsHiddenPath` | Dot-prefix segment in path → true; clean paths → false (6 cases) |
| `TestBfIsKnownHiddenSafe` | `/etc/skel/`, `/etc/selinux/`, `/etc/.pwd.lock`, `/etc/.updated` → true; user home dotfiles → false (6 cases) |
| `TestAnalyzeBodyfile_TimestompFuture` | `/usr/bin/evil` with mtime=now+7200 → 1 HIGH `"Timestomped binary: future mtime"` finding; clean binary with past mtime → no finding |
| `TestAnalyzeBodyfile_SuidNonstandard` | SUID+exec file in `/tmp/` (outside SafeDirs), old timestamps → 1 HIGH `"SUID binary in non-standard path"` finding; old atime/mtime prevents VOLATILE-EXEC co-fire |
| `TestAnalyzeBodyfile_FhsViolation` | Exec regular file in `/etc/` → 1 HIGH `"FHS violation: executable in non-exec directory"` finding |
| `TestAnalyzeBodyfile_DeletedArtifact` | `/tmp/payload (deleted)`, non-exec, old timestamps → 1 HIGH `"Deleted artifact in sensitive path"` finding; old atime/mtime prevents VOLATILE-ACTIVITY co-fire |
| `TestAnalyzeBodyfile_BinReplace` | `/usr/bin/ssh` with mtime=now, btime=30d ago → 1 MEDIUM `"System binary replacement heuristic"` finding; btime=0 path → no finding; old mtime path → no finding |

**`internal/modules/volatile_process_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestIsOwnProcess_MatchesSelfPath` | `p.Exe == selfPath` → returns true; verifies exact-match self-exclusion |
| `TestIsOwnProcess_DifferentPath` | Different exe path → returns false; confirms non-self processes are not excluded |
| `TestIsOwnProcess_EmptySelfPath` | Empty `selfPath` → always returns false; verifies guard is disabled when `SelfPath` not set |
| `TestIsOwnProcess_EmptyExe` | Empty `p.Exe` → always returns false; verifies guard is disabled for kernel threads |
| `TestShouldSkipPID_OwnProcess` | `shouldSkipPID(os.Getpid())` → `true`; triage binary skips itself during memory map walks |
| `TestShouldSkipPID_ForeignPID` | `shouldSkipPID(1)` → `false`; PID 1 (init) is not excluded |

**`internal/modules/users_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestClassifyDeletedFDs` | Mixed /tmp and /lib FDs → 2 suspicious, 2 benign |
| `TestClassifyDeletedFDs_AllBenign` | /var/log FD → 0 suspicious, 1 benign |
| `TestClassifyDeletedFDs_AllSuspicious` | /var/tmp FD → 1 suspicious, 0 benign |

**`internal/modules/ioc_hash_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestHashFileFull_SHA256Only` | SHA-256 of a known file matches expected hex digest |
| `TestHashFileFull_TooLarge` | File exceeding `maxBytes` returns `errFileTooLarge` |

**`internal/modules/audit_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestGtfobinsSUIDAbused_Contains` | Known GTFOBins SUID-abusable binaries present in `gtfobinsSUIDAbused` map |
| `TestExpectedSUIDBinaries_Contains` | Known-safe SUID binaries (`passwd`, `sudo`, `ping`, etc.) present in `expectedSUIDBinaries` |
| `TestGtfobinsSUIDAbused_DoesNotContainExpected` | No overlap between the abused and expected-safe SUID sets |
| `TestExtractNOPASSWDPaths_*` | `extractNOPASSWDPaths`: multiple rules, no NOPASSWD, relative path skipped, commented line skipped, mixed comment and active lines |
| `TestParseGetcapLine_*` | `parseGetcapLine`: valid single/multiple caps, too-few fields, empty input, plus-delimited format (`cap_net_raw+ep`), mixed `=` and `+` delimiters in same line |
| `TestDangerousCapabilities_Contains` | `dangerousFileCaps` map: `cap_setuid`/`cap_sys_admin` → HIGH; `cap_dac_override`/`cap_net_raw` → MEDIUM |
| `TestIsAuthFailureLine_*` | Nine cases: dbus `Failed to activate service` rejected; `Failed password`, `Failed publickey`, `Invalid user`, `authentication failure`, `Too many authentication failures`, `maximum authentication attempts exceeded`, `Connection closed by invalid user` matched; bare `Invalid` rejected |
| `TestCapAllowlist_NoCrossCapability` | `capAllowlist`: `newuidmap` has `cap_setuid` and not `cap_setgid`; `newgidmap` has `cap_setgid` and not `cap_setuid` |
| `TestSSHBruteForceThresholds` | `sshBruteForceHighThreshold == 100`; `sshBruteForceMediumThreshold == 20` |

**`internal/modules/persistence_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestParseDesktopFile_ExtractsFields` | Exec, Type, Hidden, NoDisplay parsed correctly from `[Desktop Entry]` section |
| `TestParseDesktopFile_OnlyParsesDesktopEntrySection` | `[Desktop Action]` section ignored; only `[Desktop Entry]` fields extracted |
| `TestClassifyExec_MalwareDir` | `/tmp/evil-payload` → HIGH, reason contains "malware staging" |
| `TestClassifyExec_ShellInlinePayload` | `bash -c '...'` → HIGH, reason contains "inline payload" |
| `TestClassifyExec_PythonInlinePayload` | `python3 -c '...'` → HIGH |
| `TestClassifyExec_InlinePayloadNotSubstringMatch` | `bash -cool /path` (contains `"bash -c"` as substring) → not HIGH (false-positive guard) |
| `TestClassifyExec_HiddenComponent` | `/home/user/.secretdir/evil` → HIGH, reason contains "hidden directory" |
| `TestClassifyExec_KnownXDGNotFlagged` | `.config` and `.local` known-safe components → INFO not HIGH |
| `TestClassifyExec_NonExistentBinary` | Guaranteed-absent absolute path + `fromUserDir=true` → MEDIUM |
| `TestClassifyExec_NonExistentBinary_SystemDirIgnored` | Same path + `fromUserDir=false` → not MEDIUM |
| `TestClassifyExec_CleanUserDir` | `/usr/bin/env` + `fromUserDir=true` → INFO |
| `TestClassifyExec_CleanSystemDir` | `/usr/bin/env` + `fromUserDir=false` → `""` (no hit) |
| `TestExecBinary_HandlesEnvPrefix` | `env VAR=val /bin/app` → `/bin/app`; `bash -c 'evil'` → `bash` |
| `TestHasHiddenComponent` | `.secretdir` → true; `.config`, `.local`, `/usr/bin/ls` → false |
| `TestIsWebShellExtension_SH` | `.sh` extension returns true from `isWebShellExtension` |
| `TestScanWebRootForShells_SkipsDpkgOwnedFile` | dpkg-owned file with malicious PHP content skipped when path is in `ownedFiles` map |
| `TestScanWebRootForShells_NilOwnedFiles_StillDetects` | nil `ownedFiles` does not suppress detection; malicious PHP returns one HIGH hit |
| `TestClassifyLDPreloadEntries_MalwareDirEntry` | `/tmp/evil.so` entry → HIGH `"Malicious LD_PRELOAD entry"`, path in message |
| `TestClassifyLDPreloadEntries_MissingFile` | Non-existent library path → MEDIUM `"Missing LD_PRELOAD library"` |
| `TestClassifyLDPreloadEntries_ExistingCleanFile` | Existing non-staging system binary (`/bin/sh` etc.) → zero results; probes candidate paths instead of `os.Executable()` which resolves to `/tmp/` on Linux and would be flagged by `ioc.IsInMalwareDir` |
| `TestClassifyLDPreloadEntries_IgnoresCommentsAndBlanks` | Comment lines and blank entries skipped; only `/tmp/evil.so` produces a result |
| `TestExtractCronCommand_AtSyntax` | `@reboot /tmp/evil` with `hasUser=true` → `/tmp/evil` (not `""`) |
| `TestExtractCronCommand_AtSyntaxWithUsernameField` | `@reboot root /tmp/evil` with `hasUser=true` → `/tmp/evil` (username token skipped) |
| `TestExtractCronCommand_AtSyntaxNoUsernameField` | `@reboot /tmp/evil` with `hasUser=false` → `/tmp/evil` |
| `TestExtractCronCommand_AtSyntaxSingleToken_UserDir` | `@reboot` alone with `hasUser=true` → `""` (no command to extract) |
| `TestScanCronScriptDir_DetectsMalicious` | File containing `curl \| bash` → 1 HIGH hit with label `"Malicious cron script"` |
| `TestScanCronScriptDir_Clean` | Clean logrotate script pre-dated 73h → 0 hits; guards `recentlyModified` false positive via `os.Chtimes` |
| `TestScanCronScriptDir_MissingDir` | Non-existent directory → nil (not a panic or empty slice) |
| `TestExtractAnacronCommand_Basic` | `7 25 cron.weekly run-parts /etc/cron.weekly` → `"run-parts /etc/cron.weekly"` |
| `TestExtractAnacronCommand_TooFewFields` | Fewer than 4 fields → `""` |
| `TestExtractAnacronCommand_Comment` | `# comment` line → `""` |
| `TestExtractAnacronCommand_MaliciousCommand` | Anacrontab line with bash TCP reverse shell → extracted command classifies as HIGH |
| `TestClassifyLDSoConfEntries_StagingPath_High` | `/tmp/evil-lib` → HIGH `"Malicious ld.so.conf entry"`, path present in msg |
| `TestClassifyLDSoConfEntries_SystemPath_Clean` | `/usr/lib/x86_64-linux-gnu` → 0 results |
| `TestClassifyLDSoConfEntries_IncludeDirective_Skipped` | `include /etc/ld.so.conf.d/*.conf` → 0 results (directive skipped) |
| `TestClassifyLDSoConfEntries_CommentsAndBlanks_Skipped` | Comments and blank lines skipped; only `/tmp/evil` produces a result |
| `TestPersistenceAtQueue_MaliciousContentFiresRegistry` | at spool file with bash TCP reverse shell → `"Malicious at/batch job"` registry entry |
| `TestPersistenceAtQueue_CleanJobNoMaliciousEntry` | at spool file with benign `find` command → no malicious registry entry |
| `TestParseGitConfigValues_HooksPath` | gitconfig with `hooksPath = /tmp/evil-hooks` and `pager = less` → both values extracted positionally |
| `TestClassifyGitHooksPath_StagingPath_High` | `/tmp/evil-hooks` → HIGH, reason contains `"staging"` |
| `TestClassifyGitHooksPath_CustomPath_Medium` | `/home/user/.config/git/hooks` → MEDIUM |
| `TestClassifyGitHooksPath_SystemPath_Clean` | `/usr/share/git-core/templates/hooks` → `""` (safe dir, no finding) |
| `TestClassifyGitHooksPath_Empty_Clean` | `""` → `""` (no finding) |
| `TestPersistenceSSHAuthorizedKeys_ReportsKeys` | home with `authorized_keys` containing one key → at least one registry entry |
| `TestPersistenceSSHAuthorizedKeys_EmptyFile_NoEntry` | comment-only `authorized_keys` → no registry entries |
| `TestPersistenceSSHAuthorizedKeys_NoFile_NoEntry` | home with no `.ssh` directory → no registry entries |
| `TestPersistenceSSHAuthorizedKeys_MultipleHomes` | three homes each with one key → at least 3 registry entries |
| `TestScanDirForSharedObjects_FindsSOInSubdir` | `.so` file in a hidden subdirectory of a staging dir → found by depth-1 scan |
| `TestScanDirForSharedObjects_DoesNotDescendTwoLevels` | `.so` file two levels deep → not found (depth cap enforced) |
| `TestScanWebRootForShells_TimedOut_ReturnsTimedOutTrue` | expired deadline (past `time.Now()`) fires `SkipAll` on first entry; `timedOut == true` and `len(hits) == 0` |
| `TestPersistenceSudoers_NOPASSWDAll_HighFinding` | sudoers file with `NOPASSWD: ALL` line → HIGH `"Sudoers NOPASSWD:ALL grant"` registry entry |
| `TestPersistenceSudoers_NOPASSWDPartial_MediumFinding` | sudoers file with plain `NOPASSWD:` line (no ALL) → MEDIUM `"Sudoers NOPASSWD grant"` registry entry |
| `TestPersistenceSudoers_RecentDropin_MediumFinding` | drop-in file in temp sudoers.d with fresh mtime → MEDIUM `"Recently modified sudoers drop-in"` registry entry |
| `TestPersistenceSudoers_Clean_NoFindings` | sudoers file with no NOPASSWD lines → zero registry entries |

**`internal/modules/volatile_memmap_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestClassifyMapLine_ExecDeleted` | `r-xp` + `(deleted)` suffix → `anomalyExecDeleted`; path preserved |
| `TestClassifyMapLine_Memfd` | `r-xp` + `memfd:secret` → `anomalyExecMemfd` |
| `TestClassifyMapLine_StagingPath` | `r-xp` + `/dev/shm/payload.so` → `anomalyExecStagingPath` |
| `TestClassifyMapLine_RWXFileBacked` | `rwxp` + `/usr/local/lib/evil.so` → `anomalyRWXFileBacked` |
| `TestClassifyMapLine_UserHome` | `r-xp` + `/home/alice/.local/lib/mod.so` → `anomalyExecUserHome` |
| `TestClassifyMapLine_RootHome` | `r-xp` + `/root/.local/lib/mod.so` → `anomalyExecUserHome` |
| `TestClassifyMapLine_LegitLib` | `r-xp` + `/usr/lib/x86_64-linux-gnu/libc.so.6` → `ok=false` |
| `TestClassifyMapLine_NoExecNonRWX` | `r--p` + any path → `ok=false` |
| `TestClassifyMapLine_RWXPrioritisedOverUserHome` | `rwxp` + `/home/alice/lib/evil.so` → `anomalyRWXFileBacked` (priority guard) |
| `TestClassifyMapLine_DeletedFileStillExists_Suppressed` | `(deleted)` mapping where file still on disk → `ok=false` (package update pattern) |
| `TestClassifyMapLine_DeletedFileGenuinelyMissing_Reported` | `(deleted)` mapping where file absent → `anomalyExecDeleted` |
| `TestMapAnomalySeverity_RWXFileBacked_IsMedium` | `anomalyRWXFileBacked` → `output.MEDIUM` |
| `TestMapAnomalySeverity_ExecMemfd_IsHigh` | `anomalyExecMemfd` → `output.HIGH` |
| `TestMapAnomalySeverity_ExecDeleted_IsHigh` | `anomalyExecDeleted` → `output.HIGH` |
| `TestMapAnomalyKindString` | All five kind constants produce expected `String()` values |
| `TestDescribeMapKinds_Empty` | nil hit slice → `""` |
| `TestDescribeMapKinds_SingleKind` | `[{anomalyExecMemfd}]` → `"execMemfd"` |
| `TestDescribeMapKinds_MultipleKinds` | `[{anomalyExecDeleted}, {anomalyExecMemfd}]` → `"execDeleted + execMemfd"` |
| `TestDescribeMapKinds_Deduplication` | two identical `anomalyRWXFileBacked` hits → `"rwxpFileBacked"` (dedup) |
| `TestDescribeMapKinds_CanonicalOrder` | input `[execUserHome, execDeleted]` → `"execDeleted + execUserHome"` (canonical order ignores input order) |
| `TestDescribeMapKinds_IncludesStagingPath` | `[{anomalyExecStagingPath}]` → `"execStagingPath"` |
| `TestHighestMapSeverity_EmptySlice` | nil slice → `output.MEDIUM` (fallback) |
| `TestHighestMapSeverity_AllMedium` | `[anomalyRWXFileBacked, anomalyExecUserHome]` → `output.MEDIUM` |
| `TestHighestMapSeverity_HasHighKind` | `[anomalyRWXFileBacked, anomalyExecMemfd]` → `output.HIGH` |
| `TestHighestMapSeverity_AllHigh` | `[anomalyExecDeleted, anomalyExecMemfd]` → `output.HIGH` |
| `TestHighestMapSeverity_StagingPathIsHigh` | `[anomalyExecStagingPath]` → `output.HIGH` (default branch) |

**`internal/modules/volatile_environ_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestEnvRuleApplies_StagingPathFires` | `LD_PRELOAD` with `/tmp/evil.so` triggers HIGH env rule |
| `TestEnvRuleApplies_SuppressionComm_Suppresses` | `faketime` / `valgrind` in `SuppressionComms` suppresses the rule even for a staging path |

**`internal/modules/volatile_kmsg_linux_test.go`**

| Test                                  | Description                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------- |
| `TestReadKmsgLinesDoesNotHang`        | `readKmsgLines` returns within 5 s; guards against Go poller blocking on `EAGAIN` for `/dev/kmsg` |

**`internal/modules/volatile_ebpf_test.go`**

| Test                                           | Description                                                             |
| ---------------------------------------------- | ----------------------------------------------------------------------- |
| `TestScanKmsgLines_WriteUser`                  | `bpf_probe_write_user` → HIGH, label "BPF write-to-userspace helper"   |
| `TestScanKmsgLines_OverrideReturn`             | `bpf_override_return` → HIGH, label "BPF override-return helper"       |
| `TestScanKmsgLines_VerifierFailure`            | `BPF: invalid` → INFO, label "BPF verifier failure"                    |
| `TestScanKmsgLines_NoMatch`                    | Benign kernel messages produce no hits                                  |
| `TestScanKmsgLines_NoSemicolon`                | Malformed record (no `;`); full line treated as message                |
| `TestScanKmsgLines_WriteUserTakesPriorityOverVerifier` | write-user wins when line also matches verifier pattern         |

**`internal/modules/volatile_container_test.go`**

| Test                                              | Description                                                                  |
| ------------------------------------------------- | ---------------------------------------------------------------------------- |
| `TestFindUntaggedRepos_OnlyDigest`                | Digest-only repo detected as untagged                                        |
| `TestFindUntaggedRepos_HasNamedTag`               | Repo with named tag not flagged                                              |
| `TestFindUntaggedRepos_Mixed`                     | Only the digest-only repo returned from mixed set                            |
| `TestFindUntaggedRepos_Empty`                     | Empty repository map returns no results                                      |
| `TestFindUntaggedRepos_EmptyRefs`                 | Repo with zero refs not flagged                                              |
| `TestParseDangerousCapabilities_SysAdmin`         | `0x200000` (bit 21) → CAP_SYS_ADMIN in highCaps                             |
| `TestParseDangerousCapabilities_NetRaw`           | `0x2000` (bit 13) → CAP_NET_RAW in medCaps                                  |
| `TestParseDangerousCapabilities_None`             | Zero bitmask → empty slices                                                  |
| `TestParseDangerousCapabilities_InvalidHex`       | Non-hex input returns error                                                  |
| `TestParseDangerousCapabilities_SysAdminAndNetRaw`| Combined bitmask splits correctly across highCaps and medCaps                |
| `TestOCIStateFlags_SysAdmin`                      | CAP_SYS_ADMIN in effective caps → highCaps                                   |
| `TestOCIStateFlags_SysModule`                     | CAP_SYS_MODULE in effective caps → highCaps                                  |
| `TestOCIStateFlags_HostNamespacePath`             | Non-empty namespace Path → hostNSPaths in `type=path` format                 |
| `TestOCIStateFlags_EmptyNamespacePath`            | Empty namespace Path → not flagged                                           |
| `TestOCIStateFlags_Clean`                         | No dangerous caps, no host paths → both slices empty                         |

**`internal/modules/sse_package_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestWriteArtifactBlock_NoSkipsNoErrors` | Log block for clean artifact: `Collected`, `Skipped : 0`, `Errors : 0` present |
| `TestWriteArtifactBlock_SkipsGroupedByReason` | Skip counts grouped by reason, sorted by count descending |
| `TestWriteArtifactBlock_ErrorsListedPerFile` | Error entries include per-file path and reason |
| `TestRunSSEPackage_NoManifest` | No manifest → no panic, `SSEZipPath` stays empty |
| `TestRunSSEPackage_CollectsSingleFile` | Single-file artifact lands under `[root_dir]/` in SSE zip; no staging dir on disk |
| `TestRunSSEPackage_OutputDirectory` | `output_directory` places file under `[root_dir]/files/logs/` |
| `TestRunSSEPackage_OutputFile` | `output_file` renames the destination filename inside the zip |
| `TestRunSSEPackage_CollectsDirectory` | Directory artifact: all files collected under `output_directory` |

**`internal/modules/deepscan_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestScanContent_WebshellFound` | `base64_decode` in PHP content → `webshells`/SH003 hit returned |
| `TestScanContent_ExfilReconFound` | pastebin URL in script → `stagers_c2` hit returned |
| `TestScanContent_CleanFile` | Standard config file with `PATH=` → zero hits |
| `TestScanContent_LineNumbers` | Hit on line 3 of 4-line input → `lineNum == 3` |
| `TestScanContent_MultipleHitsInLineOrder` | Two hits on different lines → hits returned in ascending line-number order |

**`internal/procfs/procfs_test.go`**

| Test | Description |
| ---- | ----------- |
| `TestParseModuleLine_WithTaint` | Module line with `(OE)` taint parses name and taint correctly |
| `TestParseModuleLine_NoTaint` | Module line without taint parses with empty taint field |
| `TestReadKernelVersion_ReturnsNonEmpty` | `/proc/version` readable → non-empty string returned (skipped if unreadable) |
| `TestParseUtmpFile_Timestamp` | Synthetic 384-byte utmp record with known `tv_sec` at offset 340 → `records[0].Time()` equals expected `time.Unix` value; guards against off-by-8 read into `ut_addr_v6` (the root cause of the `1970-01-01T00:00:00Z` regression) |
