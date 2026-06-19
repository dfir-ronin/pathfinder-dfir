# Pathfinder

> Drop in. Hunt down. Collect artifacts. Get out.

A single static binary for Linux live triage. No dependencies, no install — drop it on a host and run.

  [![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)
  [![Go Report
  Card](https://goreportcard.com/badge/github.com/dfir-ronin/pathfinder-dfir)](https://goreportcard.com/report/github.com/dfir-ronin/pathfinder-dfir)
  [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)



## What it does

On a compromised Linux host, the binaries and the kernel can lie. A rootkit hides its own processes, filters out its modules, and patches the syscalls underneath you. Pathfinder reads the kernel directly and verifies what the host claims, so the lies surface instead of staying hidden. It isn't just a collector. It runs detection inline, so you walk away with answers, not just artifacts. As each module completes, it analyzes the host and prints a verdict right in the terminal, so by the time it finishes you have a prioritized, analyst-facing scorecard that tells you exactly what to chase down first, in the same terminal session.

What it detects, inline:

- Processes and memory: hidden processes (getdents64/lstat hook detection), injected shellcode (anonymous executable and RWX memory, `memfd:` exec), LD_PRELOAD injection, deleted-but-running binaries, process masquerading, hidden or unsigned kernel modules and rootkit traces, malicious eBPF helpers, cryptominer CPU/memory heuristics, and namespace and container escapes (including `nsenter` against host PID 1)
- Persistence: cron and anacron jobs, at/batch queue, systemd services, timers, `.path` units, generators and user-level units, legacy init, udev rules, XDG autostart entries, MotD and `profile.d` scripts, shell startup and profile dotfiles, package manager hooks, git hooks, `/etc/ld.so.preload` backdoors, malicious shared objects staged in world-writable directories, insmod/modprobe in boot scripts, tainted or recently added kernel modules, PAM modules, web shells in server roots, SSH authorized_keys backdoors, and sudoers NOPASSWD grants
- Users and credentials: plaintext credentials, suspicious shell history, UID-0 backdoor accounts, and `/etc/shells` tampering
- System config and auth: shadow audit, kernel cmdline tampering (LSM disable, init override), immutable files, and SSH auth success/failure logs
- Network: services listening on non-standard ports, promiscuous interfaces and packet sniffers, firewall rules, and DNS/hosts redirects
- Timeline and journal: systemd journal analysis plus a mactime filesystem timeline (bodyfile) that flags timestomped files with impossible future timestamps
- Threat intel: built-in IOC signatures (bash-history, string-hunt, process env-var rules) plus your own indicators via `-ioc`, and a deepscan engine that extracts external IPs and domains and scans configs, scripts, and web roots

It still collects and packages the evidence: a timestamped ZIP with MD5 and SHA-256 plus an acquisition manifest, alongside machine-readable JSON. Reads run with O_NOATIME to preserve original access timestamps, and Pathfinder stays read-only everywhere except its own output directory, so the evidence it touches stays intact. Known-clean distro noise (Ubuntu, Debian, RHEL) is suppressed so the real anomalies stand out. For the full breakdown of every check and detection, see [DOCUMENTATION.md](DOCUMENTATION.md).

## Demo

![Pathfinder session](References/my-session.svg)

## Download

Grab the latest binary from the [Releases](https://github.com/dfir-ronin/pathfinder/releases) page:

```bash
curl -LO https://github.com/dfir-ronin/pathfinder/releases/latest/download/pathfinder-linux-amd64
chmod +x pathfinder-linux-amd64
```

## Usage

```bash
# Full scan — root recommended
sudo ./pathfinder-linux-amd64

# Quick mode — 10s timeouts, skips deep filesystem walks
sudo ./pathfinder-linux-amd64 -mode quick

# Run specific modules only
sudo ./pathfinder-linux-amd64 -volatile -users

# Stealth mode for pipeline integration
sudo ./pathfinder-linux-amd64 -stealth
```

## Note

Pathfinder is a triage companion, not a replacement for full forensic analysis. It's built to surface obvious indicators fast — the deep-dive is still on you.

## Acknowledgments

Parts of Pathfinder were built with assistance from [Claude Code](https://claude.com/claude-code), used for code review, refactoring, and documentation.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
