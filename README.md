# Pathfinder

> Drop in. Hunt down. Collect artifacts. Get out.

A single static binary for Linux live triage. No dependencies, no install — drop it on a host and run.

## What it does

Pathfinder isn't just a collector. It runs detection inline, so you walk away with answers, not just artifacts. As each module completes, it analyzes the host and prints a verdict right in the terminal, so by the time it finishes you have a prioritized, analyst-facing scorecard that tells you exactly what to chase down first, in the same terminal session.

What it detects, inline:

- **Processes and memory:** hidden processes (getdents64/lstat hook detection), injected shellcode (anonymous executable and RWX memory, `memfd:` exec), deleted-but-running binaries, process masquerading, hidden or unsigned kernel modules and rootkit traces, malicious eBPF helpers, and cryptominer CPU/memory heuristics
- **Persistence:** cron jobs, systemd units and `.path` triggers, rc and init scripts, PAM modules, shell startup and profile files, SUID/SGID binaries, udev rules, and XDG autostart entries
- **Users and credentials:** plaintext credentials, suspicious shell history, SSH `authorized_keys` backdoors and tunnels, UID-0 backdoor accounts, and `/etc/shells` tampering
- **System config and auth:** sudoers and shadow audit, kernel taint and `cmdline` tampering (LSM disable, init override), immutable files, and SSH auth success/failure logs
- **Network:** services listening on non-standard ports, promiscuous interfaces and packet sniffers, firewall rules, and DNS/hosts redirects
- **Timeline and journal:** systemd journal analysis plus a mactime filesystem timeline (bodyfile) that flags timestomped files with impossible future timestamps
- **Threat intel:** built-in IOC signatures (bash-history, string-hunt, process env-var rules) plus your own indicators via `-ioc`, and a deepscan engine that extracts external IPs and domains and scans configs, scripts, and web roots

It still collects and packages the evidence: a timestamped ZIP with MD5 and SHA-256 plus an acquisition manifest, alongside machine-readable JSON. Known-clean distro noise (Ubuntu, Debian, RHEL) is suppressed so the real anomalies stand out.

## Demo

![Pathfinder session](References/my-session.svg)

## Download

Grab the latest stable binary from the [Releases](https://github.com/dfir-ronin/pathfinder-dfir/releases) page:

```bash
curl -LO https://github.com/dfir-ronin/pathfinder-dfir/releases/latest/download/pathfinder-linux-amd64
chmod +x pathfinder-linux-amd64
```

The current build is a beta. Until a stable release is cut, grab it from the [v1.0.0-beta release](https://github.com/dfir-ronin/pathfinder-dfir/releases/tag/v1.0.0-beta):

```bash
curl -LO https://github.com/dfir-ronin/pathfinder-dfir/releases/download/v1.0.0-beta/pathfinder-linux-amd64
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

Parts of Pathfinder were built with assistance from [Claude Code](https://claude.com/claude-code), Anthropic's agentic coding tool, used for code review, refactoring, and documentation.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
