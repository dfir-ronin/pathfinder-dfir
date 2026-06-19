package modules

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/pathfinder/internal/netfs"
	"github.com/pathfinder/internal/osutil"
	"github.com/pathfinder/internal/output"
	"github.com/pathfinder/internal/procfs"
)

type taintBit struct {
	bit  uint64
	sev  output.Severity
	desc string
}

var kernelTaintBits = []taintBit{
	{1 << 0, output.LOW, "Proprietary module loaded"},
	{1 << 1, output.HIGH, "Module forcibly loaded - integrity bypass"},
	{1 << 2, output.LOW, "CPU out of spec"},
	{1 << 3, output.LOW, "Module from initrd force-unloaded"},
	{1 << 4, output.MEDIUM, "Machine check error"},
	{1 << 5, output.LOW, "Bad memory page"},
	{1 << 6, output.LOW, "User-requested unsafe permission"},
	{1 << 7, output.LOW, "Kernel died (OOM / panic)"},
	{1 << 8, output.LOW, "ACPI table overridden"},
	{1 << 9, output.LOW, "Kernel warning"},
	{1 << 10, output.LOW, "Staging driver loaded"},
	{1 << 11, output.LOW, "Firmware bug workaround applied"},
	{1 << 12, output.MEDIUM, "Out-of-tree (OOT) module loaded"},
	{1 << 13, output.HIGH, "Unsigned module loaded - rootkit indicator"},
	{1 << 14, output.LOW, "Soft lockup occurred"},
	{1 << 15, output.MEDIUM, "Kernel live-patched"},
	{1 << 16, output.LOW, "AUX taint (distro-specific)"},
	{1 << 17, output.LOW, "Struct randomization (RANDSTRUCT)"},
}

// matchTaintBits returns the matched known bits, the highest severity among them,
// and any bits not covered by the table.
func matchTaintBits(val uint64) (matched []taintBit, highestSev output.Severity, unknownBits uint64) {
	highestSev = output.LOW
	var knownMask uint64
	for _, tb := range kernelTaintBits {
		knownMask |= tb.bit
		if val&tb.bit == 0 {
			continue
		}
		matched = append(matched, tb)
		switch tb.sev {
		case output.HIGH:
			highestSev = output.HIGH
		case output.MEDIUM:
			if highestSev == output.LOW {
				highestSev = output.MEDIUM
			}
		}
	}
	unknownBits = val &^ knownMask
	if unknownBits != 0 && highestSev == output.LOW {
		highestSev = output.MEDIUM
	}
	return
}

// parseModuleTaintLetters extracts uppercase letter flags from a /proc/modules
// taint field like "(OE)" and returns them as a set.
func parseModuleTaintLetters(taint string) map[rune]bool {
	letters := make(map[rune]bool)
	for _, r := range taint {
		if r >= 'A' && r <= 'Z' {
			letters[r] = true
		}
	}
	return letters
}

type hostsIPClass int

const (
	hostsClassSkip   hostsIPClass = iota // loopback, null-route, multicast
	hostsClassLow                        // RFC1918 -- LOW finding
	hostsClassMedium                     // public routable -- MEDIUM finding
)

var rfc1918 []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			rfc1918 = append(rfc1918, n)
		}
	}
}

// classifyHostsEntryIP returns the finding class for an IP string from /etc/hosts.
func classifyHostsEntryIP(ipStr string) hostsIPClass {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return hostsClassSkip
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return hostsClassSkip
	}
	for _, network := range rfc1918 {
		if network.Contains(ip) {
			return hostsClassLow
		}
	}
	return hostsClassMedium
}

// isNonStandardModulePath returns true when path is non-empty and outside /lib/modules/.
func isNonStandardModulePath(path string) bool {
	return path != "" && !strings.HasPrefix(path, "/lib/modules/")
}

type cmdlineFinding struct {
	sev   output.Severity
	label string
	msg   string
}

var standardInitPaths = map[string]bool{
	"/lib/systemd/systemd":     true,
	"/usr/lib/systemd/systemd": true,
	"/sbin/init":               true,
	"/bin/init":                true,
	"/usr/sbin/init":           true,
}

// analyzeCmdline returns security findings for a parsed kernel cmdline parameter list.
func analyzeCmdline(params []string) []cmdlineFinding {
	var findings []cmdlineFinding
	for _, p := range params {
		switch p {
		case "rd.break", "systemd.break", "single", "emergency", "rescue":
			findings = append(findings, cmdlineFinding{
				output.MEDIUM,
				"Kernel booted into recovery/debug mode",
				fmt.Sprintf("Recovery/debug parameter in kernel cmdline: %s", p),
			})
		case "security=none":
			findings = append(findings, cmdlineFinding{
				output.HIGH,
				"LSM disabled via kernel cmdline",
				"security=none disables all Linux Security Modules",
			})
		case "nokaslr", "nosmap", "nosmep", "mitigations=off", "pti=off":
			findings = append(findings, cmdlineFinding{
				output.MEDIUM,
				"Kernel hardening disabled via cmdline",
				fmt.Sprintf("Kernel hardening parameter disabled: %s", p),
			})
		}
		for _, prefix := range []string{"init=", "rdinit="} {
			if strings.HasPrefix(p, prefix) {
				val := strings.TrimPrefix(p, prefix)
				if !standardInitPaths[val] {
					findings = append(findings, cmdlineFinding{
						output.HIGH,
						"Non-standard init override in kernel cmdline",
						fmt.Sprintf("Non-standard %s in kernel cmdline: %s", strings.TrimSuffix(prefix, "="), p),
					})
				}
			}
		}
	}
	return findings
}

// collectDpkgInstalls scans lines in reverse and returns up to n install entries.
func collectDpkgInstalls(lines []string, n int) []string {
	var out []string
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if strings.Contains(lines[i], " install ") {
			out = append(out, lines[i])
		}
	}
	return out
}

// RunBaseline executes the chrome (system baseline) sections
func RunBaseline(ctx *ModuleContext) {
	output.Chapter("[BASELINE] Auditing system baseline and network config...")
	output.Info("Output → " + ctx.Dirs.Baseline)
	baselineSystemInfo(ctx)
	baselineNetworkInterfaces(ctx)
	baselineRoutingARP(ctx)
	baselineDNSHosts(ctx)
	baselineKernelModules(ctx)
	baselineInstalledPackages(ctx)
	baselineKernelTaint(ctx)
	baselineCmdline(ctx)

	ctx.Log.Log("baseline", "complete", "all sections done")
}

func baselineSystemInfo(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "01_system_info.txt",
		"System Information", "/proc/version, /etc/os-release, /proc/uptime")
	defer w.Close()

	for _, f := range []string{"/proc/version", "/etc/os-release", "/etc/hostname"} {
		if data, err := os.ReadFile(f); err == nil {
			w.WriteSectionHeader(f)
			w.WriteString(string(data))
		}
	}

	if up, err := os.ReadFile("/proc/uptime"); err == nil {
		w.WriteSectionHeader("/proc/uptime")
		w.WriteString(string(up))
	}

	output.Ok("System info collected")
}

func baselineNetworkInterfaces(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "02_network_interfaces.txt",
		"Network Interfaces", "/sys/class/net/")
	defer w.Close()

	ifaces, err := netfs.ReadInterfaces()
	if err != nil {
		w.Write("ERROR: %v\n", err)
		return
	}

	hits := 0
	for _, iface := range ifaces {
		promisc := ""
		if iface.Promiscuous {
			promisc = " [PROMISC]"
		}
		w.Write("%-20s flags=%-10s%s\n", iface.Name, iface.Flags, promisc)
		for _, addr := range iface.Addresses {
			w.Write("  addr: %s\n", addr)
		}
		if iface.Promiscuous {
			hits++
			ctx.Registry.Add(output.HIGH, "baseline", "Network interface in promiscuous mode",
				fmt.Sprintf("Interface %s is in PROMISC mode - active packet sniffer likely", iface.Name))
		}
	}

	if hits > 0 {
		output.Warn(fmt.Sprintf("Network interfaces: %d finding(s)", hits))
	} else {
		output.Ok(fmt.Sprintf("Interfaces enumerated: %d", len(ifaces)))
	}
}

func baselineRoutingARP(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "03_routing_arp.txt",
		"Routing Table & ARP Cache", "/proc/net/route, /proc/net/arp")
	defer w.Close()

	routes, err := netfs.ReadRoutes()
	if err != nil {
		w.Write("Routing: ERROR: %v\n", err)
	} else {
		w.WriteSectionHeader("Routing Table (/proc/net/route)")
		w.Write("%-12s %-16s %-16s %-16s %s\n", "IFACE", "DEST", "GATEWAY", "MASK", "FLAGS")
		w.Write("%s\n", strings.Repeat("─", 70))
		for _, r := range routes {
			w.Write("%-12s %-16s %-16s %-16s %s\n",
				r.Iface, r.Dest, r.Gateway, r.Mask, r.Flags)
		}
	}

	arp, err := netfs.ReadARP()
	if err != nil {
		w.Write("ARP: ERROR: %v\n", err)
	} else {
		w.WriteSectionHeader("ARP Cache (/proc/net/arp)")
		w.Write("%-18s %-8s %-6s %-20s %s\n", "IP", "HWTYPE", "FLAGS", "MAC", "DEVICE")
		w.Write("%s\n", strings.Repeat("─", 65))
		for _, a := range arp {
			w.Write("%-18s %-8s %-6s %-20s %s\n",
				a.IP, a.HWType, a.Flags, a.MAC, a.Device)
		}
	}

	output.Ok("Routing and ARP collected")
}

func baselineDNSHosts(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "04_dns_hosts.txt",
		"DNS & Hosts", "/etc/resolv.conf, /etc/hosts")
	defer w.Close()

	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		w.WriteSectionHeader("/etc/resolv.conf")
		w.WriteString(string(data))
	}

	hits := 0
	if hostsData, err := os.ReadFile("/etc/hosts"); err == nil {
		w.WriteSectionHeader("/etc/hosts")
		w.WriteString(string(hostsData))

		for _, line := range strings.Split(string(hostsData), "\n") {
			line = strings.TrimSpace(line)
			if osutil.IsCommentOrBlank(line) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch classifyHostsEntryIP(fields[0]) {
			case hostsClassLow:
				hits++
				ctx.Registry.Add(output.LOW, "baseline", "Non-loopback /etc/hosts entry",
					fmt.Sprintf("Internal /etc/hosts redirect: %s - verify legitimacy", line))
			case hostsClassMedium:
				hits++
				ctx.Registry.Add(output.MEDIUM, "baseline", "Non-loopback /etc/hosts entry",
					fmt.Sprintf("Public-IP /etc/hosts redirect: %s - potential DNS hijack", line))
			}
		}
	}

	if hits > 0 {
		output.Warn(fmt.Sprintf("DNS/hosts: %d finding(s)", hits))
	} else {
		output.Ok("DNS and hosts collected")
	}
}

func baselineKernelModules(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "05_kernel_modules.txt",
		"Loaded Kernel Modules", "/proc/modules")
	defer w.Close()

	mods, err := procfs.ReadModules()
	if err != nil {
		w.Write("ERROR reading /proc/modules: %v\n", err)
		return
	}

	w.Write("%-30s %10s %5s\n", "MODULE", "SIZE", "USED")
	w.Write("%s\n", strings.Repeat("─", 50))
	for _, m := range mods {
		w.Write("%-30s %10d %5d\n", m.Name, m.Size, m.Used)
	}

	w.WriteSectionHeader("Loadable module paths (/sys/module/<name>/filename)")
	for _, m := range mods {
		data, err := os.ReadFile(fmt.Sprintf("/sys/module/%s/filename", m.Name))
		if err != nil {
			continue // built-in or inaccessible
		}
		koPath := strings.TrimSpace(string(data))
		w.Write("  %s -> %s\n", m.Name, koPath)
		if isNonStandardModulePath(koPath) {
			ctx.Registry.Add(output.HIGH, "baseline", "Kernel module loaded from non-standard path",
				fmt.Sprintf("Kernel module loaded from non-standard path: %s -> %s", m.Name, koPath))
		}
	}

	// Unsigned / out-of-tree kernel modules are reported solely by the persistence
	// module (classifyKernelModuleTaint), which owns the severity and the suppression
	// keys. Reporting them here too produced duplicate findings for the same module.

	output.Ok(fmt.Sprintf("Kernel modules enumerated: %d", len(mods)))
	ctx.Log.Log("baseline", "kernel_modules", fmt.Sprintf("count=%d", len(mods)))
}

func baselineInstalledPackages(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "06_installed_packages.txt",
		"Recently Installed Packages", "dpkg.log / rpm (exec fallback)")
	defer w.Close()

	if data, err := os.ReadFile("/var/log/dpkg.log"); err == nil {
		w.WriteSectionHeader("/var/log/dpkg.log (last 30 installs)")
		installs := collectDpkgInstalls(strings.Split(string(data), "\n"), 30)
		for _, l := range installs {
			w.Write("%s\n", l)
		}
		if len(installs) < 30 {
			if data1, err := os.ReadFile("/var/log/dpkg.log.1"); err == nil {
				more := collectDpkgInstalls(strings.Split(string(data1), "\n"), 30-len(installs))
				if len(more) > 0 {
					w.Write("\n[backfilled from /var/log/dpkg.log.1]\n")
					for _, l := range more {
						w.Write("%s\n", l)
					}
					installs = append(installs, more...)
				}
			}
		}
		output.Ok(fmt.Sprintf("dpkg install log collected (%d entries)", len(installs)))
		return
	}

	if out, err := execFallback(ctx, "rpm", "-qa", "--last"); err == nil {
		w.WriteSectionHeader("rpm -qa --last (last 30)")
		lines := strings.Split(out, "\n")
		limit := 30
		if len(lines) < limit {
			limit = len(lines)
		}
		for _, l := range lines[:limit] {
			w.Write("%s\n", l)
		}
		output.Ok("rpm package list collected")
		return
	}

	w.Write("No supported package manager log found.\n")
	output.Note("No package manager log available")
}

func baselineKernelTaint(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "07_kernel_taint.txt",
		"Kernel Taint Analysis", "/proc/sys/kernel/tainted")
	defer w.Close()

	data, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		w.Write("Cannot read /proc/sys/kernel/tainted: %v\n", err)
		output.Note("Kernel taint: cannot read")
		return
	}

	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		w.Write("Cannot parse tainted value: %v\n", err)
		return
	}

	w.Write("Tainted value: %d (0x%x)\n\n", val, val)

	if val == 0 {
		w.Write("Kernel is not tainted.\n")
		output.Ok("Kernel taint: clean (0)")
		return
	}

	matched, highestSev, unknownBits := matchTaintBits(val)

	for _, tb := range matched {
		w.Write("  [%s] bit %5d (0x%04x) - %s\n", tb.sev, tb.bit, tb.bit, tb.desc)
	}
	if unknownBits != 0 {
		w.Write("  [MEDIUM] unknown bits 0x%x - kernel may be newer than taint table\n", unknownBits)
	}

	hits := len(matched)
	msg := fmt.Sprintf("Kernel taint flags set: 0x%x (%d bit(s)) - see 07_kernel_taint.txt", val, hits)
	if unknownBits != 0 {
		msg = fmt.Sprintf("Kernel taint flags set: 0x%x (%d known bit(s), unknown bits 0x%x) - see 07_kernel_taint.txt", val, hits, unknownBits)
	}
	ctx.Registry.Add(highestSev, "baseline", "Kernel taint flags", msg)
	output.Warn(fmt.Sprintf("Kernel is tainted: 0x%x", val))
}

func baselineCmdline(ctx *ModuleContext) {
	w := newSectionWriter(ctx, ctx.Dirs.Baseline, "08_cmdline.txt",
		"Kernel Command Line", "/proc/cmdline")
	defer w.Close()

	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		w.Write("Cannot read /proc/cmdline: %v\n", err)
		output.Note("Kernel cmdline: cannot read")
		return
	}

	cmdline := strings.TrimSpace(string(data))
	w.WriteSectionHeader("/proc/cmdline")
	w.Write("%s\n", cmdline)

	findings := analyzeCmdline(strings.Fields(cmdline))
	for _, f := range findings {
		ctx.Registry.Add(f.sev, "baseline", f.label, f.msg)
	}
	hits := len(findings)

	if hits > 0 {
		output.Warn(fmt.Sprintf("Kernel cmdline: %d finding(s)", hits))
	} else {
		output.Ok("Kernel cmdline collected")
	}
}
