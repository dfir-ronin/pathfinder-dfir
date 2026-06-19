package ioc

import (
	"io"
	"regexp"
	"strings"

	"github.com/pathfinder/internal/osutil"
)

// MalwareDirs are filesystem paths considered highly suspicious for executable
// or service binaries.
var MalwareDirs = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/dev/mqueue/",
	"/run/shm/",
	// Linux malware staging directories
	"/var/tmp/.11/",
	"/var/tmp/.222/",
}

// IsInMalwareDir returns true if path starts with any MalwareDirs prefix.
func IsInMalwareDir(path string) bool {
	for _, d := range MalwareDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// InsmodLoose matches any line containing the word "insmod" or "modprobe".
var InsmodLoose = regexp.MustCompile(`(?i)\b(insmod|modprobe)\b`)

// KnownSnifferNames are executable base-names associated with packet capture.
var KnownSnifferNames = map[string]bool{
	"tcpdump":     true,
	"tshark":      true,
	"wireshark":   true,
	"dumpcap":     true,
	"snort":       true,
	"suricata":    true,
	"zeek":        true,
	"bro":         true,
	"ngrep":       true,
	"ettercap":    true,
	"dsniff":      true,
	"netsniff-ng": true,
	"pktmon":      true,
	"scapy":       true,
	"pcapng":      true,
}

// SafeDirs are directories considered "safe" for executable processes.
var SafeDirs = []string{
	"/usr/",
	"/bin/",
	"/sbin/",
	"/lib/",
	"/lib64/",
	"/opt/",
	"/snap/",
}

// IsInSafeDir returns true if path starts with any of the safe directory prefixes.
func IsInSafeDir(path string) bool {
	for _, d := range SafeDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// CompressedExtensions are file extensions for archives found in staging dirs.
var CompressedExtensions = []string{
	".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
	".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".lz4", ".zst",
}

// IsCompressedFile returns true if the filename ends with a known archive extension.
func IsCompressedFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range CompressedExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// IsMagicELF returns true if the first four bytes of the file are the ELF magic
// number (\x7fELF). Used to detect ELF binaries disguised with non-binary extensions.
func IsMagicELF(path string) bool {
	f, err := osutil.OpenNoAtime(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// SysModuleAllowlist contains entries that appear in /sys/module but not
// necessarily in /proc/modules (kernel built-ins or pseudo-entries).
var SysModuleAllowlist = map[string]bool{
	"kernel":         true,
	"config":         true,
	"block":          true,
	"parameters":     true,
	"firmware_class": true,
	"printk":         true,
	"arch_perfmon":   true,
	"cpuidle":        true,
	"rcupdate":       true,
	"workqueue":      true,
}
