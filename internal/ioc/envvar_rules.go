package ioc

import "strings"

// EnvVarRule defines a check against a single environment variable.
// If CheckValue is nil, the variable is flagged whenever it is present.
// If CheckValue is non-nil, it is called with the variable's value and the
// variable is flagged only when it returns true.
type EnvVarRule struct {
	Name             string
	CheckValue       func(val string) bool
	Severity         Severity
	Description      string
	Category         string
	SuppressionComms []string // process comm names to suppress (prefix match)
}

// SuspiciousEnvRules is the master list of suspicious environment variable checks.
var SuspiciousEnvRules = []EnvVarRule{
	// History Evasion
	{
		Name:        "HISTFILE",
		CheckValue:  func(v string) bool { return v == "/dev/null" || v == "" },
		Severity:    HIGH,
		Description: "HISTFILE=/dev/null — shell history discarded to null device",
		Category:    "history_evasion",
	},
	{
		Name:        "HISTSIZE",
		CheckValue:  func(v string) bool { return v == "0" },
		Severity:    HIGH,
		Description: "HISTSIZE=0 — in-memory command history disabled",
		Category:    "history_evasion",
	},
	{
		Name:        "HISTFILESIZE",
		CheckValue:  func(v string) bool { return v == "0" },
		Severity:    HIGH,
		Description: "HISTFILESIZE=0 — disk-based command history disabled",
		Category:    "history_evasion",
	},
	{
		Name:        "HISTCONTROL",
		CheckValue:  func(v string) bool { return strings.Contains(v, "ignorespace") },
		Severity:    MEDIUM,
		Description: "HISTCONTROL=ignorespace — space-prefixed commands not logged",
		Category:    "history_evasion",
	},
	{
		Name:        "MYSQL_HISTFILE",
		CheckValue:  func(v string) bool { return v == "/dev/null" },
		Severity:    HIGH,
		Description: "MYSQL_HISTFILE=/dev/null — BPFDoor indicator, DB history hidden",
		Category:    "history_evasion",
	},

	// Rootkit / Library Injection
	{
		Name:             "LD_PRELOAD",
		CheckValue:       isMaliciousPathValue,
		Severity:         HIGH,
		Description:      "LD_PRELOAD points to suspicious path — user-mode rootkit indicator",
		Category:         "rootkit",
		SuppressionComms: []string{"faketime", "libeatmydata", "valgrind", "ltrace"},
	},
	{
		Name: "LD_PRELOAD",
		CheckValue: func(v string) bool {
			return isNonStandardLibPath(v)
		},
		Severity:         MEDIUM,
		Description:      "LD_PRELOAD points to non-standard library path — possible library injection",
		Category:         "rootkit",
		SuppressionComms: []string{"faketime", "libeatmydata", "valgrind", "ltrace"},
	},
	{
		Name:        "LD_LIBRARY_PATH",
		CheckValue:  isMaliciousPathValue,
		Severity:    HIGH,
		Description: "LD_LIBRARY_PATH points to non-standard directory — library hijack",
		Category:    "rootkit",
	},
	{
		Name:        "PYTHONPATH",
		CheckValue:  isMaliciousPathValue,
		Severity:    MEDIUM,
		Description: "PYTHONPATH set to attacker-controlled directory — malicious module load",
		Category:    "rootkit",
	},
	{
		Name:        "PERL5LIB",
		CheckValue:  isMaliciousPathValue,
		Severity:    MEDIUM,
		Description: "PERL5LIB set to attacker-controlled directory — malicious module load",
		Category:    "rootkit",
	},

	// Remote Access / Privilege Trace
	{
		Name:        "REMOTEHOST",
		CheckValue:  nil,
		Severity:    LOW,
		Description: "REMOTEHOST present — hostname of the connecting machine",
		Category:    "access_trace",
	},
	{
		Name:        "SUDO_USER",
		CheckValue:  nil,
		Severity:    MEDIUM,
		Description: "SUDO_USER present — original low-privileged user who escalated to root",
		Category:    "access_trace",
	},

	// CGI / Web Shell Variables
	{Name: "HTTP_USER_AGENT", CheckValue: nil, Severity: MEDIUM, Description: "HTTP_USER_AGENT present — process may be a CGI handler or web shell", Category: "cgi_webshell"},
	{Name: "REMOTE_ADDR", CheckValue: nil, Severity: MEDIUM, Description: "REMOTE_ADDR present — process received an HTTP request (CGI/web shell)", Category: "cgi_webshell"},
	{Name: "REQUEST_URI", CheckValue: nil, Severity: MEDIUM, Description: "REQUEST_URI present — process invoked via HTTP request path", Category: "cgi_webshell"},
	{Name: "REQUEST_METHOD", CheckValue: nil, Severity: MEDIUM, Description: "REQUEST_METHOD present — process handling GET/POST (CGI context)", Category: "cgi_webshell"},
	{Name: "SCRIPT_NAME", CheckValue: nil, Severity: MEDIUM, Description: "SCRIPT_NAME present — CGI script name indicator", Category: "cgi_webshell"},
	{Name: "QUERY_STRING", CheckValue: nil, Severity: MEDIUM, Description: "QUERY_STRING present — process received URL query parameters (CGI/shell)", Category: "cgi_webshell"},
	{Name: "HTTP_HOST", CheckValue: nil, Severity: MEDIUM, Description: "HTTP_HOST present — process received HTTP Host header (CGI/web shell)", Category: "cgi_webshell"},
	{Name: "SERVER_NAME", CheckValue: nil, Severity: MEDIUM, Description: "SERVER_NAME present — process running in web server CGI context", Category: "cgi_webshell"},

	// SSH Lateral Movement Indicators
	{Name: "SSH_CONNECTION", CheckValue: nil, Severity: MEDIUM, Description: "SSH_CONNECTION present — process spawned from an inbound SSH session", Category: "ssh_lateral"},
	{Name: "SSH_CLIENT", CheckValue: nil, Severity: MEDIUM, Description: "SSH_CLIENT present — direct trace of connecting SSH client IP address", Category: "ssh_lateral"},
	{Name: "SSH_TTY", CheckValue: nil, Severity: MEDIUM, Description: "SSH_TTY present — interactive SSH PTY session; check for unexpected processes", Category: "ssh_lateral"},
	{Name: "SSH_ORIGINAL_COMMAND", CheckValue: nil, Severity: MEDIUM, Description: "SSH_ORIGINAL_COMMAND present — forced SSH command execution (key restriction)", Category: "ssh_lateral"},

	// Staging / Path Manipulation
	{
		Name: "OLDPWD",
		CheckValue: func(v string) bool {
			return strings.HasPrefix(v, "/tmp") ||
				strings.HasPrefix(v, "/var/tmp") ||
				strings.HasPrefix(v, "/dev/shm")
		},
		Severity:    MEDIUM,
		Description: "OLDPWD in staging directory — process moved from scratch space",
		Category:    "staging",
	},
	{
		Name:        "PATH",
		CheckValue:  hasLeadingDotOrMaliciousDir,
		Severity:    HIGH,
		Description: "PATH begins with . /tmp or /dev/shm — attacker binary injection possible",
		Category:    "staging",
	},
	{
		Name: "PWD",
		CheckValue: func(v string) bool {
			return strings.HasPrefix(v, "/tmp") ||
				strings.HasPrefix(v, "/dev/shm") ||
				strings.HasPrefix(v, "/var/tmp")
		},
		Severity:    MEDIUM,
		Description: "PWD is a staging directory — automated exploit or webshell indicator",
		Category:    "staging",
	},

	// Cloud Credential Exposure
	{Name: "AWS_ACCESS_KEY_ID", CheckValue: func(v string) bool { return v != "" }, Severity: HIGH, Description: "AWS access key in process environment — credential theft or cloud pivot", Category: "cloud_creds"},
	{Name: "AWS_SECRET_ACCESS_KEY", CheckValue: func(v string) bool { return v != "" }, Severity: HIGH, Description: "AWS secret key in process environment — cloud credential exposure", Category: "cloud_creds"},
	{Name: "AWS_SESSION_TOKEN", CheckValue: func(v string) bool { return v != "" }, Severity: HIGH, Description: "AWS session token in process environment — possible stolen credential", Category: "cloud_creds"},
	{Name: "GOOGLE_APPLICATION_CREDENTIALS", CheckValue: func(v string) bool { return v != "" }, Severity: HIGH, Description: "GCP service account credentials path in environment — cloud credential exposure", Category: "cloud_creds"},
	{Name: "AZURE_CLIENT_SECRET", CheckValue: func(v string) bool { return v != "" }, Severity: HIGH, Description: "Azure client secret in process environment — credential exposure", Category: "cloud_creds"},
	{
		Name:        "KUBECONFIG",
		CheckValue:  isMaliciousPathValue,
		Severity:    HIGH,
		Description: "KUBECONFIG pointing to staging directory — Kubernetes cluster pivot",
		Category:    "cloud_creds",
	},
}

// isMaliciousPathValue returns true if any colon-separated component of a
// path variable points to a staging directory or a hidden path.
func isMaliciousPathValue(v string) bool {
	for _, part := range strings.Split(v, ":") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "/tmp/") ||
			strings.HasPrefix(part, "/var/tmp/") ||
			strings.HasPrefix(part, "/dev/shm/") ||
			strings.HasPrefix(part, "/dev/mqueue/") {
			return true
		}
		// Hidden file or directory component
		if strings.Contains(part, "/.") {
			return true
		}
	}
	return false
}

// isNonStandardLibPath returns true if any colon-separated component of v
// is not under a standard system library directory and not a staging path.
// Note: bare /lib/ is excluded because real system libs live in architecture
// subdirectories (e.g. /lib/x86_64-linux-gnu/); a file directly in /lib/
// (e.g. /lib/preload_backdoor.so) is considered non-standard.
func isNonStandardLibPath(v string) bool {
	// standardPrefixes is non-exhaustive; covers common x86, aarch64, and ARM
	// Debian multiarch layouts. Add entries for riscv64, s390x, etc. as needed.
	standardPrefixes := []string{
		"/usr/lib/", "/usr/local/lib/",
		"/usr/lib64/", "/lib64/", "/usr/libexec/",
		"/lib/x86_64-linux-gnu/", "/lib/aarch64-linux-gnu/",
		"/lib/i386-linux-gnu/", "/lib/arm-linux-gnueabihf/",
	}
	for _, part := range strings.Split(v, ":") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if isMaliciousPathValue(part) {
			return false // HIGH rule handles this
		}
		standard := false
		for _, sp := range standardPrefixes {
			if strings.HasPrefix(part, sp) {
				standard = true
				break
			}
		}
		if !standard {
			return true
		}
	}
	return false
}

// hasLeadingDotOrMaliciousDir returns true if the first PATH component is
// ".", /tmp, /dev/shm, or /var/tmp.
func hasLeadingDotOrMaliciousDir(v string) bool {
	parts := strings.Split(v, ":")
	if len(parts) == 0 {
		return false
	}
	first := strings.TrimSpace(parts[0])
	return first == "." ||
		strings.HasPrefix(first, "/tmp") ||
		strings.HasPrefix(first, "/dev/shm") ||
		strings.HasPrefix(first, "/var/tmp")
}

// StandardEnvVars are variables expected in every shell or interpreter process
// spawned by a legitimate login or daemon manager.
var StandardEnvVars = []string{"PATH", "HOME", "USER"}

// ShellNames are process names that must have a full environment.
// A shell process missing PATH/HOME/USER was likely spawned by an exploit.
var ShellNames = map[string]bool{
	"bash":    true,
	"sh":      true,
	"dash":    true,
	"zsh":     true,
	"ksh":     true,
	"fish":    true,
	"python":  true,
	"python2": true,
	"python3": true,
	"perl":    true,
	"ruby":    true,
}
