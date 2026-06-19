package ioc

import (
	"regexp"
	"strings"
)

// Severity mirrors output.Severity to avoid a circular import.
type Severity string

const (
	HIGH   Severity = "HIGH"
	MEDIUM Severity = "MEDIUM"
	LOW    Severity = "LOW"
)

// Signature is a single detection rule.
type Signature struct {
	ID          string
	Pattern     *regexp.Regexp
	Severity    Severity
	Description string
	Category    string // string-hunt category; empty = not a string-hunt sig
}

// Hit is a single signature match result.
type Hit struct {
	Sig     Signature
	Line    string
	LineNum int
}

// BashHistorySignatures are patterns matched against shell history lines.
var BashHistorySignatures = []Signature{
	{ID: "BH001", Pattern: regexp.MustCompile(`(?i)curl\s+.+\|\s*(ba)?sh`), Severity: HIGH, Description: "curl pipe to shell — remote code execution"},
	{ID: "BH002", Pattern: regexp.MustCompile(`(?i)wget\s+.+-O\s*-?\s*\|`), Severity: HIGH, Description: "wget pipe to shell — remote code execution"},
	{ID: "BH003", Pattern: regexp.MustCompile(`(?i)python[23]?\s+-c\s+.+(exec|eval|import\s+os)`), Severity: HIGH, Description: "Python one-liner with exec/eval/os import"},
	{ID: "BH004", Pattern: regexp.MustCompile(`(?i)perl\s+-e\s+.+(exec|system|socket)`), Severity: HIGH, Description: "Perl one-liner with exec/system/socket"},
	{ID: "BH005", Pattern: regexp.MustCompile(`(?i)base64\s+-d\s*\|`), Severity: HIGH, Description: "base64 decode pipe — encoded payload"},
	{ID: "BH006", Pattern: regexp.MustCompile(`(?i)(nc|ncat|netcat)\s+.+-e\s+`), Severity: HIGH, Description: "netcat with -e flag — reverse shell"},
	{ID: "BH007", Pattern: regexp.MustCompile(`(?i)bash\s+-i\s*>&?\s*/dev/(tcp|udp)/`), Severity: HIGH, Description: "bash /dev/tcp reverse shell"},
	{ID: "BH008", Pattern: regexp.MustCompile(`(?i)socat\s+.+(exec|pty|tcp)`), Severity: HIGH, Description: "socat tunnel or PTY spawn"},
	{ID: "BH009", Pattern: regexp.MustCompile(`(?i)(history\s+-c|unset\s+HISTFILE|HISTFILESIZE=0)`), Severity: HIGH, Description: "History evasion — clearing or disabling history"},
	{ID: "BH010", Pattern: regexp.MustCompile(`(?i)dd\s+if=/dev/(zero|urandom|mem|sda)`), Severity: HIGH, Description: "dd reading from block/mem device — possible wiping"},
	{ID: "BH011", Pattern: regexp.MustCompile(`(?i)iptables\s+-F`), Severity: HIGH, Description: "iptables -F — flushing firewall rules"},
	{ID: "BH012", Pattern: regexp.MustCompile(`(?i)(useradd|adduser)\s+`), Severity: MEDIUM, Description: "User account creation in history"},
	{ID: "BH013", Pattern: regexp.MustCompile(`(?i)usermod\s+.+-G\s*(sudo|wheel|root)`), Severity: HIGH, Description: "usermod adding user to privileged group"},
	{ID: "BH014", Pattern: regexp.MustCompile(`(?i)chmod\s+[+ugoa]*s\s+`), Severity: HIGH, Description: "chmod setting SUID/SGID bit"},
	{ID: "BH015", Pattern: regexp.MustCompile(`(?i)chattr\s+\+i`), Severity: MEDIUM, Description: "chattr +i — setting immutable flag"},
	{ID: "BH016", Pattern: regexp.MustCompile(`(?i)(pkill|kill)\s+-9\s+`), Severity: MEDIUM, Description: "Force-killing processes"},
	{ID: "BH017", Pattern: regexp.MustCompile(`(?i)mount\s+.+(--bind|tmpfs|proc)`), Severity: MEDIUM, Description: "Unusual mount — bind, tmpfs or /proc"},
	{ID: "BH018", Pattern: regexp.MustCompile(`(?i)python[23]?\s+-m\s+http\.server`), Severity: MEDIUM, Description: "Python HTTP server started — staging or exfil"},
	{ID: "BH019", Pattern: regexp.MustCompile(`(?i)(wget|curl)\s+.+(-O\s+/tmp|-o\s+/tmp|/dev/shm)`), Severity: HIGH, Description: "Download to staging directory"},
	{ID: "BH020", Pattern: regexp.MustCompile(`(?i)(chmod|chown)\s+777\s+`), Severity: MEDIUM, Description: "World-writable permissions set"},
	{ID: "BH021", Pattern: regexp.MustCompile(`(?i)crontab\s+.+(-e|-l|-r)`), Severity: MEDIUM, Description: "crontab modification in history"},
	{ID: "BH022", Pattern: regexp.MustCompile(`(?i)nohup\s+.+&\s*$`), Severity: MEDIUM, Description: "nohup background — persistence or daemonization"},
	{ID: "BH023", Pattern: regexp.MustCompile(`(?i)eval\s+\$\(`), Severity: HIGH, Description: "eval with command substitution — obfuscated execution"},
	{ID: "BH024", Pattern: regexp.MustCompile(`(?i)scp\s+.+:/`), Severity: LOW, Description: "scp remote copy — possible data transfer"},
	{ID: "BH025", Pattern: regexp.MustCompile(`(?i)(export\s+)?HISTFILE=/dev/null`), Severity: HIGH, Description: "HISTFILE redirected to /dev/null — evasion"},
	{ID: "BH026", Pattern: regexp.MustCompile(`(?i)insmod\s+|modprobe\s+`), Severity: HIGH, Description: "Kernel module loaded from history"},
	{ID: "BH027", Pattern: regexp.MustCompile(`(?i)strace\s+.+-p\s+`), Severity: MEDIUM, Description: "strace attaching to process — credential harvesting possible"},
	{ID: "BH028", Pattern: regexp.MustCompile(`(?i)tcpdump\s+`), Severity: MEDIUM, Description: "tcpdump — packet capture"},
	{ID: "BH029", Pattern: regexp.MustCompile(`(?i)at\s+now|echo\s+.+\|\s*at\s+`), Severity: MEDIUM, Description: "at job scheduled — deferred persistence"},
	{ID: "BH030", Pattern: regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)`), Severity: HIGH, Description: "Direct access to sensitive auth file"},

	// Modern Malware TTPs (BH031-BH039) -- next available: BH040
	{ID: "BH031", Pattern: regexp.MustCompile(`(?i)shopt\s+-[ou]+\s+history`), Severity: HIGH, Description: "Shell history suppression via shopt"},
	{ID: "BH032", Pattern: regexp.MustCompile(`(?i)setenforce\s+0`), Severity: HIGH, Description: "SELinux disabled at runtime"},
	{ID: "BH033", Pattern: regexp.MustCompile(`(?i)(systemctl|service)\s+(stop|disable)\s+(firewalld|apparmor|ufw)`), Severity: HIGH, Description: "Firewall or AppArmor disabled"},
	{ID: "BH034", Pattern: regexp.MustCompile(`(?i)finit_module\s*\(`), Severity: HIGH, Description: "Fileless kernel module load via finit_module syscall"},
	{ID: "BH035", Pattern: regexp.MustCompile(`(?i)\b(masscan|zgrab|pnscan)\b`), Severity: MEDIUM, Description: "Network scanner executed — lateral movement recon"},
	// BH036-BH038: May fire on legitimate cloud-init tooling; correlate with other cloud activity.
	{ID: "BH036", Pattern: regexp.MustCompile(`(?i)curl\s+.*x-aws-ec2-metadata-token`), Severity: HIGH, Description: "IMDSv2 metadata token request — cloud credential harvesting"},
	{ID: "BH037", Pattern: regexp.MustCompile(`(?i)curl\s+.*metadata\.google\.internal`), Severity: HIGH, Description: "GCP metadata API probe — cloud credential harvesting"},
	{ID: "BH038", Pattern: regexp.MustCompile(`(?i)curl\s+.*169\.254\.169\.254`), Severity: HIGH, Description: "Cloud IMDS endpoint probe (AWS/Azure/Alibaba/Tencent)"},
	{ID: "BH039", Pattern: regexp.MustCompile(`(?i)chmod\s+[2-7][0-7]{3}\b`), Severity: HIGH, Description: "chmod setting SUID/SGID bit (octal notation)"},
}

// StringHuntSignatures are patterns for scanning cmdlines, configs, and scripts.
var StringHuntSignatures = []Signature{
	// Web Shells
	{ID: "SH001", Pattern: regexp.MustCompile(`(?i)system\s*\(\s*['\"]\s*/bin/sh`), Severity: HIGH, Description: "system('/bin/sh') call — webshell or exploit", Category: "webshells"},
	{ID: "SH002", Pattern: regexp.MustCompile(`(?i)(passthru|shell_exec|popen)\s*\(`), Severity: HIGH, Description: "PHP/script shell execution function", Category: "webshells"},
	{ID: "SH003", Pattern: regexp.MustCompile(`(?i)base64_decode\s*\(`), Severity: HIGH, Description: "base64_decode call — obfuscated payload", Category: "webshells"},
	{ID: "SH004", Pattern: regexp.MustCompile(`(?i)(gzinflate|str_rot13|gzuncompress)\s*\(`), Severity: HIGH, Description: "Deobfuscation function — webshell pattern", Category: "webshells"},
	{ID: "SH005", Pattern: regexp.MustCompile(`(?i)REMOTE_ADDR|HTTP_USER_AGENT|REQUEST_URI`), Severity: MEDIUM, Description: "CGI environment variable in binary/script", Category: "webshells"},

	// Stagers & C2
	{ID: "SH006", Pattern: regexp.MustCompile(`(?i)AAAAB3NzaC1yc2`), Severity: MEDIUM, Description: "SSH RSA public key embedded in file", Category: "stagers_c2"},
	{ID: "SH007", Pattern: regexp.MustCompile(`(?i)(pastebin\.com|hastebin\.com|transfer\.sh)`), Severity: HIGH, Description: "Paste site reference — exfil or payload hosting", Category: "stagers_c2"},
	{ID: "SH008", Pattern: regexp.MustCompile(`(?i)\b(curl|wget)\b`), Severity: LOW, Description: "curl/wget present — correlate with other signals", Category: "stagers_c2"},
	{ID: "SH009", Pattern: regexp.MustCompile(`(?i)process\.env\.(?:GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|KUBERNETES_SERVICE_HOST|SLACK_WEBHOOK)\b`), Severity: HIGH, Description: "Named credential env var harvesting", Category: "stagers_c2"},
	{ID: "SH010", Pattern: regexp.MustCompile(`(?i)(dns\.resolve|dns\.lookup|dns\.resolveTxt)\s*\(`), Severity: HIGH, Description: "DNS API call — potential exfiltration channel", Category: "stagers_c2"},

	// Script Execution
	{ID: "SH011", Pattern: regexp.MustCompile(`(?i)eval\s*\(\s*(atob|Buffer\.from|decodeURIComponent)`), Severity: HIGH, Description: "Obfuscated eval — base64/URI-decoded payload execution", Category: "script_exec"},
	{ID: "SH012", Pattern: regexp.MustCompile(`(?i)Function\s*\(\s*(?:"[^"]{20,}"|'[^']{20,}')\s*\)`), Severity: HIGH, Description: "Function constructor with string arg — dynamic code execution", Category: "script_exec"},
	{ID: "SH013", Pattern: regexp.MustCompile(`(?i)(setTimeout|setInterval)\s*\(\s*["']`), Severity: MEDIUM, Description: "Timer receiving string arg — deferred eval pattern", Category: "script_exec"},
	{ID: "SH014", Pattern: regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]\s*\)`), Severity: HIGH, Description: "child_process require — shell execution capability", Category: "script_exec"},
	{ID: "SH015", Pattern: regexp.MustCompile(`(?i)(execSync|spawnSync)\s*\(`), Severity: HIGH, Description: "Synchronous shell execution call", Category: "script_exec"},
	{ID: "SH016", Pattern: regexp.MustCompile(`(?i)(os\.platform|os\.homedir|os\.arch)\s*\(\)`), Severity: MEDIUM, Description: "OS fingerprinting — platform-specific payload drop", Category: "script_exec"},
	{ID: "SH017", Pattern: regexp.MustCompile(`(?i)fs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile)\s*\(`), Severity: MEDIUM, Description: "Filesystem operation in script file", Category: "script_exec"},
	{ID: "SH018", Pattern: regexp.MustCompile(`(?i)os\.system\s*\(`), Severity: HIGH, Description: "Python os.system call — shell execution", Category: "script_exec"},
	{ID: "SH019", Pattern: regexp.MustCompile(`(?i)subprocess\.(run|Popen|call)\s*\(`), Severity: HIGH, Description: "Python subprocess execution", Category: "script_exec"},
	{ID: "SH020", Pattern: regexp.MustCompile(`(?i)python[23]?\s+-c\s+.*(exec|eval|import\s+os|import\s+subprocess)`), Severity: HIGH, Description: "Python one-liner with exec/eval/os/subprocess", Category: "script_exec"},
	{ID: "SH021", Pattern: regexp.MustCompile(`(?i)(?:bash|sh)\b\s+-c\s+["']\$\(`), Severity: HIGH, Description: "sh/bash -c with command substitution — dynamic shell execution", Category: "script_exec"},

	// Data Exfiltration
	{ID: "SH023", Pattern: regexp.MustCompile(`(?i)(s3\.amazonaws\.com|api\.github\.com/repos/[^/]+/[^/]+/contents|googleapis\.com/upload|api\.telegram\.org/bot[\w:@-]+/send|discord\.com/api/webhooks/\d+/[\w-]+)`), Severity: HIGH, Description: "Upload to cloud storage or messaging webhook — data exfiltration channel", Category: "data_exfil"},
	{ID: "SH024", Pattern: regexp.MustCompile(`(?i)\b(curl|wget)\b.*(--upload-file|--data-binary|--data-raw|\s-T\s|\s-F\s+\S*@)`), Severity: HIGH, Description: "curl/wget with file-upload flag — HTTP-based data exfiltration", Category: "data_exfil"},
	{ID: "SH025", Pattern: regexp.MustCompile(`(?i)\btar\b[^|]*[czjJa][^|]*\|\s*(curl|wget|nc|ncat|socat|openssl|ssh)\b`), Severity: HIGH, Description: "tar archive piped to network tool — in-flight data exfiltration", Category: "data_exfil"},
	{ID: "SH026", Pattern: regexp.MustCompile(`(?i)\b(tar|gzip|bzip2|xz|zstd|zip|7z|pigz|lz4)\b.*>\s*["']?(\/tmp|\/dev\/shm|\/var\/tmp)\/`), Severity: MEDIUM, Description: "Archive compressed to staging directory — data staging for exfiltration", Category: "data_exfil"},
	{ID: "SH027", Pattern: regexp.MustCompile(`(?i)\bscp\b(\s+-[a-zA-Z0-9]+)*\s+\S+\s+[\w.-]+@[\w.-]+:`), Severity: HIGH, Description: "scp outbound transfer — remote file copy for data exfiltration", Category: "data_exfil"},
	{ID: "SH028", Pattern: regexp.MustCompile(`(?i)\brsync\b.*(-e\s+['"]?ssh|--rsh=['"]?ssh).*@[\w.-]+`), Severity: HIGH, Description: "rsync over SSH — remote synchronisation for data exfiltration", Category: "data_exfil"},
	{ID: "SH029", Pattern: regexp.MustCompile(`(?i)\bsftp\b(\s+-[a-zA-Z0-9]+)*\s+[\w.-]+@[\w.-]+`), Severity: MEDIUM, Description: "sftp outbound transfer — file transfer for data exfiltration", Category: "data_exfil"},
}

var StringHuntCategoryFiles = map[string]string{
	"webshells":   "02_string_hunt_webshells.txt",
	"stagers_c2":  "03_string_hunt_stagers_c2.txt",
	"script_exec": "04_string_hunt_script_exec.txt",
	"data_exfil":  "05_string_hunt_data_exfil.txt",
}

var StringHuntCategoryLabels = map[string]string{
	"webshells":   "Web Shells (PHP exec, base64_decode, gzinflate)",
	"stagers_c2":  "Stagers & C2 (paste sites, SSH key, curl/wget, credential harvest, DNS exfil)",
	"script_exec": "Script Execution (eval, child_process, subprocess, bash -c)",
	"data_exfil":  "Data Exfiltration (cloud upload, scp/rsync/sftp, archive-to-network, SSH tunnel)",
}

// StringHuntCategoryDetectionLabel maps each string-hunt category to its Registry
// detection label. Categories not present here fall back to "Suspicious string match in config/script".
var StringHuntCategoryDetectionLabel = map[string]string{
	"data_exfil": "Data exfil pattern in config/script",
}

// CategoryPreFilter holds a combined alternation regexp for one string-hunt category.
type CategoryPreFilter struct {
	Re       *regexp.Regexp
	Category string
}

// BuildCategoryPreFilters builds one combined alternation regexp per category from
// StringHuntSignatures. Each pattern is wrapped in a non-capturing group before
// joining with | to preserve flag scoping. Safe to call once and share across
// goroutines.
func BuildCategoryPreFilters() []CategoryPreFilter {
	byCategory := make(map[string][]*regexp.Regexp)
	order := make([]string, 0)
	for _, sig := range StringHuntSignatures {
		if sig.Category == "" {
			continue
		}
		if _, seen := byCategory[sig.Category]; !seen {
			order = append(order, sig.Category)
		}
		byCategory[sig.Category] = append(byCategory[sig.Category], sig.Pattern)
	}
	filters := make([]CategoryPreFilter, 0, len(order))
	for _, cat := range order {
		pats := byCategory[cat]
		parts := make([]string, len(pats))
		for i, p := range pats {
			parts[i] = "(?:" + p.String() + ")"
		}
		combined := regexp.MustCompile(strings.Join(parts, "|"))
		filters = append(filters, CategoryPreFilter{Re: combined, Category: cat})
	}
	return filters
}

// ScanLines checks each line of text against a given signature list.
func ScanLines(text string, sigs []Signature) []Hit {
	var hits []Hit
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		for _, sig := range sigs {
			if sig.Pattern.MatchString(line) {
				hits = append(hits, Hit{
					Sig:     sig,
					Line:    strings.TrimSpace(line),
					LineNum: i + 1,
				})
			}
		}
	}
	return hits
}
