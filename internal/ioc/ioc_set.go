package ioc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// Matcher is a single compiled custom IOC indicator.
type Matcher struct {
	Raw       string
	IsLiteral bool // true for plain-string (non-regex, non-glob) indicators
	IsRegex   bool // compiled regexp match
	Re        *regexp.Regexp
	CIDR      *net.IPNet // non-nil only for IP CIDR matchers
	lowerRaw  string     // cached strings.ToLower(Raw) for literals; may be empty for hand-built matchers
}

// IOCHit is a single IOCSet match result.
type IOCHit struct {
	Indicator string
	Line      string
	LineNum   int
}

// IOCSet holds all loaded custom IOC indicators for a triage session.
type IOCSet struct {
	Commands  []Matcher
	Filenames []Matcher
	Processes []Matcher
	Domains   []Matcher
	IPs       []Matcher
	Hashes    map[string]struct{} // lowercase hex; exact-only (no regex on hashes)
	Loaded    int
	Skipped   int
}

// MatchCommand returns the matched indicator and true if s matches any command indicator.
func (sh *IOCSet) MatchCommand(s string) (string, bool) { return matchAny(sh.Commands, s) }

// MatchFilename returns the matched indicator and true if s matches any filename indicator.
// Literals match as a path segment / basename (bounded by non-filename chars), not as an
// interior substring, so "sh" matches "/bin/sh" but not "bash". Regex matchers are unchanged.
func (sh *IOCSet) MatchFilename(s string) (string, bool) { return matchAnyPath(sh.Filenames, s) }

// MatchProcess returns the matched indicator and true if s matches any process indicator.
// Literals match the comm by exact or basename equality, not substring, so "sh" matches the
// process "sh" or "/bin/sh" but not "bash"/"ssh"/"flush". Regex matchers are unchanged.
func (sh *IOCSet) MatchProcess(s string) (string, bool) { return matchAnyToken(sh.Processes, s) }

// MatchIP checks an IP string against IP matchers including CIDR ranges.
func (sh *IOCSet) MatchIP(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	for _, m := range sh.IPs {
		if m.CIDR != nil {
			if ip != nil && m.CIDR.Contains(ip) {
				return m.Raw, true
			}
			continue
		}
		if m.IsLiteral {
			if ipStr == m.Raw {
				return m.Raw, true
			}
		} else if m.IsRegex && m.Re != nil {
			if m.Re.MatchString(ipStr) {
				return m.Raw, true
			}
		}
	}
	return "", false
}

// MatchHash returns true if the lowercase hex hash matches any loaded hash indicator.
func (sh *IOCSet) MatchHash(hexHash string) bool {
	_, ok := sh.Hashes[strings.ToLower(hexHash)]
	return ok
}

// AppendIPMatcher compiles a single IP/CIDR string and appends it to sh.IPs.
// Returns an error if the entry is neither a valid CIDR nor a valid literal.
func AppendIPMatcher(sh *IOCSet, raw string) error {
	if strings.ContainsRune(raw, '/') {
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			sh.IPs = append(sh.IPs, Matcher{Raw: raw, CIDR: cidr})
			return nil
		}
	}
	m, err := compileMatcher(raw)
	if err != nil {
		return err
	}
	sh.IPs = append(sh.IPs, m)
	return nil
}

// matchAnyToken matches literal matchers against s by exact or basename equality
// (case-insensitive). Regex matchers fall back to a full regex match.
func matchAnyToken(matchers []Matcher, s string) (string, bool) {
	lower := strings.ToLower(s)
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	for _, m := range matchers {
		if m.IsLiteral {
			ml := m.literalLower()
			if lower == ml || base == ml {
				return m.Raw, true
			}
		} else if m.IsRegex && m.Re != nil {
			if m.Re.MatchString(s) {
				return m.Raw, true
			}
		}
	}
	return "", false
}

// matchAnyPath matches literal matchers against s only where the literal appears bounded
// by non-filename characters (a path segment or basename). Regex matchers fall back to a
// full regex match.
func matchAnyPath(matchers []Matcher, s string) (string, bool) {
	lower := strings.ToLower(s)
	for _, m := range matchers {
		if m.IsLiteral {
			if containsBounded(lower, m.literalLower()) {
				return m.Raw, true
			}
		} else if m.IsRegex && m.Re != nil {
			if m.Re.MatchString(s) {
				return m.Raw, true
			}
		}
	}
	return "", false
}

func isFilenameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-'
}

// containsBounded reports whether sub occurs in s with a non-filename byte (or string edge)
// on both sides.
func containsBounded(s, sub string) bool {
	if sub == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(s[from:], sub)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(sub)
		leftOK := i == 0 || !isFilenameByte(s[i-1])
		rightOK := end == len(s) || !isFilenameByte(s[end])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
}

// literalLower returns the cached lowercased literal, computing it on demand for
// hand-built matchers that did not go through compileMatcher.
func (m Matcher) literalLower() string {
	if m.lowerRaw != "" {
		return m.lowerRaw
	}
	return strings.ToLower(m.Raw)
}

// matchAny is the internal fast-path+regex matcher used by all IOCSet.Match* methods.
// Literals use strings.Contains (case-insensitive); regex uses the compiled Re.
// Returns on the first match for early-exit performance.
func matchAny(matchers []Matcher, s string) (string, bool) {
	lower := strings.ToLower(s)
	for _, m := range matchers {
		if m.IsLiteral {
			if strings.Contains(lower, m.literalLower()) {
				return m.Raw, true
			}
		} else if m.IsRegex && m.Re != nil {
			if m.Re.MatchString(s) {
				return m.Raw, true
			}
		}
	}
	return "", false
}

// ParseIOCSet reads an IOC file and returns a compiled IOCSet.
//
// File format (section-based):
//
//	# comment
//	[commands]
//	curl * | bash
//	regex:base64\s+-d\s*\|
//
//	[ips]
//	10.0.0.0/8
//	185.220.101.5
//
// Regex auto-detection: entries containing * ? [ ] ^ $ | \ ( ) are treated as glob/regex.
// Explicit prefix "regex:" forces regex interpretation regardless.
// Invalid regex entries are warned and skipped; load continues.
func ParseIOCSet(path string) (*IOCSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ioc: open %s: %w", path, err)
	}
	defer f.Close()

	sh := &IOCSet{Hashes: make(map[string]struct{})}
	section := ""
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section == "" {
			continue
		}

		if section == "hashes" {
			norm := strings.ToLower(line)
			if !isValidHash(norm) {
				fmt.Fprintf(os.Stderr, "[IOC WARN] line %d: invalid hash %q — skipped\n", lineNum, line)
				sh.Skipped++
				continue
			}
			sh.Hashes[norm] = struct{}{}
			sh.Loaded++
			continue
		}

		if section == "ips" && strings.ContainsRune(line, '/') {
			if _, cidr, cidrErr := net.ParseCIDR(line); cidrErr == nil {
				sh.IPs = append(sh.IPs, Matcher{Raw: line, CIDR: cidr})
				sh.Loaded++
				continue
			}
		}

		m, compileErr := compileMatcher(line)
		if compileErr != nil {
			fmt.Fprintf(os.Stderr, "[IOC WARN] line %d: %v — skipped\n", lineNum, compileErr)
			sh.Skipped++
			continue
		}
		switch section {
		case "commands":
			sh.Commands = append(sh.Commands, m)
			sh.Loaded++
		case "filenames":
			sh.Filenames = append(sh.Filenames, m)
			sh.Loaded++
		case "processes":
			sh.Processes = append(sh.Processes, m)
			sh.Loaded++
		case "domains":
			sh.Domains = append(sh.Domains, m)
			sh.Loaded++
		case "ips":
			sh.IPs = append(sh.IPs, m)
			sh.Loaded++
		default:
			fmt.Fprintf(os.Stderr, "[IOC WARN] line %d: unknown section %q — skipped\n", lineNum, section)
			sh.Skipped++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ioc: read %s: %w", path, err)
	}

	return sh, nil
}

// compileMatcher converts a raw indicator string into a Matcher.
// Glob wildcards (* ?) are translated to regex equivalents before compiling.
func compileMatcher(raw string) (Matcher, error) {
	m := Matcher{Raw: raw}
	isExplicit := strings.HasPrefix(raw, "regex:")
	pattern := raw
	if isExplicit {
		pattern = raw[6:]
	}

	hasSpecial := !isExplicit && strings.ContainsAny(raw, "*?[]^$|\\()")
	if isExplicit || hasSpecial {
		if hasSpecial {
			// Escape all regex meta-chars, then restore glob wildcard semantics.
			pattern = regexp.QuoteMeta(raw)
			pattern = strings.ReplaceAll(pattern, `\*`, ".*")
			pattern = strings.ReplaceAll(pattern, `\?`, ".")
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return m, fmt.Errorf("invalid pattern %q: %w", raw, err)
		}
		m.IsRegex = true
		m.Re = re
	} else {
		m.IsLiteral = true
		m.lowerRaw = strings.ToLower(raw)
	}
	return m, nil
}

// HashLengths reports which digest lengths are present in the loaded hash set
// (32=MD5, 40=SHA-1, 64=SHA-256) so scanners only compute the digests an
// operator actually supplied.
func (sh *IOCSet) HashLengths() (md5, sha1, sha256 bool) {
	for h := range sh.Hashes {
		switch len(h) {
		case 32:
			md5 = true
		case 40:
			sha1 = true
		case 64:
			sha256 = true
		}
	}
	return
}

// isValidHash returns true for lowercase hex strings of MD5 (32), SHA1 (40), or SHA256 (64) length.
func isValidHash(s string) bool {
	switch len(s) {
	case 32, 40, 64:
	default:
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
