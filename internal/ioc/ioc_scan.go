package ioc

import (
	"bufio"
	"strings"

	"github.com/pathfinder/internal/osutil"
)

// maxIOCLine bounds a single scanned line. bufio.Scanner defaults to 64 KB,
// which silently drops minified web shells, base64 blobs, and single-line audit
// records -- exactly the lines that carry IOCs. 8 MB covers realistic payloads
// while still bounding memory per line.
const maxIOCLine = 8 * 1024 * 1024

// newIOCScanner returns a line scanner whose token limit is maxIOCLine rather
// than bufio's 64 KB default.
func newIOCScanner(text string) *bufio.Scanner {
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, 0, 64*1024), maxIOCLine)
	return s
}

// IOCScanFile scans a file line by line against matchers.
// Missing or unreadable files are silently skipped (returns nil).
// Uses O_NOATIME to preserve forensic timestamps.
func IOCScanFile(path string, matchers []Matcher) []IOCHit {
	data, err := osutil.ReadFileNoAtime(path)
	if err != nil {
		return nil
	}
	return IOCScanText(string(data), matchers)
}

// IOCScanText scans arbitrary text against matchers.
func IOCScanText(text string, matchers []Matcher) []IOCHit {
	if len(matchers) == 0 || text == "" {
		return nil
	}
	var hits []IOCHit
	scanner := newIOCScanner(text)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if ind, ok := matchAny(matchers, line); ok {
			hits = append(hits, IOCHit{
				Indicator: ind,
				Line:      strings.TrimSpace(line),
				LineNum:   lineNum,
			})
		}
	}
	return hits
}

// IOCScanFileForIPs extracts all IPv4 addresses from a file and checks each
// against the IOCSet's IP matchers (including CIDR ranges).
// Missing files are silently skipped.
func IOCScanFileForIPs(path string, sh *IOCSet) []IOCHit {
	if len(sh.IPs) == 0 {
		return nil
	}
	data, err := osutil.ReadFileNoAtime(path)
	if err != nil {
		return nil
	}
	return IOCScanTextForIPs(string(data), sh)
}

// ScanProcNetForIPs parses /proc/net/{tcp,udp}{,6} content, hex-decodes the
// local and remote address columns, and matches each decoded IP against the
// IOCSet's IP matchers (literal and CIDR). The header row and malformed lines
// are skipped. This is the correct path for live-connection IP IOCs; the
// dotted-decimal scanners (IOCScanTextForIPs) cannot match /proc/net hex.
func ScanProcNetForIPs(text string, sh *IOCSet) []IOCHit {
	if len(sh.IPs) == 0 || text == "" {
		return nil
	}
	var hits []IOCHit
	scanner := newIOCScanner(text)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		seen := make(map[string]bool)
		for _, col := range []string{fields[1], fields[2]} {
			host, _, ok := strings.Cut(col, ":")
			if !ok {
				continue
			}
			ip := ParseProcNetIP(host)
			if ip == nil {
				continue
			}
			s := ip.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			if ind, ok := sh.MatchIP(s); ok {
				hits = append(hits, IOCHit{Indicator: ind, Line: strings.TrimSpace(line), LineNum: lineNum})
			}
		}
	}
	return hits
}

// IOCScanTextForIPs extracts all IPv4 addresses from text and checks against
// the IOCSet's IP matchers.
func IOCScanTextForIPs(text string, sh *IOCSet) []IOCHit {
	if len(sh.IPs) == 0 || text == "" {
		return nil
	}
	var hits []IOCHit
	scanner := newIOCScanner(text)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		seenThisLine := make(map[string]bool)
		for _, ipStr := range reIPv4.FindAllString(line, -1) {
			if seenThisLine[ipStr] {
				continue
			}
			seenThisLine[ipStr] = true
			if ind, ok := sh.MatchIP(ipStr); ok {
				hits = append(hits, IOCHit{
					Indicator: ind,
					Line:      strings.TrimSpace(line),
					LineNum:   lineNum,
				})
			}
		}
	}
	return hits
}
