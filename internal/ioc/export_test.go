package ioc

import (
	"bufio"
	"net"
	"strings"
)

// CompileMatcherForTest exposes compileMatcher to external tests.
func CompileMatcherForTest(raw string) (Matcher, error) { return compileMatcher(raw) }

// ParseIOCSetFromString parses IOC indicators from a string. Only available in tests.
func ParseIOCSetFromString(content string) (*IOCSet, error) {
	sh := &IOCSet{Hashes: make(map[string]struct{})}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
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
			if isValidHash(norm) {
				sh.Hashes[norm] = struct{}{}
				sh.Loaded++
			} else {
				sh.Skipped++
			}
			continue
		}
		if section == "ips" && strings.ContainsRune(line, '/') {
			if _, cidr, err := net.ParseCIDR(line); err == nil {
				sh.IPs = append(sh.IPs, Matcher{Raw: line, CIDR: cidr})
				sh.Loaded++
				continue
			}
		}
		m, err := compileMatcher(line)
		if err != nil {
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
			sh.Skipped++
		}
	}
	return sh, scanner.Err()
}
