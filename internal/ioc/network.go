package ioc

import (
	"encoding/hex"
	"net"
	"regexp"
	"strings"
)

var (
	reIPv4   = regexp.MustCompile(`\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|info|biz|xyz|top|online|site|ru|cn|br|de|uk|fr|nl|in|au|jp|kr|eu|cc|tk|pw|club|live|fun|app|dev|cloud|store|tech)\b`)
)

var privateCIDRs []*net.IPNet

func init() {
	privRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	for _, cidr := range privRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, network)
		}
	}
}

// IsPrivateIP returns true for loopback, RFC-1918, link-local, and other
// non-routable address ranges.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractExternalIPs finds public IPv4 addresses in arbitrary text.
func ExtractExternalIPs(text string) []string {
	matches := reIPv4.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		// Defensive: reIPv4 already constrains octets so every match parses today.
		// This guards against a future regex loosening surfacing malformed near-IPs.
		if net.ParseIP(m) == nil {
			continue
		}
		if !IsPrivateIP(m) && !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

// ParseProcNetIP decodes the hex address column from /proc/net/{tcp,udp}{,6}
// (the part before ':port') into a net.IP. The kernel writes each 32-bit word
// in host (little-endian) byte order. Returns nil for anything that is not a
// valid 8-char (IPv4) or 32-char (IPv6) hex string.
func ParseProcNetIP(hexAddr string) net.IP {
	switch len(hexAddr) {
	case 8:
		b, err := hex.DecodeString(hexAddr)
		if err != nil {
			return nil
		}
		return net.IPv4(b[3], b[2], b[1], b[0])
	case 32:
		b, err := hex.DecodeString(hexAddr)
		if err != nil {
			return nil
		}
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			ip[w*4+0] = b[w*4+3]
			ip[w*4+1] = b[w*4+2]
			ip[w*4+2] = b[w*4+1]
			ip[w*4+3] = b[w*4+0]
		}
		return ip
	default:
		return nil
	}
}

// ExtractDomains finds likely FQDNs in arbitrary text.
func ExtractDomains(text string) []string {
	matches := reDomain.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		lower := strings.ToLower(m)
		if lower == "localhost" || strings.HasSuffix(lower, ".local") {
			continue
		}
		if !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}
