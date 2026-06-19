package suppress

import (
	"bufio"
	"os"
	"strings"
)

// DetectDistro returns "ubuntu", "rhel", or "" (unknown) by reading /etc/os-release.
func DetectDistro() string {
	return parseOSRelease("/etc/os-release")
}

func parseOSRelease(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = strings.Trim(v, `"`)
	}

	id := fields["ID"]
	idLike := fields["ID_LIKE"]

	switch {
	case id == "ubuntu":
		return "ubuntu"
	case id == "debian":
		return "debian"
	case id == "rhel" || id == "ol":
		return "rhel"
	case strings.Contains(idLike, "rhel"):
		return "rhel"
	case strings.Contains(idLike, "ubuntu"):
		return "ubuntu"
	case strings.Contains(idLike, "debian"):
		return "debian"
	}
	return ""
}
