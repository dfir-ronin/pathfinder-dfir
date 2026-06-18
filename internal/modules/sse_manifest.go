// internal/modules/sse_manifest.go
package modules

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pathfinder/internal/osutil"
	"gopkg.in/yaml.v3"
)

// uacUserHomePlaceholder replaces %user_home% in raw YAML before parsing;
// % cannot start an unquoted YAML scalar in yaml.v3.
const uacUserHomePlaceholder = "__user_home__"

type sseManifest struct {
	Version      string        `yaml:"version"`
	MaxTotalSize string        `yaml:"max_total_size"`
	Artifacts    []sseArtifact `yaml:"artifacts"`
}

type sseArtifact struct {
	Description        string       `yaml:"description"`
	Collector          string       `yaml:"collector"`
	Path               ssePathField `yaml:"path"`
	OutputDirectory    string       `yaml:"output_directory"`
	OutputFile         string       `yaml:"output_file"`
	SupportedOS        []string     `yaml:"supported_os"`
	MaxDepth           int          `yaml:"max_depth"`
	NamePattern        []string     `yaml:"name_pattern"`
	ExcludeNamePattern []string     `yaml:"exclude_name_pattern"`
	MaxFileSize        string       `yaml:"max_file_size"`
	ExcludePathPattern []string     `yaml:"exclude_path_pattern"`
	PathPattern        []string     `yaml:"path_pattern"`
	FileType           []string     `yaml:"file_type"`
}

// ssePathField accepts a YAML string (space-separated tokens) or a YAML sequence.
// The scalar form is split on spaces on purpose: it mirrors UAC's space-separated
// token format. A path that itself contains spaces must therefore use the sequence
// form, where each list item is taken as one complete path. Do not "fix" the scalar
// split to a single verbatim path without re-checking UAC manifest compatibility.
type ssePathField []string

func (p *ssePathField) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*p = strings.Fields(value.Value)
	case yaml.SequenceNode:
		var items []string
		if err := value.Decode(&items); err != nil {
			return err
		}
		*p = items
	default:
		return fmt.Errorf("path: unexpected YAML node kind %v", value.Kind)
	}
	return nil
}

func loadManifest(path string) (*sseManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.ReplaceAll(data, []byte("\t"), []byte("    "))
	data = bytes.ReplaceAll(data, []byte("%user_home%"), []byte(uacUserHomePlaceholder))
	var m sseManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// readHomeDirs parses a passwd-format file and returns home directories
// for root and users with UID >= 1000 with a login shell.
func readHomeDirs(passwdPath string) []string {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return nil
	}
	var homes []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if osutil.IsCommentOrBlank(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		username := fields[0]
		home := fields[5]
		shell := fields[6]

		noLogin := shell == "/bin/false" || shell == "/usr/sbin/nologin" || shell == "/sbin/nologin" || shell == "/usr/bin/nologin"
		if noLogin {
			continue
		}

		uid, _ := strconv.Atoi(fields[2])
		isRoot := username == "root"

		if (isRoot || uid >= 1000) && !seen[home] {
			homes = append(homes, home)
			seen[home] = true
		}
	}
	return homes
}

// expandUserHomes replaces %user_home% in pattern with each home directory from passwdPath.
// Returns the original pattern unchanged if it contains no placeholder.
func expandUserHomes(pattern, passwdPath string) []string {
	if !strings.Contains(pattern, uacUserHomePlaceholder) {
		return []string{pattern}
	}
	homes := readHomeDirs(passwdPath)
	result := make([]string, 0, len(homes))
	for _, home := range homes {
		result = append(result, strings.ReplaceAll(pattern, uacUserHomePlaceholder, home))
	}
	return result
}

// hasUACPlaceholder reports whether s contains a UAC-style %identifier% token.
// This detects placeholders like %temp_directory% or %user_home% without
// falsely matching literal % characters in file names like "100%_done.log".
func hasUACPlaceholder(s string) bool {
	for {
		i := strings.Index(s, "%")
		if i < 0 {
			return false
		}
		rest := s[i+1:]
		j := strings.IndexAny(rest, "%/")
		if j >= 0 && rest[j] == '%' {
			return true
		}
		s = rest
	}
}

// resolvedTarget is a resolved collection path plus how it was produced.
// fromGlob marks paths that came from expanding a wildcard token; globBase is
// the deepest non-glob directory prefix of that wildcard pattern. Together they
// let the collector contain attacker-influenced symlinks to their glob root.
type resolvedTarget struct {
	path     string
	fromGlob bool
	globBase string
}

// resolveTargets expands %user_home% and glob patterns, recording provenance.
func resolveTargets(tokens []string, passwdPath string) []resolvedTarget {
	var expanded []string
	for _, token := range tokens {
		expanded = append(expanded, expandUserHomes(token, passwdPath)...)
	}
	var filtered []string
	for _, p := range expanded {
		if !hasUACPlaceholder(p) {
			filtered = append(filtered, p)
		}
	}
	var resolved []resolvedTarget
	for _, pattern := range filtered {
		if containsGlobChars(pattern) {
			base := globBaseDir(pattern)
			for _, m := range mustGlob(pattern) {
				resolved = append(resolved, resolvedTarget{path: m, fromGlob: true, globBase: base})
			}
		} else {
			resolved = append(resolved, resolvedTarget{path: pattern, fromGlob: false})
		}
	}
	return resolved
}

func mustGlob(pattern string) []string {
	matches, _ := filepath.Glob(pattern)
	return matches
}

// globBaseDir returns the deepest leading run of non-glob path segments,
// i.e. the directory a wildcard pattern is anchored at. "/tmp/*.log" -> "/tmp".
// An empty result (glob in the first segment) collapses to "/".
func globBaseDir(pattern string) string {
	var b []string
	for _, seg := range strings.Split(pattern, "/") {
		if containsGlobChars(seg) {
			break
		}
		b = append(b, seg)
	}
	base := strings.Join(b, "/")
	if base == "" {
		return "/"
	}
	return base
}

// resolveTokens returns just the resolved paths. Retained for callers/tests
// that do not need provenance.
func resolveTokens(tokens []string, passwdPath string) []string {
	rts := resolveTargets(tokens, passwdPath)
	paths := make([]string, len(rts))
	for i, rt := range rts {
		paths[i] = rt.path
	}
	return paths
}

func containsGlobChars(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// parseFileSize parses a UAC size string (e.g. "10MB", "500k", "2g") to bytes.
// Returns 0 for empty string (no limit).
func parseFileSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	lower := strings.ToLower(strings.TrimSpace(s))
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"tb", 1 << 40}, {"gb", 1 << 30}, {"mb", 1 << 20}, {"kb", 1 << 10},
		{"t", 1 << 40}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10},
		{"b", 1}, {"c", 1},
	}
	for _, u := range suffixes {
		if strings.HasSuffix(lower, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q", s)
			}
			if n < 0 {
				return 0, fmt.Errorf("invalid size %q: must not be negative", s)
			}
			return n * u.mult, nil
		}
	}
	n, err := strconv.ParseInt(lower, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unrecognized size format %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return n, nil
}

// entryNameForPath builds the zip entry name for a collected path.
// When outputDir is empty, absPath is mirrored under sseRootDir.
// When outputDir is set, rel (the base name or relative sub-path) is placed under outputDir.
func entryNameForPath(absPath, rel, outputDir string) string {
	var sub string
	if outputDir != "" {
		sub = path.Join(strings.TrimPrefix(filepath.ToSlash(outputDir), "/"), filepath.ToSlash(rel))
	} else {
		sub = strings.TrimPrefix(filepath.ToSlash(absPath), "/")
	}
	return sseRootDir + "/" + sanitizeEntrySub(sub)
}

// sanitizeEntrySub guarantees the returned sub-path can never escape the
// archive root: anchoring at "/" before path.Clean collapses any leading or
// embedded ".." (you cannot ascend above root), then the leading slash is
// stripped. Slash-based path.Clean is used (not filepath.Clean) so entry names
// are identical regardless of host OS.
func sanitizeEntrySub(p string) string {
	cleaned := path.Clean("/" + p)
	return strings.TrimPrefix(cleaned, "/")
}
