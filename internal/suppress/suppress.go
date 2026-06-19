package suppress

import (
	"embed"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yaml
var profileFS embed.FS

// SuppressRule is a single suppression rule from a profile or user config.
// All non-empty fields must match (AND logic). process_in and path_in use OR logic internally.
// Suppress nil means true; *false cancels a matching profile rule.
type SuppressRule struct {
	Suppress        *bool    `yaml:"suppress"`
	Module          string   `yaml:"module"`
	RuleID          string   `yaml:"rule_id"`
	MessageContains string   `yaml:"message_contains"`
	PathIn          []string `yaml:"path_in"`
	PathGlob        string   `yaml:"path_glob"`
	ProcessIn       []string `yaml:"process_in"` // entries ending in "-" are prefix-matched
	Reason          string   `yaml:"reason"`
	source          string   // "profile" or "user"
}

// Engine applies suppression rules to findings.
type Engine struct {
	rules        []SuppressRule
	profileCount atomic.Int64
	userCount    atomic.Int64
}

type profileFile struct {
	Suppress []SuppressRule `yaml:"suppress"`
}

// New builds an Engine from the universal profile + the named distro profile + optional user rules.
// distro must be "", "ubuntu", or "rhel". Unknown names load universal only.
func New(distro string, userRules []SuppressRule) (*Engine, error) {
	var rules []SuppressRule

	load := func(name string) error {
		data, err := profileFS.ReadFile("profiles/" + name + ".yaml")
		if err != nil {
			return err
		}
		var pf profileFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			return err
		}
		for i := range pf.Suppress {
			pf.Suppress[i].source = "profile"
		}
		rules = append(rules, pf.Suppress...)
		return nil
	}

	if err := load("universal"); err != nil {
		return nil, err
	}
	if distro == "ubuntu" || distro == "rhel" || distro == "debian" {
		_ = load(distro) // distro profile missing is not fatal
	}

	for i := range userRules {
		userRules[i].source = "user"
	}
	rules = append(rules, userRules...)

	return &Engine{rules: rules}, nil
}

// LoadUserRules parses a YAML file containing a top-level "suppress:" list.
func LoadUserRules(path string) ([]SuppressRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf profileFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	return pf.Suppress, nil
}

// Check reports whether a finding should be suppressed and which source matched ("profile" or "user").
// It is safe to call from multiple goroutines.
func (e *Engine) Check(module, label, msg string) (bool, string) {
	f := finding{
		module:  module,
		ruleID:  label,
		message: msg,
		path:    extractPath(msg),
		process: extractProcess(msg),
	}
	var firstMatch *SuppressRule
	for i := range e.rules {
		r := &e.rules[i]
		if !r.matchesFinding(f) {
			continue
		}
		if r.Suppress != nil && !*r.Suppress {
			return false, "" // user cancel wins immediately
		}
		if firstMatch == nil {
			firstMatch = r
		}
	}
	if firstMatch == nil {
		return false, ""
	}
	if firstMatch.source == "profile" {
		e.profileCount.Add(1)
	} else {
		e.userCount.Add(1)
	}
	return true, firstMatch.source
}

// Counts returns the number of findings suppressed by profile and user rules respectively.
func (e *Engine) Counts() (profile, user int) {
	return int(e.profileCount.Load()), int(e.userCount.Load())
}

// finding is the internal representation used for rule matching.
type finding struct {
	module  string
	ruleID  string
	message string
	path    string
	process string
}

func (r *SuppressRule) matchesFinding(f finding) bool {
	if r.Module != "" && r.Module != f.module {
		return false
	}
	if r.RuleID != "" && r.RuleID != f.ruleID {
		return false
	}
	if r.MessageContains != "" && !strings.Contains(f.message, r.MessageContains) {
		return false
	}
	if len(r.PathIn) > 0 {
		found := false
		for _, p := range r.PathIn {
			if p == f.path {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.PathGlob != "" && !matchGlob(r.PathGlob, f.path) {
		return false
	}
	if len(r.ProcessIn) > 0 && !matchesAny(r.ProcessIn, f.process) {
		return false
	}
	return true
}

// extractPath returns the file path embedded in a finding message.
//
// Handles three formats:
//   - deepscan/persist string-hunt: "... /path (line N) — ...": last slash-prefixed token before "(line"
//   - bodyfile/persist-unit: "label: /path": path after ": /", trimmed at a " — reason" suffix or first space
//   - fallback: "label in /path": everything after " in /"
func extractPath(msg string) string {
	// "... /path (line N) — ..." (deepscan string hunt, persist MotD scan)
	if i := strings.Index(msg, " (line "); i >= 0 {
		prefix := msg[:i]
		if j := strings.LastIndex(prefix, " "); j >= 0 {
			if candidate := prefix[j+1:]; strings.HasPrefix(candidate, "/") {
				return candidate
			}
		}
	}
	// "label: /path" (bodyfile, persist unit findings). Cut a trailing reason suffix
	// (" — reason") or, failing that, at the first space, so the path is not over-captured.
	if i := strings.Index(msg, ": /"); i >= 0 {
		rest := msg[i+2:]
		if j := strings.Index(rest, " — "); j >= 0 {
			return rest[:j]
		}
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	// "label in /path" (fallback)
	if i := strings.Index(msg, " in /"); i >= 0 {
		return msg[i+4:]
	}
	return ""
}

// extractProcess returns the process comm from "PID NNN (comm)" in a finding message.
func extractProcess(msg string) string {
	i := strings.Index(msg, " (")
	if i < 0 {
		return ""
	}
	j := strings.Index(msg[i:], ")")
	if j < 0 {
		return ""
	}
	return msg[i+2 : i+j]
}

// matchesAny checks whether s matches any entry in list.
// Entries ending in "-" are treated as prefixes.
func matchesAny(list []string, s string) bool {
	for _, item := range list {
		if strings.HasSuffix(item, "-") {
			prefix := strings.TrimSuffix(item, "-")
			if strings.HasPrefix(s, prefix) {
				return true
			}
		} else if item == s {
			return true
		}
	}
	return false
}

// matchGlob matches p against pattern using path.Match semantics (always forward slashes),
// with added support for ** to match any number of path segments.
func matchGlob(pattern, p string) bool {
	if !strings.Contains(pattern, "**") {
		ok, _ := path.Match(pattern, p)
		return ok
	}
	return matchDoubleGlob(strings.Split(pattern, "/"), strings.Split(p, "/"), 0, 0)
}

func matchDoubleGlob(pat, parts []string, pi, ri int) bool {
	for pi < len(pat) {
		if pat[pi] == "**" {
			for skip := ri + 1; skip <= len(parts); skip++ {
				if matchDoubleGlob(pat, parts, pi+1, skip) {
					return true
				}
			}
			return false
		}
		if ri >= len(parts) {
			return false
		}
		ok, _ := path.Match(pat[pi], parts[ri])
		if !ok {
			return false
		}
		pi++
		ri++
	}
	return ri == len(parts)
}
