//go:build linux

package modules

import (
	"strings"
	"testing"

	"github.com/pathfinder/internal/ioc"
)

// stagingPath mimics isMaliciousPathValue for test purposes: returns true for
// /tmp/, /var/tmp/, or paths containing a hidden component (e.g. /.hidden/).
func stagingPath(v string) bool {
	for _, part := range strings.Split(v, ":") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "/tmp/") ||
			strings.HasPrefix(part, "/var/tmp/") ||
			strings.Contains(part, "/.") {
			return true
		}
	}
	return false
}

func TestEnvRuleApplies_StagingPathFires(t *testing.T) {
	rule := ioc.EnvVarRule{
		Name:       "LD_PRELOAD",
		CheckValue: stagingPath,
		Severity:   ioc.Severity("HIGH"),
	}
	if !envRuleApplies(rule, "bash", "/tmp/evil.so") {
		t.Error("want staging path to trigger HIGH rule")
	}
}

func TestEnvRuleApplies_SuppressionComm_Suppresses(t *testing.T) {
	rule := ioc.EnvVarRule{
		Name:             "LD_PRELOAD",
		CheckValue:       stagingPath,
		Severity:         ioc.Severity("HIGH"),
		SuppressionComms: []string{"faketime", "valgrind"},
	}
	if envRuleApplies(rule, "faketime", "/tmp/evil.so") {
		t.Error("faketime should be suppressed")
	}
	if envRuleApplies(rule, "faketime-2.20", "/tmp/evil.so") {
		t.Error("faketime prefix match should be suppressed")
	}
}

func TestEnvRuleApplies_NonSuppressedComm_Fires(t *testing.T) {
	rule := ioc.EnvVarRule{
		Name:             "LD_PRELOAD",
		CheckValue:       stagingPath,
		Severity:         ioc.Severity("HIGH"),
		SuppressionComms: []string{"faketime"},
	}
	if !envRuleApplies(rule, "bash", "/tmp/evil.so") {
		t.Error("bash should not be suppressed")
	}
}
