package report

import (
	"strings"
	"testing"
)

func TestMaliciousUdevCardMentionsImport(t *testing.T) {
	d, ok := Detections["Malicious udev RUN command"]
	if !ok {
		t.Fatal("Detections missing 'Malicious udev RUN command' entry")
	}
	if !strings.Contains(d.WhyFlagged, "IMPORT{program}") {
		t.Errorf("WhyFlagged should mention IMPORT{program}, got: %s", d.WhyFlagged)
	}
	if !strings.Contains(d.NextSteps, "IMPORT{program}") {
		t.Errorf("NextSteps should mention IMPORT{program}, got: %s", d.NextSteps)
	}
}
