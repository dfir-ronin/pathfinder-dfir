//go:build linux

package procfs

import (
	"os"
	"strings"
	"testing"
)

func selfPID() int { return os.Getpid() }

func TestMapsNonEmpty_Self(t *testing.T) {
	if !MapsNonEmpty(selfPID()) {
		t.Error("MapsNonEmpty(self) = false, want true")
	}
}

func TestMapsNonEmpty_Bogus(t *testing.T) {
	if MapsNonEmpty(1 << 30) {
		t.Error("MapsNonEmpty(nonexistent pid) = true, want false")
	}
}

func TestReadMaps_SelfHasContent(t *testing.T) {
	out, err := ReadMaps(selfPID())
	if err != nil {
		t.Fatalf("ReadMaps: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("ReadMaps(self) returned empty")
	}
}
