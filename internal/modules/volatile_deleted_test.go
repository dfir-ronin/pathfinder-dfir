//go:build linux

package modules

import (
	"testing"

	"github.com/pathfinder/internal/procfs"
)

func TestClassifyDeletedFDs(t *testing.T) {
	fds := []procfs.OpenFD{
		{PID: 100, FD: "3", Target: "/tmp/evil (deleted)"},
		{PID: 101, FD: "4", Target: "/dev/shm/payload (deleted)"},
		{PID: 102, FD: "5", Target: "/lib/x86_64-linux-gnu/libfoo.so.2 (deleted)"},
		{PID: 103, FD: "6", Target: "/usr/lib/systemd/libsystemd.so (deleted)"},
	}
	susp, benign := classifyDeletedFDs(fds)
	if len(susp) != 2 {
		t.Errorf("want 2 suspicious FDs, got %d", len(susp))
	}
	if len(benign) != 2 {
		t.Errorf("want 2 benign FDs, got %d", len(benign))
	}
	if susp[0].Target != "/tmp/evil (deleted)" {
		t.Errorf("unexpected first suspicious FD: %s", susp[0].Target)
	}
	if susp[1].Target != "/dev/shm/payload (deleted)" {
		t.Errorf("unexpected second suspicious FD: %s", susp[1].Target)
	}
}

func TestClassifyDeletedFDs_AllBenign(t *testing.T) {
	fds := []procfs.OpenFD{
		{PID: 1, FD: "3", Target: "/var/log/syslog (deleted)"},
	}
	susp, benign := classifyDeletedFDs(fds)
	if len(susp) != 0 {
		t.Errorf("want 0 suspicious, got %d", len(susp))
	}
	if len(benign) != 1 {
		t.Errorf("want 1 benign, got %d", len(benign))
	}
}

func TestClassifyDeletedFDs_AllSuspicious(t *testing.T) {
	fds := []procfs.OpenFD{
		{PID: 1, FD: "3", Target: "/var/tmp/malware (deleted)"},
	}
	susp, benign := classifyDeletedFDs(fds)
	if len(susp) != 1 {
		t.Errorf("want 1 suspicious, got %d", len(susp))
	}
	if len(benign) != 0 {
		t.Errorf("want 0 benign, got %d", len(benign))
	}
}
