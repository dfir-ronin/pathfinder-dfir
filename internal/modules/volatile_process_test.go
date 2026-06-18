//go:build linux

package modules

import (
	"os"
	"testing"

	"github.com/pathfinder/internal/procfs"
)

func TestIsOwnProcess_MatchesSelfPath(t *testing.T) {
	p := &procfs.Process{Exe: "/root/Downloads/pathfinder_v1.53.3"}
	if !isOwnProcess(p, "/root/Downloads/pathfinder_v1.53.3") {
		t.Error("process with exe matching selfPath should be own process")
	}
}

func TestIsOwnProcess_DifferentPath(t *testing.T) {
	p := &procfs.Process{Exe: "/tmp/evil"}
	if isOwnProcess(p, "/root/Downloads/pathfinder_v1.53.3") {
		t.Error("process with different exe should not match")
	}
}

func TestIsOwnProcess_EmptySelfPath(t *testing.T) {
	p := &procfs.Process{Exe: "/tmp/evil"}
	if isOwnProcess(p, "") {
		t.Error("empty selfPath must never match")
	}
}

func TestIsOwnProcess_EmptyExe(t *testing.T) {
	p := &procfs.Process{Exe: ""}
	if isOwnProcess(p, "/root/Downloads/pathfinder_v1.53.3") {
		t.Error("empty exe must never match")
	}
}

func TestShouldSkipPID_OwnProcess(t *testing.T) {
	if !shouldSkipPID(os.Getpid()) {
		t.Error("own PID must be skipped")
	}
}

func TestShouldSkipPID_ForeignPID(t *testing.T) {
	if shouldSkipPID(1) {
		t.Error("PID 1 must not be skipped")
	}
}
