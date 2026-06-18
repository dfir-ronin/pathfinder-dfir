package modules

import (
	"testing"

	"github.com/pathfinder/internal/output"
)

func TestVolatileKmsgLines_WriteUser(t *testing.T) {
	lines := []string{
		"6,1234,5678,-;bpf_probe_write_user: process evil (pid 999) attempted to write to user memory",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].label != "BPF write-to-userspace helper" {
		t.Errorf("want label %q, got %q", "BPF write-to-userspace helper", hits[0].label)
	}
	if hits[0].severity != output.HIGH {
		t.Errorf("want HIGH, got %v", hits[0].severity)
	}
	if hits[0].line != "bpf_probe_write_user: process evil (pid 999) attempted to write to user memory" {
		t.Errorf("want message after semicolon, got %q", hits[0].line)
	}
}

func TestVolatileKmsgLines_OverrideReturn(t *testing.T) {
	lines := []string{
		"6,1234,5678,-;bpf_override_return: process foo (pid 123)",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].label != "BPF override-return helper" {
		t.Errorf("want label %q, got %q", "BPF override-return helper", hits[0].label)
	}
	if hits[0].severity != output.HIGH {
		t.Errorf("want HIGH, got %v", hits[0].severity)
	}
}

func TestVolatileKmsgLines_VerifierFailure(t *testing.T) {
	lines := []string{
		"4,5678,9999,-;BPF: invalid indirect read from stack R0",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].label != "BPF verifier failure" {
		t.Errorf("want label %q, got %q", "BPF verifier failure", hits[0].label)
	}
	if hits[0].severity != output.INFO {
		t.Errorf("want INFO, got %v", hits[0].severity)
	}
}

func TestVolatileKmsgLines_NoMatch(t *testing.T) {
	lines := []string{
		"6,1,2,-;Normal kernel message about USB device",
		"6,2,3,-;EXT4-fs: mounted filesystem",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 0 {
		t.Fatalf("want 0 hits, got %d", len(hits))
	}
}

func TestVolatileKmsgLines_NoSemicolon(t *testing.T) {
	// Malformed record with no semicolon: full line is treated as message.
	lines := []string{
		"bpf_probe_write_user: something happened",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].label != "BPF write-to-userspace helper" {
		t.Errorf("want write-user label, got %q", hits[0].label)
	}
}

func TestVolatileKmsgLines_WriteUserTakesPriorityOverVerifier(t *testing.T) {
	// Line contains both bpf_probe_write_user and "fail"; write-user must win.
	lines := []string{
		"6,1,2,-;bpf_probe_write_user: failed to write to address",
	}
	hits := volatileKmsgLines(lines)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].label != "BPF write-to-userspace helper" {
		t.Errorf("write-user should take priority over verifier, got %q", hits[0].label)
	}
}
