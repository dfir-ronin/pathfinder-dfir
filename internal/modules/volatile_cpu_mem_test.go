//go:build linux

package modules

import "testing"

func TestCPUMemSuppressedProcs_KnownHeavyProcessSuppressed(t *testing.T) {
	for _, name := range []string{"mysqld", "postgres", "java", "node", "python3", "ffmpeg", "make", "gcc", "cc1", "bazel", "cargo"} {
		if !cpuMemSuppressedProcs[name] {
			t.Errorf("%q should be in cpuMemSuppressedProcs", name)
		}
	}
}

func TestCPUMemSuppressedProcs_CommonProcessNotSuppressed(t *testing.T) {
	for _, name := range []string{"sshd", "wget", "curl", "bash"} {
		if cpuMemSuppressedProcs[name] {
			t.Errorf("%q must not be in cpuMemSuppressedProcs", name)
		}
	}
}
