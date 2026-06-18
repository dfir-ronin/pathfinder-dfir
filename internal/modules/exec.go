package modules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// trustedToolDirs is the fixed set of absolute directories Pathfinder will run
// external tools from. On a compromised host the inherited $PATH (or a planted
// ./iptables, bpftool, crictl, nft) can point at a trojan that runs as root and
// forges evidence; resolving only against these dirs removes that vector.
var trustedToolDirs = []string{
	"/usr/bin", "/usr/sbin", "/sbin", "/bin",
	"/usr/local/bin", "/usr/local/sbin",
}

// childEnv is the minimal, sanitized environment passed to external tools so a
// hostile inherited environment cannot influence them. PATH still lists trusted
// dirs only; LC_ALL=C stabilizes tool output for parsing.
var childEnv = []string{
	"PATH=/usr/bin:/usr/sbin:/sbin:/bin:/usr/local/bin:/usr/local/sbin",
	"LC_ALL=C",
}

// resolveTool returns the absolute path of an executable named `name` found in
// one of dirs. The name must be a bare tool name (no path separator), so it
// cannot be steered to a relative or absolute location outside dirs.
func resolveTool(name string, dirs []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("tool name must not contain a path separator: %q", name)
	}
	for _, dir := range dirs {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate) // follows symlinks; system tools are often symlinked
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue // not executable
		}
		return candidate, nil
	}
	return "", fmt.Errorf("tool not found in trusted dirs: %s", name)
}

// execWithTimeout runs cmd with args and a deadline, returning combined
// stdout+stderr. The tool is resolved against trustedToolDirs and run with a
// sanitized environment. Returns an error if the tool is not found or the
// timeout expires.
func execWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	path, err := resolveTool(name, trustedToolDirs)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = childEnv
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return buf.String(), fmt.Errorf("timeout after %v", timeout)
		}
		// Non-zero exit is normal for tools like rpm -Va; return output with exit annotation.
		if exitErr, ok := err.(*exec.ExitError); ok {
			return buf.String() + fmt.Sprintf("\n[exit %d]", exitErr.ExitCode()), nil
		}
		return buf.String(), nil
	}
	return buf.String(), nil
}
