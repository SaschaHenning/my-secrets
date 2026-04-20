//go:build !darwin && !linux

package caller

import (
	"os/exec"
	"strconv"
	"strings"
)

// processInfo falls back to ps(1) on platforms we have not yet written a
// native implementation for. This path spawns two subprocesses per hop;
// mys is primarily a macOS tool, so the slow fallback is acceptable here.
func processInfo(pid int) (name string, ppid int, ok bool) {
	if pid <= 0 {
		return "", 0, false
	}
	out, err := exec.Command("ps", "-o", "comm=,ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", 0, false
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", 0, false
	}
	// ps prints "<comm> <ppid>"; the last whitespace-separated token is ppid.
	idx := strings.LastIndexAny(line, " \t")
	if idx < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(line[:idx]), n, true
}
