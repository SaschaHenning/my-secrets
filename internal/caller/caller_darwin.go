//go:build darwin

package caller

import (
	"bytes"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// processInfo looks up a process's command name and parent PID on macOS
// without spawning any subprocesses. Before this change parentChain fired
// two ps(1) calls per hop (up to 24 subprocesses per mys invocation); the
// native path does one sysctl per hop and returns in single-digit ms.
//
// The name is resolved in two steps:
//  1. kern.procargs2 — returns the full executable path argv[0] would show.
//     This matches `ps -o comm=` for GUI apps (e.g. "claude" instead of
//     node's internal p_comm value "2.1.114"), so classify() keeps working.
//  2. kern.proc.pid kinfo_proc.p_comm — 16-byte truncated fallback used
//     when procargs2 is unavailable (permission denied, short-lived pid,
//     kernel-only tasks like launchd).
//
// The parent PID is always taken from kinfo_proc.eproc.e_ppid; procargs2
// does not include it.
func processInfo(pid int) (name string, ppid int, ok bool) {
	if pid <= 0 {
		return "", 0, false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return "", 0, false
	}
	ppid = int(kp.Eproc.Ppid)

	// Prefer procargs2 — it gives the executable name users recognise.
	// Skip pid 1 and other restricted pids where the kernel returns EINVAL.
	if n := procargs2Name(pid); n != "" {
		return n, ppid, true
	}

	// Fallback: p_comm (MAXCOMLEN = 16 chars, then a terminating null).
	comm := kp.Proc.P_comm[:]
	for i, b := range comm {
		if b == 0 {
			comm = comm[:i]
			break
		}
	}
	return string(comm), ppid, true
}

// procargs2Name reads kern.procargs2 for pid and returns the basename of
// the executable path. Returns "" if the sysctl fails or the buffer is
// malformed — callers fall back to p_comm in that case.
//
// Layout (see xnu bsd/kern/kern_sysctl.c):
//
//	uint32_t argc
//	char executable_path[]      // NUL-terminated, full path
//	char padding[]              // zero-byte padding to alignment
//	char argv[0][], argv[1][]   // NUL-terminated arg strings
//	char envp[0][], ...
func procargs2Name(pid int) string {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(data) < 4 {
		return ""
	}
	// Skip the 4-byte argc; the next non-empty NUL-terminated string is
	// the executable path.
	rest := data[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return ""
	}
	return filepath.Base(string(rest[:end]))
}
