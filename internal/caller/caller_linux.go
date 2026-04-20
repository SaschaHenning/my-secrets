//go:build linux

package caller

import (
	"os"
	"strconv"
	"strings"
)

// processInfo parses /proc/<pid>/stat for the process name (field 2, in
// parentheses, may contain spaces) and ppid (field 4). One file read per
// hop, no subprocess spawn.
//
// The `comm` field is bracketed and can contain whitespace and closing
// parentheses, so we locate the first '(' and the LAST ')' rather than
// splitting on spaces.
func processInfo(pid int) (name string, ppid int, ok bool) {
	if pid <= 0 {
		return "", 0, false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, false
	}
	s := string(data)
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp < 0 || rp < 0 || rp <= lp {
		return "", 0, false
	}
	comm := s[lp+1 : rp]
	// Fields after comm are space-separated: state, ppid, pgrp, ...
	// We want field index 1 (0 = state) after the trailing ')'.
	rest := strings.TrimLeft(s[rp+1:], " ")
	parts := strings.SplitN(rest, " ", 4)
	if len(parts) < 3 {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, false
	}
	return comm, n, true
}
