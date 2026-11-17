// Package gopassutil contains output helpers for gopass subprocess calls.
package gopassutil

import "strings"

// StripGopassBanner removes gopass's informational git-command prefix while
// keeping trimmed payload lines in their original order.
func StripGopassBanner(out string) []string {
	lines := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Running '") && strings.Contains(line, "' in ") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
