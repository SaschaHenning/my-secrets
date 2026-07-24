//go:build darwin

package lockanchor

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func validateAnchorFilesystem(anchor *os.File) (string, error) {
	if anchor == nil {
		return "", errors.New("stable lock anchor is nil")
	}
	var state unix.Statfs_t
	if err := unix.Fstatfs(int(anchor.Fd()), &state); err != nil {
		return "", fmt.Errorf("inspect stable lock anchor filesystem: %w", err)
	}
	name := darwinFilesystemName(state.Fstypename)
	if state.Flags&unix.MNT_LOCAL == 0 {
		return "", fmt.Errorf(
			"non-local %s home filesystem cannot be a lock anchor",
			name,
		)
	}
	return name, nil
}

func darwinFilesystemName(value [16]byte) string {
	raw := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		raw = append(raw, character)
	}
	if name := strings.TrimSpace(string(raw)); name != "" {
		return name
	}
	return "unknown"
}
