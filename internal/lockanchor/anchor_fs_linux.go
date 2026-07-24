//go:build linux

package lockanchor

import (
	"errors"
	"fmt"
	"os"

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
	filesystemType := uint64(uint32(state.Type))
	// Linux exposes no generic ST_LOCAL equivalent. We can reject the stable
	// NFS and CIFS/SMB magic values, but cannot portably classify every network
	// or userspace filesystem. Deployments must therefore keep the account home
	// on a known-local filesystem; unknown types are an explicit platform
	// caveat rather than evidence that the filesystem is local.
	if err := rejectKnownLinuxNetworkFilesystem(filesystemType); err != nil {
		return "", err
	}
	return fmt.Sprintf("linux type %#x", filesystemType), nil
}
