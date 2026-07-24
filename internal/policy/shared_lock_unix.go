//go:build darwin || linux

package policy

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openSharedPolicyFile(path string) (*os.File, error) {
	fd, err := unix.Open(
		path,
		unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_RDONLY,
		0,
	)
	if errors.Is(err, unix.ELOOP) {
		return nil, errors.New("symbolic-link policies are not allowed")
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
