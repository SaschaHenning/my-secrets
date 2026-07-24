//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package sync

import (
	"fmt"
	"os"
)

func tryLockFile(_ *os.File) (bool, error) {
	return false, fmt.Errorf("cross-process mount locking is unsupported on this platform")
}

func unlockFile(_ *os.File) error {
	return nil
}
