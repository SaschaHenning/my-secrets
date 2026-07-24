//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package teamaudit

import (
	"errors"
	"os"
)

func tryAuditFileLock(_ *os.File) (bool, error) {
	return false, errors.New("team audit file locking is unavailable on this platform")
}

func unlockAuditFile(_ *os.File) error {
	return nil
}
