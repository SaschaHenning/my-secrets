//go:build !darwin && !linux

package lockanchor

import (
	"errors"
	"os"
)

func openAnchor() (*os.File, string, error) {
	return nil, "", errors.New(
		"secure cross-process locking is unsupported on this platform",
	)
}

func validateLockedAnchor(_ *os.File, _ string) error {
	return errors.New(
		"secure cross-process locking is unsupported on this platform",
	)
}

func tryLock(_ *os.File) (bool, error) {
	return false, errors.New(
		"secure cross-process locking is unsupported on this platform",
	)
}

func unlock(_ *os.File) error {
	return nil
}
