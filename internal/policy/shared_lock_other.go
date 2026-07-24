//go:build !darwin && !linux

package policy

import (
	"errors"
	"os"
)

func openSharedPolicyFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePolicyFileInfo(before); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, openErr := file.Stat()
	after, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil {
		return nil, errors.Join(openErr, pathErr, file.Close())
	}
	if err := validatePolicyFileInfo(opened); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := validatePolicyFileInfo(after); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.Join(
			errors.New("policy file changed while opening"),
			file.Close(),
		)
	}
	return file, nil
}
