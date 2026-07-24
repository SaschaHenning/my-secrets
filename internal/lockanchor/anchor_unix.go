//go:build darwin || linux

package lockanchor

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func openAnchor() (*os.File, string, error) {
	canonicalHome, effectiveUID, err := canonicalAnchorHome()
	if err != nil {
		return nil, "", err
	}
	anchor, err := openDirectory(canonicalHome)
	if err != nil {
		return nil, "", fmt.Errorf("open canonical home directory: %w", err)
	}
	if err := validateAnchor(
		anchor,
		canonicalHome,
		effectiveUID,
	); err != nil {
		return nil, "", errors.Join(err, anchor.Close())
	}
	return anchor, canonicalHome, nil
}

func validateLockedAnchor(anchor *os.File, canonicalPath string) error {
	if anchor == nil {
		return errors.New("stable lock anchor is nil")
	}
	currentHome, effectiveUID, err := canonicalAnchorHome()
	if err != nil {
		return err
	}
	if currentHome != canonicalPath {
		return errors.New(
			"canonical home directory changed while acquiring stable lock",
		)
	}
	return validateAnchor(anchor, canonicalPath, effectiveUID)
}

func canonicalAnchorHome() (string, int, error) {
	current, err := user.Current()
	if err != nil {
		return "", 0, fmt.Errorf("resolve current operating-system user: %w", err)
	}
	if current.HomeDir == "" {
		return "", 0, errors.New(
			"current operating-system user has no home directory",
		)
	}
	effectiveUID := unix.Geteuid()
	accountUID, err := strconv.Atoi(current.Uid)
	if err != nil {
		return "", 0, fmt.Errorf(
			"parse current operating-system user id %q: %w",
			current.Uid,
			err,
		)
	}
	if accountUID != effectiveUID {
		return "", 0, fmt.Errorf(
			"operating-system user id %d does not match effective user %d",
			accountUID,
			effectiveUID,
		)
	}
	absoluteHome, err := filepath.Abs(current.HomeDir)
	if err != nil {
		return "", 0, fmt.Errorf("resolve absolute home directory: %w", err)
	}
	canonicalHome, err := filepath.EvalSymlinks(absoluteHome)
	if err != nil {
		return "", 0, fmt.Errorf("resolve canonical home directory: %w", err)
	}
	canonicalHome = filepath.Clean(canonicalHome)
	if !filepath.IsAbs(canonicalHome) {
		return "", 0, errors.New("canonical home directory is not absolute")
	}
	if filepath.Dir(canonicalHome) == canonicalHome {
		return "", 0, errors.New(
			"filesystem root cannot be a stable lock anchor",
		)
	}
	return canonicalHome, effectiveUID, nil
}

func openDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(
		path,
		unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validateAnchor(
	anchor *os.File,
	canonicalPath string,
	effectiveUID int,
) (resultErr error) {
	if anchor == nil {
		return errors.New("stable lock anchor is nil")
	}
	if canonicalPath == "" ||
		!filepath.IsAbs(canonicalPath) ||
		filepath.Clean(canonicalPath) != canonicalPath {
		return errors.New("stable lock anchor path is not canonical")
	}
	resolvedPath, err := filepath.EvalSymlinks(canonicalPath)
	if err != nil {
		return fmt.Errorf("re-resolve canonical home directory: %w", err)
	}
	if filepath.Clean(resolvedPath) != canonicalPath {
		return errors.New(
			"stable lock anchor path no longer resolves canonically",
		)
	}

	parentPath := filepath.Dir(canonicalPath)
	parent, err := openDirectory(parentPath)
	if err != nil {
		return fmt.Errorf("open stable lock anchor parent: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
	}()

	var anchorState unix.Stat_t
	if err := unix.Fstat(int(anchor.Fd()), &anchorState); err != nil {
		return fmt.Errorf("inspect stable lock anchor: %w", err)
	}
	var anchorPathState unix.Stat_t
	if err := unix.Fstatat(
		int(parent.Fd()),
		filepath.Base(canonicalPath),
		&anchorPathState,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect stable lock anchor path: %w", err)
	}
	if !sameInode(anchorState, anchorPathState) {
		return errors.New(
			"stable lock anchor path no longer matches opened directory",
		)
	}

	var parentState unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &parentState); err != nil {
		return fmt.Errorf("inspect stable lock anchor parent: %w", err)
	}
	var parentPathState unix.Stat_t
	if err := unix.Lstat(parentPath, &parentPathState); err != nil {
		return fmt.Errorf("inspect stable lock anchor parent path: %w", err)
	}
	if !sameInode(parentState, parentPathState) {
		return errors.New(
			"stable lock anchor parent path no longer matches opened directory",
		)
	}
	if _, err := validateAnchorFilesystem(anchor); err != nil {
		return err
	}

	parentWritable, parentWriteKnown, err := parentWritable(parent)
	if err != nil {
		return err
	}
	return validateMetadata(metadata{
		anchorUID:        int(anchorState.Uid),
		parentUID:        int(parentState.Uid),
		effectiveUID:     effectiveUID,
		anchorMode:       directoryMode(uint32(anchorState.Mode)),
		parentMode:       directoryMode(uint32(parentState.Mode)),
		parentWritable:   parentWritable,
		parentWriteKnown: parentWriteKnown,
	})
}

func parentWritable(
	parent *os.File,
) (writable bool, known bool, err error) {
	if parent == nil {
		return false, false, errors.New("stable lock anchor parent is nil")
	}
	err = unix.Faccessat(
		int(parent.Fd()),
		".",
		unix.W_OK,
		unix.AT_EACCESS,
	)
	if err == nil {
		return true, true, nil
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return false, true, nil
	}
	return false, false, fmt.Errorf(
		"check stable lock anchor parent writability: %w",
		err,
	)
}

func sameInode(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func directoryMode(mode uint32) os.FileMode {
	permissions := os.FileMode(mode & 0o777)
	if mode&unix.S_IFMT == unix.S_IFDIR {
		return permissions | os.ModeDir
	}
	return permissions
}

func tryLock(anchor *os.File) (bool, error) {
	err := unix.Flock(int(anchor.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlock(anchor *os.File) error {
	return unix.Flock(int(anchor.Fd()), unix.LOCK_UN)
}
