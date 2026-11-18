//go:build darwin || linux

package lockanchor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// holderSeq makes one registry file per lease, so parallel leases of one
// process do not delete each other's record.
var holderSeq atomic.Uint64

// registerHolder records this PID while it holds the kernel lock. flock has
// no portable owner query, so waiters read this registry to name the holder.
// Best effort: a failure only makes the wait notice less specific.
func registerHolder(shared bool) func() {
	dir := holderDir()
	if dir == "" || os.MkdirAll(dir, 0o700) != nil || !privateDirectory(dir) {
		return func() {}
	}
	mode := "exclusive"
	if shared {
		mode = "shared"
	}
	path := filepath.Join(dir, fmt.Sprintf("%d-%d", os.Getpid(), holderSeq.Add(1)))
	// O_EXCL|O_NOFOLLOW: a planted symlink must not redirect the write.
	fd, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return func() {}
	}
	file := os.NewFile(uintptr(fd), path)
	_, writeErr := fmt.Fprintf(file, "%s %s\n", mode, time.Now().UTC().Format(time.RFC3339))
	if closeErr := file.Close(); writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return func() {}
	}
	return func() { _ = os.Remove(path) }
}

// privateDirectory accepts only a real directory owned by this user and
// closed to group and others, so another account cannot feed fake holders.
func privateDirectory(dir string) bool {
	var state unix.Stat_t
	if unix.Lstat(dir, &state) != nil {
		return false
	}
	return state.Mode&unix.S_IFMT == unix.S_IFDIR &&
		int(state.Uid) == unix.Geteuid() &&
		state.Mode&0o077 == 0
}

// holders lists live PIDs from the registry and prunes entries of dead ones.
func holders() []int {
	dir := holderDir()
	if dir == "" || !privateDirectory(dir) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	seen := make(map[int]struct{})
	var live []int
	for _, entry := range entries {
		pidText, _, _ := strings.Cut(entry.Name(), "-")
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid <= 0 {
			continue
		}
		if pid != self && !processAlive(pid) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
			continue
		}
		if _, duplicate := seen[pid]; duplicate {
			continue
		}
		seen[pid] = struct{}{}
		live = append(live, pid)
	}
	sort.Ints(live)
	return live
}

func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}
