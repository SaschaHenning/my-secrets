package lockanchor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultWaitTimeout = 2 * time.Minute

	// WaitTimeoutEnv overrides the bounded lock wait (Go duration, e.g. "5m").
	WaitTimeoutEnv = "MYS_LOCK_WAIT_TIMEOUT"
)

// Package hooks so tests can redirect the holder registry and the notice.
var (
	holderDir                 = defaultHolderDir
	waitNoticeDelay           = 3 * time.Second
	noticeOutput    io.Writer = os.Stderr
)

func waitTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv(WaitTimeoutEnv)); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultWaitTimeout
}

func defaultHolderDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "mys", "lock-holders")
}

// registerHolder records this PID while it holds the kernel lock. flock has
// no portable owner query, so waiters read this registry to name the holder.
// Best effort: a failure only makes the wait notice less specific.
func registerHolder(shared bool) func() {
	dir := holderDir()
	if dir == "" || os.MkdirAll(dir, 0o700) != nil {
		return func() {}
	}
	mode := "exclusive"
	if shared {
		mode = "shared"
	}
	path := filepath.Join(dir, strconv.Itoa(os.Getpid()))
	content := fmt.Sprintf("%s %s\n", mode, time.Now().UTC().Format(time.RFC3339))
	if os.WriteFile(path, []byte(content), 0o600) != nil {
		return func() {}
	}
	return func() { _ = os.Remove(path) }
}

// holders lists live PIDs from the registry and prunes entries of dead ones.
func holders() []int {
	dir := holderDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var live []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if pid != self && !processAlive(pid) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
			continue
		}
		live = append(live, pid)
	}
	sort.Ints(live)
	return live
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || err == syscall.EPERM
}

func describeHolders() string {
	pids := holders()
	if len(pids) == 0 {
		return "holder unknown"
	}
	parts := make([]string, len(pids))
	for i, pid := range pids {
		parts[i] = strconv.Itoa(pid)
	}
	return "held by PID " + strings.Join(parts, ", ")
}

func printWaitNotice() {
	pids := holders()
	who := "unbekannter Prozess"
	if len(pids) > 0 {
		parts := make([]string, len(pids))
		for i, pid := range pids {
			parts[i] = strconv.Itoa(pid)
		}
		who = "PID " + strings.Join(parts, ", ")
	}
	_, _ = fmt.Fprintf(
		noticeOutput,
		"mys: warte auf die Sperre, gehalten von %s (Abbruch nach %s, %s setzt das Limit)\n",
		who,
		waitTimeout(),
		WaitTimeoutEnv,
	)
}
