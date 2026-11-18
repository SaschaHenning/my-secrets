package lockanchor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
