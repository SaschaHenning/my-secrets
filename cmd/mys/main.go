// Package main is the my-secrets CLI, web UI, and MCP server entrypoint.
// All three modes share the same app-layer orchestration so every access
// ends up in the same audit log.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// Version is set via ldflags at build time. Fallback for `go run`.
var Version = "dev"

func main() {
	ensureGPGTTY()
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func ensureGPGTTY() {
	if os.Getenv("GPG_TTY") == "" {
		tty := detectControllingTTY()
		if tty == "" {
			return
		}
		_ = os.Setenv("GPG_TTY", tty)
	}
	_ = exec.Command("gpg-connect-agent", "updatestartuptty", "/bye").Run()
}

func detectControllingTTY() string {
	for _, fd := range []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()} {
		if target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd))); err == nil {
			if tty := normalizeTTY(target); tty != "" {
				return tty
			}
		}
	}

	out, err := exec.Command("ps", "-o", "tty=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return ""
	}
	return normalizeTTY(string(out))
}

func normalizeTTY(raw string) string {
	tty := strings.TrimSpace(raw)
	if tty == "" || tty == "?" || tty == "??" {
		return ""
	}
	if strings.HasPrefix(tty, "pipe:") || strings.HasPrefix(tty, "socket:") {
		return ""
	}
	if strings.HasPrefix(tty, "/dev/") {
		return tty
	}
	if strings.HasPrefix(tty, "pts/") || strings.HasPrefix(tty, "tty") {
		return "/dev/" + tty
	}
	return ""
}

func rootCmd() *cobra.Command {
	var requester string
	var noSync bool
	root := &cobra.Command{
		Use:           "mys",
		Short:         "my-secrets — local credential manager with audit log",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Mirror the flag into the app package so that App.AutoSync
			// can observe it without having to thread a parameter
			// through every call site.
			app.NoSyncFlag = noSync
		},
	}
	root.PersistentFlags().StringVar(&requester, "requester", "",
		"explicit caller label (claude-code | human | script | ai). Cannot downgrade detected AI signals.")
	root.PersistentFlags().BoolVar(&noSync, "no-sync", false,
		"skip auto-sync after add/rotate/rm (equivalent to MYS_AUTO_SYNC=0 for this invocation)")

	root.AddCommand(
		initCmd(&requester),
		lsCmd(&requester),
		searchCmd(&requester),
		getCmd(&requester),
		addCmd(&requester),
		rotateCmd(&requester),
		rmCmd(&requester),
		keyCmd(&requester),
		auditCmd(),
		webCmd(),
		mcpCmd(),
		bwExportCmd(&requester),
		syncCmd(&requester),
		recipientCmd(&requester),
		installSkillCmd(),
		doctorCmd(&requester),
		totpCmd(&requester),
	)
	return root
}
