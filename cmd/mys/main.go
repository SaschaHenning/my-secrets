// Package main is the my-secrets CLI, web UI, and MCP server entrypoint.
// All three modes share the same app-layer orchestration so every access
// ends up in the same audit log.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set via ldflags at build time. Fallback for `go run`.
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var requester string
	root := &cobra.Command{
		Use:           "mys",
		Short:         "my-secrets — local credential manager with audit log",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	root.PersistentFlags().StringVar(&requester, "requester", "",
		"explicit caller label (claude-code | human | script | ai). Cannot downgrade detected AI signals.")

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
	)
	return root
}
