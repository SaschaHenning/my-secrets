package main

import (
	"context"
	"os"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/mcp"
	"github.com/spf13/cobra"
)

// mcpCmd builds the `mys mcp` subcommand.
func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run as MCP server over stdio (AI tool entrypoint)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Force the AI classification regardless of env.
			a, err := app.Open(ctx, "claude-code")
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return mcp.Serve(ctx, a, os.Stdin, os.Stdout)
		},
	}
}
