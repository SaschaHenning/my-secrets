package main

import (
	"context"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/web"
	"github.com/spf13/cobra"
)

// webCmd builds the `mys web` subcommand.
func webCmd() *cobra.Command {
	var port int
	c := &cobra.Command{
		Use:   "web",
		Short: "Start the localhost web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.OpenAuditOnly()
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return web.Serve(ctx, a, port, cmd.OutOrStdout())
		},
	}
	c.Flags().IntVar(&port, "port", 7823, "listen port")
	return c
}
