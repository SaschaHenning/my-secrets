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
			web.Version = Version
			// The web UI now browses/decrypts entries (see internal/web's
			// /entries routes), so it needs store access, not just the
			// audit DB. Override is forced to "human": mys web is always
			// local + Touch-ID-gated, and caller.Identify only accepts
			// this override when there is no AI signal in the process's
			// env/parent chain — deliberately never start `mys web` from
			// inside an agent session, or its calls will classify as AI.
			a, err := app.Open(ctx, "human")
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return web.Serve(ctx, a, port, cmd.OutOrStdout())
		},
	}
	c.Flags().IntVar(&port, "port", 7823, "listen port")
	c.AddCommand(webInstallCmd(), webUninstallCmd(), webStatusCmd())
	return c
}
