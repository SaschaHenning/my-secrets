package main

import (
	"context"
	"fmt"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// rmCmd builds the `mys rm` subcommand.
func rmCmd(requester *string) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <path>",
		Short: "Remove an entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			if err := a.Remove(ctx, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	}
}
