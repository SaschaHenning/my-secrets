package main

import (
	"context"
	"fmt"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// searchCmd builds the `mys search` subcommand.
func searchCmd(requester *string) *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search secret paths and metadata",
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
			paths, err := a.Search(ctx, args[0])
			if err != nil {
				return err
			}
			for _, p := range paths {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
}
