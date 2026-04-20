package main

import (
	"context"
	"fmt"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// rotateCmd builds the `mys rotate` subcommand.
func rotateCmd(requester *string) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <path>",
		Short: "Rotate password (reads new password from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			pw, err := readPasswordStdin(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			if err := a.Rotate(ctx, args[0], pw); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotated %s\n", args[0])
			return nil
		},
	}
}
