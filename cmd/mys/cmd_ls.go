package main

import (
	"context"
	"fmt"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// lsCmd builds the `mys ls` subcommand.
func lsCmd(requester *string) *cobra.Command {
	var (
		org string
		tag string
	)
	c := &cobra.Command{
		Use:   "ls",
		Short: "List secret paths",
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
			paths, err := a.List(ctx, org)
			if err != nil {
				return err
			}
			// Optional tag filter requires decrypting each entry's metadata.
			if tag != "" {
				filtered := make([]string, 0, len(paths))
				for _, p := range paths {
					e, err := a.Get(ctx, p)
					if err != nil {
						continue
					}
					for _, t := range e.Tags {
						if t == tag {
							filtered = append(filtered, p)
							break
						}
					}
				}
				paths = filtered
			}
			for _, p := range paths {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
	c.Flags().StringVar(&org, "org", "", "filter by org (top-level folder)")
	c.Flags().StringVar(&tag, "tag", "", "filter by tag (exact match); requires decrypting entries")
	return c
}
