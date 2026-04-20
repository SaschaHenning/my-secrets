package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/spf13/cobra"
)

// bwExportCmd builds the `mys bw-export` subcommand.
func bwExportCmd(requester *string) *cobra.Command {
	var (
		org     string
		out     string
		reveal  bool
		confirm bool
	)
	c := &cobra.Command{
		Use:   "bw-export",
		Short: "Export entries as Bitwarden-compatible JSON (one-way, PLAINTEXT)",
		Long: `Exports every secret in the selected org to a Bitwarden-compatible JSON file.
The output is PLAINTEXT — do not leave it on disk.

Requires --reveal AND --i-understand to run. AI callers cannot invoke this
command; it is rejected for actor_kind=ai.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if !reveal || !confirm {
				return fmt.Errorf("bw-export requires both --reveal and --i-understand; refusing")
			}
			// Deny AI-flagged callers outright.
			detected := caller.Identify(*requester)
			if detected.Kind == caller.KindAI {
				return fmt.Errorf("bw-export is refused for AI callers")
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
			items := make([]map[string]any, 0, len(paths))
			for _, p := range paths {
				e, err := a.Get(ctx, p)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "skip %s: %v\n", p, err)
					continue
				}
				items = append(items, map[string]any{
					"name":  p,
					"notes": e.Notes,
					"login": map[string]any{
						"username": e.Username,
						"password": e.Password,
						"uris": []map[string]any{
							{"uri": e.URL},
						},
					},
					"folderId": e.Org,
				})
			}
			payload := map[string]any{
				"encrypted": false,
				"folders":   []map[string]any{},
				"items":     items,
			}
			if out == "" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
			}
			// 0o600 — file must not be world- or group-readable.
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(payload)
		},
	}
	c.Flags().StringVar(&org, "org", "", "filter by org")
	c.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	c.Flags().BoolVar(&reveal, "reveal", false, "REQUIRED — acknowledge that output contains plaintext passwords")
	c.Flags().BoolVar(&confirm, "i-understand", false, "REQUIRED — confirm you understand plaintext will be written")
	return c
}
