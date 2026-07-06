package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// openAuditOnly is swapped out in tests so refused-attempt audit rows
// do not land in the developer's real audit DB.
var openAuditOnly = app.OpenAuditOnly

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

Items are grouped into "mys/<org>" folders so an import never mixes with the
rest of the vault. TOTP entries are exported as otpauth URIs in login.totp.

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
			// Deny AI-flagged callers outright — and leave a forensic
			// trace: a refused bulk-export attempt is exactly the kind
			// of event the audit log exists for.
			detected := caller.Identify(*requester)
			if detected.Kind == caller.KindAI {
				if aa, aerr := openAuditOnly(); aerr == nil {
					aa.Override = *requester
					aa.AuditExport(ctx, org, audit.ResultDenied, "bw-export refused for AI caller")
					_ = aa.Close(ctx)
				}
				return fmt.Errorf("bw-export is refused for AI callers")
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return runBwExport(ctx, a, cmd.OutOrStdout(), cmd.ErrOrStderr(), org, out)
		},
	}
	c.Flags().StringVar(&org, "org", "", "filter by org")
	c.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	c.Flags().BoolVar(&reveal, "reveal", false, "REQUIRED — acknowledge that output contains plaintext passwords")
	c.Flags().BoolVar(&confirm, "i-understand", false, "REQUIRED — confirm you understand plaintext will be written")
	return c
}

// runBwExport lists, decrypts and maps the entries, then encodes the
// Bitwarden payload to stdout or a 0600 file. Split from RunE so tests
// can drive it against a fake store.
func runBwExport(ctx context.Context, a *app.App, stdout, stderr io.Writer, org, out string) error {
	paths, err := a.List(ctx, org)
	if err != nil {
		return err
	}
	entries := make([]*store.Entry, 0, len(paths))
	for _, p := range paths {
		e, err := a.Get(ctx, p)
		if err != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", p, err)
			continue
		}
		entries = append(entries, e)
	}
	payload, err := bw.BuildExport(entries)
	if err != nil {
		return err
	}
	dest := out
	if dest == "" {
		dest = "stdout"
	}
	if err := writeExport(payload, stdout, out); err != nil {
		return err
	}
	a.AuditExport(ctx, org, audit.ResultOK, fmt.Sprintf("dest=%s count=%d", dest, len(entries)))
	return nil
}

func writeExport(payload bw.Export, stdout io.Writer, out string) error {
	if out == "" {
		return json.NewEncoder(stdout).Encode(payload)
	}
	// 0o600 — file must not be world- or group-readable.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// OpenFile only applies the mode to newly created files; force it
	// so re-exporting over an existing 0644 file cannot stay readable.
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
