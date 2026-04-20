package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/spf13/cobra"
)

// auditCmd builds the `mys audit` subcommand tree.
func auditCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "audit",
		Short: "Audit log commands",
	}

	var (
		tailActor  string
		tailAction string
		tailOrg    string
		tailLimit  int
	)
	tail := &cobra.Command{
		Use:   "tail",
		Short: "Show recent audit entries",
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
			entries, err := a.Audit.Tail(ctx, audit.Filter{
				Actor: tailActor, Action: tailAction, Org: tailOrg, Limit: tailLimit,
			})
			if err != nil {
				return err
			}
			for _, e := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "#%d %s %s %s path=%s org=%s result=%s reason=%s\n",
					e.Seq, e.TS.Format("2006-01-02 15:04:05"), e.ActorKind, e.Action,
					e.SecretPath, e.Org, e.Result, e.Reason)
			}
			return nil
		},
	}
	tail.Flags().StringVar(&tailActor, "actor", "", "filter actor_kind (human|ai|script)")
	tail.Flags().StringVar(&tailAction, "action", "", "filter action (get|list|...)")
	tail.Flags().StringVar(&tailOrg, "org", "", "filter org")
	tail.Flags().IntVar(&tailLimit, "limit", 50, "max rows")

	var (
		sinceActor  string
		sinceAction string
		sinceOrg    string
		sinceLimit  int
		sinceFormat string
	)
	since := &cobra.Command{
		Use:   "since <date>",
		Short: "Show entries since a date (YYYY-MM-DD or RFC3339 timestamp)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			t, err := parseSince(args[0])
			if err != nil {
				return err
			}
			a, err := app.OpenAuditOnly()
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			entries, err := a.Audit.Tail(ctx, audit.Filter{
				Actor: sinceActor, Action: sinceAction, Org: sinceOrg,
				Since: t, Limit: sinceLimit,
			})
			if err != nil {
				return err
			}
			if sinceFormat == "json" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(entries)
			}
			for _, e := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "#%d %s %s %s path=%s org=%s result=%s reason=%s\n",
					e.Seq, e.TS.Format("2006-01-02 15:04:05"), e.ActorKind, e.Action,
					e.SecretPath, e.Org, e.Result, e.Reason)
			}
			return nil
		},
	}
	since.Flags().StringVar(&sinceActor, "actor", "", "filter actor_kind")
	since.Flags().StringVar(&sinceAction, "action", "", "filter action")
	since.Flags().StringVar(&sinceOrg, "org", "", "filter org")
	since.Flags().IntVar(&sinceLimit, "limit", 200, "max rows")
	since.Flags().StringVar(&sinceFormat, "format", "text", "output format: text | json")

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Check that the audit log has no gaps",
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
			ok, missing, err := a.Audit.Verify(ctx)
			if err != nil {
				return err
			}
			if ok {
				total, _ := a.Audit.Count(ctx)
				fmt.Fprintf(cmd.OutOrStdout(), "audit ok — %d rows, no gaps\n", total)
				return nil
			}
			return fmt.Errorf("audit gaps: %v", missing)
		},
	}

	root.AddCommand(tail, since, verify)
	return root
}

// parseSince accepts either YYYY-MM-DD or RFC3339 timestamps.
func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised date %q (use YYYY-MM-DD or RFC3339)", s)
}
