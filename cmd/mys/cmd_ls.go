package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/rotation"
	"github.com/spf13/cobra"
)

// lsCmd builds the `mys ls` subcommand.
func lsCmd(requester *string) *cobra.Command {
	var (
		org        string
		tag        string
		staleOnly  bool
		rotatingIn string
	)
	c := &cobra.Command{
		Use:   "ls",
		Short: "List secret paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Validate the --rotating-in value up front — if the user
			// typed garbage we want a clean error before we unlock
			// gopass and decrypt every entry in the store.
			var window time.Duration
			if rotatingIn != "" {
				d, err := rotation.ParseDuration(rotatingIn)
				if err != nil {
					return err
				}
				window = d
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return runLs(ctx, a, cmd.OutOrStdout(), lsOptions{
				Org:        org,
				Tag:        tag,
				StaleOnly:  staleOnly,
				RotatingIn: window,
				Now:        time.Now().UTC(),
			})
		},
	}
	c.Flags().StringVar(&org, "org", "", "filter by org (top-level folder)")
	c.Flags().StringVar(&tag, "tag", "", "filter by tag (exact match); requires decrypting entries")
	c.Flags().BoolVar(&staleOnly, "stale", false,
		"only list entries that are past their rotate_after horizon")
	c.Flags().StringVar(&rotatingIn, "rotating-in", "",
		"only list entries due for rotation within this window (e.g. 7d, 30d)")
	return c
}

// lsOptions bundles the filter flags for runLs. It exists so the tests
// can drive the command logic without going through cobra.
type lsOptions struct {
	Org        string
	Tag        string
	StaleOnly  bool
	RotatingIn time.Duration // zero = filter disabled
	Now        time.Time
}

// runLs is the testable core of `mys ls`. It lists, filters, and prints;
// all app/store access happens through the given app.App so tests can
// wire in an in-memory fake store.
func runLs(ctx context.Context, a *app.App, out io.Writer, opt lsOptions) error {
	paths, err := a.List(ctx, opt.Org)
	if err != nil {
		return err
	}

	// If any filter needs the full entry (tag, stale, rotating-in) we
	// decrypt once per path and reuse the entry for all checks.
	needDetails := opt.Tag != "" || opt.StaleOnly || opt.RotatingIn > 0
	if !needDetails {
		for _, p := range paths {
			fmt.Fprintln(out, p)
		}
		return nil
	}

	for _, p := range paths {
		e, err := a.Get(ctx, p)
		if err != nil {
			continue
		}
		if opt.Tag != "" {
			hit := false
			for _, t := range e.Tags {
				if t == opt.Tag {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		stale, overdue := rotation.IsStale(e, opt.Now)
		if opt.StaleOnly && !stale {
			continue
		}
		if opt.RotatingIn > 0 {
			due, _ := rotation.DueWithin(e, opt.Now, opt.RotatingIn)
			if !due {
				continue
			}
		}
		if opt.StaleOnly {
			// Enriched format: "<path>  <N>d old  rotate_after=<policy>"
			// The age reported is the time since the horizon elapsed —
			// the quantity the user is actually chasing.
			days := int(overdue / (24 * time.Hour))
			fmt.Fprintf(out, "%s  %dd old  rotate_after=%s\n", p, days, e.RotateAfter)
			continue
		}
		fmt.Fprintln(out, p)
	}
	return nil
}
