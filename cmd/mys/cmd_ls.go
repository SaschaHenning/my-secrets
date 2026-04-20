package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/rotation"
	"github.com/spf13/cobra"
)

// lsCmd builds the `mys ls` subcommand.
//
// Beyond the baseline path listing the flags cover four filter modes:
//
//   - --org <o>                     path prefix on the top-level folder.
//   - --tag <t>                     exact tag match; requires decrypting.
//   - --domain <q> [--similar]      routes through app.SearchByDomain so the
//     tier/hint system can surface typos and partial
//     URL queries to the user. Without --similar
//     only exact + subdomain hits are listed; with
//     --similar the substring + fuzzy tiers are added
//     below a blank line, each prefixed with [tier]
//     and followed by the hint.
//   - --field k=v (repeatable)      AND-filters every entry's Fields map
//     against the provided key/value pairs. An empty value
//     (`--field region=`) matches any non-empty value for
//     the key — a presence check.
//   - --stale / --rotating-in       rotation-policy filters.
func lsCmd(requester *string) *cobra.Command {
	var (
		org        string
		tag        string
		domainQ    string
		similar    bool
		fieldsRaw  []string
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
			// Parse --field filters up-front so invalid input fails fast.
			fieldFilters, err := parseFieldFilters(fieldsRaw)
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)

			// --domain takes precedence: its output shape is different
			// (includes tier + hint) and mixing in tag/field filters on
			// top would make the result ambiguous.
			if domainQ != "" {
				return runLsDomain(ctx, cmd.OutOrStdout(), a, domainQ, similar)
			}

			return runLs(ctx, a, cmd.OutOrStdout(), lsOptions{
				Org:          org,
				Tag:          tag,
				FieldFilters: fieldFilters,
				StaleOnly:    staleOnly,
				RotatingIn:   window,
				Now:          time.Now().UTC(),
			})
		},
	}
	c.Flags().StringVar(&org, "org", "", "filter by org (top-level folder)")
	c.Flags().StringVar(&tag, "tag", "", "filter by tag (exact match); requires decrypting entries")
	c.Flags().StringVar(&domainQ, "domain", "", "filter by domain (exact + subdomain match)")
	c.Flags().BoolVar(&similar, "similar", false,
		"with --domain: also list substring + fuzzy matches, each prefixed with [tier] and a hint")
	c.Flags().StringArrayVar(&fieldsRaw, "field", nil,
		"filter by custom field key=value (repeatable, AND-combined); requires decrypting entries")
	c.Flags().BoolVar(&staleOnly, "stale", false,
		"only list entries that are past their rotate_after horizon")
	c.Flags().StringVar(&rotatingIn, "rotating-in", "",
		"only list entries due for rotation within this window (e.g. 7d, 30d)")
	return c
}

// lsOptions bundles the filter flags for runLs. It exists so the tests
// can drive the command logic without going through cobra.
type lsOptions struct {
	Org          string
	Tag          string
	FieldFilters map[string]string
	StaleOnly    bool
	RotatingIn   time.Duration // zero = filter disabled
	Now          time.Time
}

// runLs is the testable core of `mys ls` for everything except --domain.
func runLs(ctx context.Context, a *app.App, out io.Writer, opt lsOptions) error {
	paths, err := a.List(ctx, opt.Org)
	if err != nil {
		return err
	}

	// If any filter needs the full entry (tag, field, stale, rotating-in)
	// we decrypt once per path and reuse the entry for all checks.
	needDetails := opt.Tag != "" || len(opt.FieldFilters) > 0 || opt.StaleOnly || opt.RotatingIn > 0
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
		if opt.Tag != "" && !hasTag(e.Tags, opt.Tag) {
			continue
		}
		if len(opt.FieldFilters) > 0 && !matchesFields(e.Fields, opt.FieldFilters) {
			continue
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
			days := int(overdue / (24 * time.Hour))
			fmt.Fprintf(out, "%s  %dd old  rotate_after=%s\n", p, days, e.RotateAfter)
			continue
		}
		fmt.Fprintln(out, p)
	}
	return nil
}

// runLsDomain implements the --domain branch. It calls SearchByDomain
// exactly once with includeSimilar=true and then decides locally which
// tiers to print. That avoids doubling the audit trail and the decrypt
// cost for the "summary only" case (review finding C1).
func runLsDomain(ctx context.Context, out io.Writer, a *app.App, query string, includeSimilar bool) error {
	matches, similar, err := a.SearchByDomain(ctx, query, true)
	if err != nil {
		return err
	}
	for _, m := range matches {
		if includeSimilar {
			fmt.Fprintf(out, "[%s] %s  %s\n", m.Tier, m.Entry.Path, m.Hint)
		} else {
			fmt.Fprintln(out, m.Entry.Path)
		}
	}
	if !includeSimilar {
		if len(similar) > 0 {
			fmt.Fprintf(out, "\n%d similar entries (substring/fuzzy) — rerun with --similar to include them\n", len(similar))
		}
		return nil
	}
	for _, m := range similar {
		fmt.Fprintf(out, "[%s] %s  %s\n", m.Tier, m.Entry.Path, m.Hint)
	}
	return nil
}

// parseFieldFilters accepts the same "key=value" syntax as --field on
// `mys add`, but is deliberately more forgiving on the key: we only
// require a non-empty key rather than enforcing the add-time regex.
func parseFieldFilters(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	for _, s := range raw {
		i := strings.Index(s, "=")
		if i <= 0 {
			return nil, fmt.Errorf("invalid --field filter %q: expected key=value", s)
		}
		k := s[:i]
		v := s[i+1:]
		out[k] = v
	}
	return out, nil
}

// matchesFields returns true iff every (k, v) in filters is present and
// matches in fields. An empty filter value (`--field region=`) matches
// any non-empty value for that key — a presence check is almost always
// what the user wants when they leave the value off.
func matchesFields(fields, filters map[string]string) bool {
	for k, want := range filters {
		got, ok := fields[k]
		if !ok {
			return false
		}
		if want == "" {
			if got == "" {
				return false
			}
			continue
		}
		if !strings.EqualFold(got, want) {
			return false
		}
	}
	return true
}

// hasTag returns true if t appears anywhere in tags. Case-sensitive —
// tags are stored as-entered and the existing behaviour matched exactly.
func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}
