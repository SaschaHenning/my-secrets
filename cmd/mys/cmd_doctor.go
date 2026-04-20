package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/doctor"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ANSI colour codes for status prefixes. Plain-text fallback is used when
// stdout is not a TTY.
const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiGrey   = "\x1b[90m"
	ansiReset  = "\x1b[0m"
)

// doctorCmd builds the `mys doctor` subcommand.
func doctorCmd(requester *string) *cobra.Command {
	var (
		jsonOut bool
		only    []string
	)
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks on the my-secrets setup",
		Long: `mys doctor runs a series of read-only health checks against the
local my-secrets setup and prints a pass/warn/fail report. Exit code is
non-zero if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			report := doctor.Run(ctx, only)
			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				writeDoctorText(out, report)
			}
			// Audit the aggregate outcome. We use a best-effort open — a
			// broken audit DB should not hide check failures.
			writeDoctorAudit(ctx, *requester, report)
			if report.Summary.Fail > 0 {
				return fmt.Errorf("%d check(s) failed", report.Summary.Fail)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON instead of text")
	c.Flags().StringSliceVar(&only, "only", nil, "run only the named checks (comma-separated IDs)")
	return c
}

// writeDoctorText writes the human-friendly report to w. ANSI colour is used
// only if w is an *os.File pointing at a TTY.
func writeDoctorText(w io.Writer, r doctor.Report) {
	colour := false
	if f, ok := w.(*os.File); ok && f != nil {
		colour = term.IsTerminal(int(f.Fd()))
	}
	fmt.Fprintf(w, "mys doctor — %s\n\n", r.Timestamp.Local().Format("2006-01-02 15:04:05"))
	for _, c := range r.Checks {
		prefix := statusPrefix(c.Status, colour)
		fmt.Fprintf(w, "%s %s — %s\n", prefix, c.Label, c.Message)
		if c.Remedy != "" {
			fmt.Fprintf(w, "         -> %s\n", c.Remedy)
		}
	}
	fmt.Fprintf(w, "\nSummary: %d PASS / %d WARN / %d FAIL / %d SKIP\n",
		r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Skip)
}

// statusPrefix returns the bracketed [PASS]/[WARN]/[FAIL]/[SKIP] prefix,
// optionally wrapped in ANSI colour codes.
func statusPrefix(s doctor.Status, colour bool) string {
	var label, col string
	switch s {
	case doctor.StatusPass:
		label, col = "[PASS]", ansiGreen
	case doctor.StatusWarn:
		label, col = "[WARN]", ansiYellow
	case doctor.StatusFail:
		label, col = "[FAIL]", ansiRed
	case doctor.StatusSkip:
		label, col = "[SKIP]", ansiGrey
	default:
		label = "[????]"
	}
	if !colour || col == "" {
		return label
	}
	return col + label + ansiReset
}

// writeDoctorAudit records a single summary audit row. Failures to open the
// audit DB are swallowed — the exit code still reflects the check results.
func writeDoctorAudit(ctx context.Context, requester string, r doctor.Report) {
	a, err := app.OpenAuditOnly()
	if err != nil {
		return
	}
	defer a.Close(ctx)
	d := caller.Identify(requester)
	detail, _ := json.Marshal(struct {
		Caller caller.Detail `json:"caller"`
		IDs    []string      `json:"check_ids"`
	}{Caller: d, IDs: checkIDs(r)})
	reason := fmt.Sprintf("pass=%d warn=%d fail=%d skip=%d",
		r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Skip)
	result := audit.ResultOK
	if r.Summary.Fail > 0 {
		result = audit.ResultError
	}
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      audit.ActionDoctor,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
}

func checkIDs(r doctor.Report) []string {
	out := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		out = append(out, c.ID)
	}
	return out
}
