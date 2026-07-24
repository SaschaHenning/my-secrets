package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/store"
	totppkg "github.com/SaschaHenning/my-secrets/internal/totp"
	"github.com/spf13/cobra"
)

// nowFunc is the time source used by totpCmd. Tests override it to
// produce deterministic codes; production code leaves the default of
// time.Now.
var nowFunc = time.Now

// totpCmd builds `mys totp` with two modes:
//   - `mys totp add <path> <uri-or-seed>` → stores a new TOTP entry
//   - `mys totp <path>` (no subcommand)   → prints the current code
//
// The parent command handles the bare `mys totp <path>` case via RunE,
// while `add` is a dedicated subcommand so its flags do not pollute
// the default action.
func totpCmd(requester *string) *cobra.Command {
	var watch bool

	parent := &cobra.Command{
		Use:   "totp <path>",
		Short: "Generate TOTP codes for a stored seed",
		Long: "Generate a RFC 6238 TOTP code for a stored seed.\n\n" +
			"Use `mys totp add <path> <uri-or-seed>` to create an entry,\n" +
			"and `mys totp <path>` to print the current code.",
		Args: cobra.ExactArgs(1),
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
			if watch {
				return runTOTPWatch(ctx, a, args[0], cmd.OutOrStdout())
			}
			return runTOTPOnce(ctx, a, args[0], cmd.OutOrStdout())
		},
	}
	parent.Flags().BoolVar(&watch, "watch", false, "refresh the code every second until interrupted")

	parent.AddCommand(totpAddCmd(requester))
	return parent
}

// totpAddOptions bundles the flag values for `mys totp add`.
type totpAddOptions struct {
	Issuer    string
	Label     string
	Algorithm string
	Digits    int
	Period    int
}

// buildTOTPEntry turns the `mys totp add` arguments into a store.Entry.
// Extracted from the cobra runner so tests can exercise the URI-vs-seed
// branching without opening a real store.
func buildTOTPEntry(path, input string, opts totpAddOptions) (*store.Entry, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("uri-or-seed must not be empty")
	}
	e := &store.Entry{
		Path:          path,
		Org:           store.OrgOf(path),
		Kind:          store.KindTOTP,
		TOTPIssuer:    opts.Issuer,
		TOTPLabel:     opts.Label,
		TOTPAlgorithm: strings.ToUpper(strings.TrimSpace(opts.Algorithm)),
		TOTPDigits:    opts.Digits,
		TOTPPeriod:    opts.Period,
	}
	if strings.HasPrefix(strings.ToLower(input), "otpauth://") {
		parsed, err := totppkg.ParseURI(input)
		if err != nil {
			return nil, fmt.Errorf("parse uri: %w", err)
		}
		e.Password = parsed.Seed
		if e.TOTPIssuer == "" {
			e.TOTPIssuer = parsed.Issuer
		}
		if e.TOTPLabel == "" {
			e.TOTPLabel = parsed.Label
		}
		if opts.Algorithm == "" {
			e.TOTPAlgorithm = totppkg.AlgorithmString(parsed.Algorithm)
		}
		if opts.Digits == 0 {
			e.TOTPDigits = totppkg.DigitsInt(parsed.Digits)
		}
		if opts.Period == 0 && parsed.Period > 0 {
			e.TOTPPeriod = int(parsed.Period)
		}
	} else {
		// Raw base32 seed — strip spaces so the user can paste the
		// chunked form ("JBSW Y3DP EHPK 3PXP") the providers show.
		e.Password = strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	}
	if e.Password == "" {
		return nil, fmt.Errorf("no seed extracted from input")
	}
	if e.TOTPAlgorithm == "" {
		e.TOTPAlgorithm = "SHA1"
	}
	if e.TOTPDigits == 0 {
		e.TOTPDigits = 6
	}
	if e.TOTPPeriod == 0 {
		e.TOTPPeriod = 30
	}
	return e, nil
}

// totpAddCmd implements `mys totp add <path> <uri-or-seed>`.
func totpAddCmd(requester *string) *cobra.Command {
	var opts totpAddOptions
	c := &cobra.Command{
		Use:   "add <path> <uri-or-seed>",
		Short: "Add a TOTP entry from an otpauth:// URI or raw base32 seed",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			e, err := buildTOTPEntry(args[0], args[1], opts)
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			if err := a.Add(ctx, e); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored totp %s (%s:%s)\n", e.Path, e.TOTPIssuer, e.TOTPLabel)
			return nil
		},
	}
	c.Flags().StringVar(&opts.Issuer, "issuer", "", "issuer override (e.g. GitHub)")
	c.Flags().StringVar(&opts.Label, "label", "", "label override (e.g. sascha@example.com)")
	c.Flags().StringVar(&opts.Algorithm, "algorithm", "", "SHA1 | SHA256 | SHA512 (default SHA1)")
	c.Flags().IntVar(&opts.Digits, "digits", 0, "digit count (6, 7 or 8, default 6)")
	c.Flags().IntVar(&opts.Period, "period", 0, "period seconds (default 30)")
	return c
}

// runTOTPOnce generates a single code and writes it to w.
func runTOTPOnce(ctx context.Context, a *app.App, path string, w io.Writer) error {
	now := nowFunc()
	details, err := a.GenerateTOTPDetails(ctx, path, now)
	if err != nil {
		return err
	}
	printTOTPCode(
		w,
		path,
		details.Issuer,
		details.Label,
		details.Code,
		details.SecondsLeft,
	)
	return nil
}

// runTOTPWatch runs the watch loop, re-printing the code on the same
// terminal line every second until Ctrl-C.
func runTOTPWatch(ctx context.Context, a *app.App, path string, w io.Writer) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Read the code and display metadata through one policy-checked access.
	// Subsequent ticks only regenerate the code, keeping metadata stable while
	// preserving the existing one-audit-row-per-window behavior.
	details, err := a.GenerateTOTPDetails(ctx, path, nowFunc())
	if err != nil {
		return err
	}
	writeWatchLine(
		w,
		path,
		details.Issuer,
		details.Label,
		details.Code,
		details.SecondsLeft,
	)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(w)
			return nil
		case <-sigCh:
			fmt.Fprintln(w)
			return nil
		case <-ticker.C:
			code, secondsLeft, err := a.GenerateTOTP(ctx, path, nowFunc())
			if err != nil {
				fmt.Fprintln(w)
				return err
			}
			writeWatchLine(w, path, details.Issuer, details.Label, code, secondsLeft)
		}
	}
}

// writeWatchLine prints a single-line variant using \r so successive
// updates overwrite the previous line.
func writeWatchLine(w io.Writer, path, issuer, label, code string, secondsLeft int) {
	fmt.Fprintf(w, "\r%s (%s:%s)  %s  (%2ds left)   ", path, issuer, label, formatCode(code), secondsLeft)
}

// printTOTPCode renders the canonical two-line output for `mys totp <path>`.
func printTOTPCode(w io.Writer, path, issuer, label, code string, secondsLeft int) {
	fmt.Fprintf(w, "\n%s (%s:%s)\n%s     (%ds left)\n", path, issuer, label, formatCode(code), secondsLeft)
}

// formatCode inserts a thin space after three digits so a "487291" 6-digit
// code reads as "487 291". Leaves 7- and 8-digit codes in "1234 5678"
// style (split into two groups). Non-standard lengths are returned
// unmodified.
func formatCode(code string) string {
	switch len(code) {
	case 6:
		return code[:3] + " " + code[3:]
	case 7:
		return code[:3] + " " + code[3:]
	case 8:
		return code[:4] + " " + code[4:]
	}
	return code
}
