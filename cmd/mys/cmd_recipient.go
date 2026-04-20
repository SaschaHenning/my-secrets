package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/recipient"
	"github.com/spf13/cobra"
)

// errRecipientAborted is returned when the confirmation prompt did not yield
// a lowercase "y". Callers treat this as a clean exit, not an error, and
// print "aborted" to stdout.
var errRecipientAborted = errors.New("recipient add aborted")

// errRecipientAIDenied is returned when an AI caller tries to mutate the
// recipient set. Document in help text.
var errRecipientAIDenied = errors.New(
	"recipient changes are refused for AI callers — use a human session")

// recipientCmd builds the `mys recipient` subcommand tree. The add/remove
// commands are audited, AI-denied mutations of the gopass recipient list.
// This is deliberately for your own additional devices or hardware tokens
// only; team sharing belongs in Bitwarden.
func recipientCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "recipient",
		Short: "Manage gopass recipients (your own additional devices or YubiKeys)",
		Long: `Manage the set of GPG keys that can decrypt the password store.

Scope: use this ONLY for your own additional devices or hardware tokens
(for example a second laptop or a YubiKey). Adding another person's key
is the wrong trust model — the new recipient can decrypt every secret in
the store, including entries under private/**. For team sharing, use
Bitwarden, not this command.

AI callers (Claude Code, Cursor, etc.) are hard-denied from add and
remove. Listing the current recipients is allowed for everyone.`,
	}
	root.AddCommand(
		recipientAddCmd(requester),
		recipientListCmd(requester),
		recipientRemoveCmd(requester),
	)
	return root
}

func recipientAddCmd(requester *string) *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "add <keyfile-or-keyid>",
		Short: "Import a GPG key and add it as a gopass recipient (requires confirmation)",
		Long: `Import a GPG key from a file and register it as a gopass recipient.

This is intended for your own second device or hardware token. Adding
another person's key is the wrong trust model — team sharing belongs in
Bitwarden.

The command prints the imported key's fingerprint and UIDs and then
asks for an explicit lowercase "y" before calling gopass. Non-TTY
invocations abort by default; pass --yes for scripted use.

AI callers are hard-denied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRecipientAdd(ctx, cmd, *requester, args[0], yes)
		},
	}
	c.Flags().BoolVar(&yes, "yes", false,
		"skip the interactive confirmation (required when stdin is not a TTY)")
	return c
}

func recipientListCmd(requester *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List current gopass recipients with fingerprint, UID, and expiry",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRecipientList(ctx, cmd, *requester)
		},
	}
}

func recipientRemoveCmd(requester *string) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <keyid>",
		Short: "Remove a gopass recipient (re-encrypts every secret in the store)",
		Long: `Remove a GPG key from the gopass recipient set. Gopass re-encrypts
every entry for the remaining recipients. Removing the only recipient
would orphan the store, so gopass itself refuses that case.

AI callers are hard-denied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRecipientRemove(ctx, cmd, *requester, args[0])
		},
	}
}

// runRecipientAdd is the implementation split out of the cobra RunE so
// tests can invoke it directly with a fake stdin / audit log.
func runRecipientAdd(ctx context.Context, cmd *cobra.Command, requester, keyRef string, yes bool) error {
	d := caller.Identify(requester)
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	if d.Kind == caller.KindAI {
		writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, "", d,
			audit.ResultDenied, "ai caller refused")
		return errRecipientAIDenied
	}

	fpr, uid, err := recipient.Import(ctx, keyRef)
	if err != nil {
		writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, "", d,
			audit.ResultError, "import: "+err.Error())
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "imported key:\n  fingerprint: %s\n  uid: %s\n\n", fpr, uid)
	fmt.Fprintln(out, "This key will be able to DECRYPT every secret in your store,")
	fmt.Fprintln(out, "including private/**. This should be your own second device or")
	fmt.Fprintln(out, "hardware token, not another person's key.")
	fmt.Fprint(out, "Continue? [y/N] ")

	ok, err := confirmAdd(cmd.InOrStdin(), out, yes)
	if err != nil {
		writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, fpr, d,
			audit.ResultError, fmt.Sprintf("fpr=%s uid=%s prompt=%s", fpr, uid, err.Error()))
		return err
	}
	if !ok {
		writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, fpr, d,
			audit.ResultDenied, fmt.Sprintf("fpr=%s uid=%s user=declined", fpr, uid))
		fmt.Fprintln(out, "aborted")
		return nil
	}

	if err := recipient.Add(ctx, fpr); err != nil {
		writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, fpr, d,
			audit.ResultError, fmt.Sprintf("fpr=%s uid=%s gopass=%s", fpr, uid, err.Error()))
		return err
	}
	writeRecipientAudit(ctx, a, audit.ActionRecipientAdd, fpr, d,
		audit.ResultOK, fmt.Sprintf("fpr=%s uid=%s", fpr, uid))
	fmt.Fprintf(out, "added recipient %s\n", fpr)
	return nil
}

func runRecipientList(ctx context.Context, cmd *cobra.Command, requester string) error {
	d := caller.Identify(requester)
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	recs, err := recipient.List(ctx)
	if err != nil {
		writeRecipientAudit(ctx, a, audit.ActionRecipientList, "", d,
			audit.ResultError, err.Error())
		return err
	}
	out := cmd.OutOrStdout()
	for _, r := range recs {
		uid := ""
		if len(r.UIDs) > 0 {
			uid = r.UIDs[0]
		}
		exp := "unknown"
		if !r.Expires.IsZero() {
			exp = r.Expires.Format("2006-01-02")
		}
		fmt.Fprintf(out, "%s  %s  expires=%s\n", r.Fingerprint, uid, exp)
	}
	writeRecipientAudit(ctx, a, audit.ActionRecipientList, "", d,
		audit.ResultOK, fmt.Sprintf("count=%d", len(recs)))
	return nil
}

func runRecipientRemove(ctx context.Context, cmd *cobra.Command, requester, fpr string) error {
	d := caller.Identify(requester)
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	if d.Kind == caller.KindAI {
		writeRecipientAudit(ctx, a, audit.ActionRecipientRemove, fpr, d,
			audit.ResultDenied, "ai caller refused")
		return errRecipientAIDenied
	}

	if err := recipient.Remove(ctx, fpr); err != nil {
		writeRecipientAudit(ctx, a, audit.ActionRecipientRemove, fpr, d,
			audit.ResultError, fmt.Sprintf("fpr=%s gopass=%s", fpr, err.Error()))
		return err
	}
	writeRecipientAudit(ctx, a, audit.ActionRecipientRemove, fpr, d,
		audit.ResultOK, "fpr="+fpr)
	fmt.Fprintf(cmd.OutOrStdout(), "removed recipient %s\n", fpr)
	return nil
}

// confirmAdd reads stdin and returns true iff the user typed a bare "y"
// (lowercase). Any other answer — including "Y", "yes", blank, EOF — is
// treated as abort. Non-TTY stdin aborts unless --yes was passed.
func confirmAdd(in io.Reader, out io.Writer, yes bool) (bool, error) {
	if yes {
		fmt.Fprintln(out, "(auto-confirmed via --yes)")
		return true, nil
	}
	if !isTerminalStdin(in) {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "non-interactive stdin: pass --yes to confirm non-interactively")
		return false, nil
	}
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.TrimRight(line, "\r\n") == "y", nil
}

// isTerminalStdin reports whether the given reader is the real terminal
// stdin. We only treat os.Stdin as a TTY when its file descriptor is a
// character device. Tests injecting a bytes.Buffer read as non-TTY.
func isTerminalStdin(in io.Reader) bool {
	if in == nil {
		return false
	}
	if in != os.Stdin {
		// Custom reader (used by tests) — not a TTY.
		return false
	}
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// writeRecipientAudit records a single audit row for a recipient operation.
// Mirrors app.writeAudit, but is standalone because recipient changes do
// not go through the store facade (they mutate keyring + gopass config,
// not individual entries).
func writeRecipientAudit(ctx context.Context, a *app.App, action, fpr string,
	d caller.Detail, result, reason string) {
	if a == nil || a.Audit == nil {
		return
	}
	detail, _ := json.Marshal(d)
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      action,
		SecretPath:  fpr,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
}
