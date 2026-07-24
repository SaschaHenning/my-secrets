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
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
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
// The default mount remains restricted to the user's own additional devices
// or hardware tokens. Explicitly shared mounts may contain foreign team keys.
func recipientCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "recipient",
		Short: "Manage recipients for the personal store or an explicitly shared mount",
		Long: `Manage the set of GPG keys that can decrypt the password store.

DEFAULT STORE SCOPE: without --mount (or with --mount root), use this ONLY
for your own additional devices or hardware tokens (for example a second
laptop or a YubiKey). Adding another person's key to the personal store
is the wrong trust model — the new recipient can decrypt every secret,
including entries under private/**.

SHARED MOUNT SCOPE: --mount <name> may target a mount explicitly marked
shared in sync.yaml. A shared mount uses team-keys.yaml as its team
identity map; every listed recipient can decrypt every secret in that
mount. This is advisory team sharing, not enforceable read auditing.

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
	var (
		mount string
		yes   bool
	)
	c := &cobra.Command{
		Use:   "add <keyfile-or-keyid>",
		Short: "Import a GPG key and add it as a gopass recipient (requires confirmation)",
		Long: `Import a GPG key from a file and register it as a gopass recipient.

Without --mount (or with --mount root), this is intended ONLY for your
own second device or hardware token. Never add another person's key to
the personal store.

With --mount <name>, the command targets that configured mount. If the
mount is marked shared in sync.yaml, foreign team keys are allowed only
after validating the live mount's team-keys.yaml. A fingerprint missing
from the manifest is warned about but may still be added while the
identity map catches up.

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
			return runRecipientAddForMount(ctx, cmd, *requester, args[0], mount, yes)
		},
	}
	c.Flags().StringVar(&mount, "mount", "",
		"target gopass mount (default: personal root store)")
	c.Flags().BoolVar(&yes, "yes", false,
		"skip the interactive confirmation (required when stdin is not a TTY)")
	return c
}

func recipientListCmd(requester *string) *cobra.Command {
	var mount string
	c := &cobra.Command{
		Use:   "list",
		Short: "List current gopass recipients with fingerprint, UID, and expiry",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRecipientListForMount(ctx, cmd, *requester, mount)
		},
	}
	c.Flags().StringVar(&mount, "mount", "",
		"target gopass mount (default: personal root store)")
	return c
}

func recipientRemoveCmd(requester *string) *cobra.Command {
	var mount string
	c := &cobra.Command{
		Use:   "remove <keyid>",
		Short: "Remove a gopass recipient (re-encrypts every secret in the store)",
		Long: `Remove a GPG key from the gopass recipient set. Gopass re-encrypts
every entry for the remaining recipients. Removing the only recipient
would orphan the store, so gopass itself refuses that case.

Use --mount <name> to target a configured personal or shared mount.
Shared mounts must still be marked shared and contain a valid
team-keys.yaml when the mutation occurs.

AI callers are hard-denied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRecipientRemoveForMount(ctx, cmd, *requester, args[0], mount)
		},
	}
	c.Flags().StringVar(&mount, "mount", "",
		"target gopass mount (default: personal root store)")
	return c
}

type recipientMountTarget struct {
	mount  string
	config *syncpkg.Config
	shared bool
}

// runRecipientAdd preserves the pre-mount helper contract for existing
// callers and tests. An empty mount is the personal root store.
func runRecipientAdd(
	ctx context.Context,
	cmd *cobra.Command,
	requester, keyRef string,
	yes bool,
) error {
	return runRecipientAddForMount(ctx, cmd, requester, keyRef, "", yes)
}

// runRecipientAddForMount is split out of the cobra RunE so tests can invoke
// the mount-aware flow directly with fake stdin, audit storage, and runners.
func runRecipientAddForMount(
	ctx context.Context,
	cmd *cobra.Command,
	requester, keyRef, mount string,
	yes bool,
) error {
	return runRecipientAddForMountAs(
		ctx, cmd, caller.Identify(requester), keyRef, mount, yes)
}

func runRecipientAddForMountAs(
	ctx context.Context,
	cmd *cobra.Command,
	d caller.Detail,
	keyRef, mount string,
	yes bool,
) error {
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	if d.Kind == caller.KindAI {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, "", mount, d,
			audit.ResultDenied, "ai caller refused")
		return errRecipientAIDenied
	}

	target, err := loadRecipientMountTarget(mount)
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, "", mount, d,
			audit.ResultDenied, "mount: "+err.Error())
		return err
	}
	if target.shared {
		if err := recipient.ValidateSharedMount(ctx, target.mount, target.config); err != nil {
			writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, "", target.mount, d,
				audit.ResultDenied, "shared mount: "+err.Error())
			return err
		}
	}

	fpr, uid, err := recipient.Import(ctx, keyRef)
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, "", target.mount, d,
			audit.ResultError, "import: "+err.Error())
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "imported key:\n  fingerprint: %s\n  uid: %s\n\n", fpr, uid)

	var foreign recipient.ForeignInfo
	if target.shared {
		foreign, err = recipient.InspectForeign(ctx, target.mount, fpr, target.config)
		if err != nil {
			writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, fpr, target.mount, d,
				audit.ResultDenied, recipientAddReason(fpr, uid, foreign, "manifest="+err.Error()))
			return err
		}
		if foreign.Listed {
			fmt.Fprintf(out, "team member: %s <%s>\n\n", foreign.Name, foreign.Email)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"warning: fingerprint %s is not listed in %s for shared mount %q yet\n",
				fpr, "team-keys.yaml", target.mount)
		}
	}

	printRecipientAddWarning(out, target)
	fmt.Fprint(out, "Continue? [y/N] ")

	ok, err := confirmAdd(cmd.InOrStdin(), out, yes)
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, fpr, target.mount, d,
			audit.ResultError, recipientAddReason(
				fpr, uid, foreign, "prompt="+err.Error()))
		return err
	}
	if !ok {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, fpr, target.mount, d,
			audit.ResultDenied, recipientAddReason(fpr, uid, foreign, "user=declined"))
		fmt.Fprintln(out, "aborted")
		return nil
	}

	err = mutateRecipientTarget(ctx, target, func(current recipientMountTarget) error {
		if current.shared {
			return recipient.AddForeign(ctx, current.mount, fpr, current.config)
		}
		return recipient.AddToMount(ctx, current.mount, fpr)
	})
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, fpr, target.mount, d,
			audit.ResultError, recipientAddReason(fpr, uid, foreign, "gopass="+err.Error()))
		return err
	}
	writeRecipientMountAudit(ctx, a, audit.ActionRecipientAdd, fpr, target.mount, d,
		audit.ResultOK, recipientAddReason(fpr, uid, foreign, ""))
	fmt.Fprintf(out, "added recipient %s\n", fpr)
	return nil
}

func printRecipientAddWarning(out io.Writer, target recipientMountTarget) {
	if target.shared {
		fmt.Fprintf(out, "This key will be able to DECRYPT every secret in shared mount %q.\n",
			target.mount)
		fmt.Fprintln(out, "Only add a team member after verifying the fingerprint out of band;")
		fmt.Fprintln(out, "removing the key later cannot revoke secrets already decrypted.")
		return
	}
	fmt.Fprintln(out, "This key will be able to DECRYPT every secret in your store,")
	fmt.Fprintln(out, "including private/**. This should be your own second device or")
	fmt.Fprintln(out, "hardware token, not another person's key.")
}

func recipientAddReason(
	fpr, uid string,
	foreign recipient.ForeignInfo,
	suffix string,
) string {
	parts := []string{"fpr=" + fpr, "uid=" + uid}
	if foreign.Listed {
		parts = append(parts, "team_name="+foreign.Name, "team_email="+foreign.Email)
	}
	if suffix != "" {
		parts = append(parts, suffix)
	}
	return strings.Join(parts, " ")
}

func runRecipientList(ctx context.Context, cmd *cobra.Command, requester string) error {
	return runRecipientListForMount(ctx, cmd, requester, "")
}

func runRecipientListForMount(
	ctx context.Context,
	cmd *cobra.Command,
	requester, mount string,
) error {
	return runRecipientListForMountAs(
		ctx, cmd, caller.Identify(requester), mount)
}

func runRecipientListForMountAs(
	ctx context.Context,
	cmd *cobra.Command,
	d caller.Detail,
	mount string,
) error {
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	if err := validateRecipientMount(mount); err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientList, "", mount, d,
			audit.ResultDenied, "mount: "+err.Error())
		return err
	}

	recs, err := recipient.ListFromMount(ctx, mount)
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientList, "", mount, d,
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
	writeRecipientMountAudit(ctx, a, audit.ActionRecipientList, "", mount, d,
		audit.ResultOK, fmt.Sprintf("count=%d", len(recs)))
	return nil
}

func runRecipientRemove(ctx context.Context, cmd *cobra.Command, requester, fpr string) error {
	return runRecipientRemoveForMount(ctx, cmd, requester, fpr, "")
}

func runRecipientRemoveForMount(
	ctx context.Context,
	cmd *cobra.Command,
	requester, fpr, mount string,
) error {
	return runRecipientRemoveForMountAs(
		ctx, cmd, caller.Identify(requester), fpr, mount)
}

func runRecipientRemoveForMountAs(
	ctx context.Context,
	cmd *cobra.Command,
	d caller.Detail,
	fpr, mount string,
) error {
	a, err := app.OpenAuditOnly()
	if err != nil {
		return err
	}
	defer a.Close(ctx)

	if d.Kind == caller.KindAI {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientRemove, fpr, mount, d,
			audit.ResultDenied, "ai caller refused")
		return errRecipientAIDenied
	}

	target, err := loadRecipientMountTarget(mount)
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientRemove, fpr, mount, d,
			audit.ResultDenied, "mount: "+err.Error())
		return err
	}
	if target.shared {
		if err := recipient.ValidateSharedMount(ctx, target.mount, target.config); err != nil {
			writeRecipientMountAudit(ctx, a, audit.ActionRecipientRemove, fpr, target.mount, d,
				audit.ResultDenied, "shared mount: "+err.Error())
			return err
		}
	}

	err = mutateRecipientTarget(ctx, target, func(current recipientMountTarget) error {
		if current.shared {
			if err := recipient.ValidateSharedMount(ctx, current.mount, current.config); err != nil {
				return err
			}
		}
		return recipient.RemoveFromMount(ctx, current.mount, fpr)
	})
	if err != nil {
		writeRecipientMountAudit(ctx, a, audit.ActionRecipientRemove, fpr, target.mount, d,
			audit.ResultError, fmt.Sprintf("fpr=%s gopass=%s", fpr, err.Error()))
		return err
	}
	writeRecipientMountAudit(ctx, a, audit.ActionRecipientRemove, fpr, target.mount, d,
		audit.ResultOK, "fpr="+fpr)
	fmt.Fprintf(cmd.OutOrStdout(), "removed recipient %s\n", fpr)
	return nil
}

func loadRecipientMountTarget(mount string) (recipientMountTarget, error) {
	if err := validateRecipientMount(mount); err != nil {
		return recipientMountTarget{}, err
	}
	target := recipientMountTarget{mount: mount}
	if mount == "" || mount == syncpkg.DefaultStoreMount {
		return target, nil
	}
	cfg, err := syncpkg.Load("")
	if err != nil {
		return recipientMountTarget{}, err
	}
	remote, ok := cfg.Remote(mount)
	if !ok {
		return recipientMountTarget{}, fmt.Errorf(
			"mount %q is not configured in sync.yaml", mount)
	}
	target.config = cfg
	target.shared = remote.Shared
	return target, nil
}

func validateRecipientMount(mount string) error {
	if mount == "" || mount == syncpkg.DefaultStoreMount {
		return nil
	}
	if err := syncpkg.ValidateSharedMountName(mount); err != nil {
		return fmt.Errorf("invalid recipient mount: %w", err)
	}
	return nil
}

func mutateRecipientTarget(
	ctx context.Context,
	original recipientMountTarget,
	mutate func(recipientMountTarget) error,
) error {
	release, err := syncpkg.AcquireMountLock(ctx, original.mount)
	if err != nil {
		return err
	}

	current, mutationErr := loadRecipientMountTarget(original.mount)
	if mutationErr == nil && current.shared != original.shared {
		mutationErr = fmt.Errorf(
			"mount %q sharing mode changed while awaiting confirmation", original.mount)
	}
	if mutationErr == nil {
		mutationErr = mutate(current)
	}
	return errors.Join(mutationErr, release())
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
	writeRecipientMountAudit(ctx, a, action, fpr, "", d, result, reason)
}

func writeRecipientMountAudit(
	ctx context.Context,
	a *app.App,
	action, fpr, mount string,
	d caller.Detail,
	result, reason string,
) {
	if a == nil || a.Audit == nil {
		return
	}
	detail, _ := json.Marshal(d)
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      action,
		SecretPath:  fpr,
		Org:         mount,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
}
