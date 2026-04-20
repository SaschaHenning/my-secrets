package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/gopassinit"
	"github.com/SaschaHenning/my-secrets/internal/gpgsetup"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// initOptions bundles everything `mys init` needs. Extracting this into
// a struct makes the step functions testable and the cobra RunE a thin
// adapter.
type initOptions struct {
	// Requester flows in from the root `--requester` flag so audit
	// rows carry the same actor attribution as other commands.
	Requester string

	// Flags
	Yes          bool
	Name         string
	Email        string
	NoPassphrase bool
	InstallSkill bool   // set when --install-skill is present
	SkillScope   string // "global" or "local" — meaningful only when InstallSkill or Yes w/ flag
	WithSync     bool

	// If true, the user passed --install-skill explicitly (even with
	// its zero value). We use this to decide whether to prompt in
	// interactive mode. Cobra sets the flag via Changed().
	installSkillExplicit bool

	// Same marker for --with-sync. When the user did not pass it and
	// we are interactive, we prompt at the end; in --yes mode we skip.
	withSyncExplicit bool

	// I/O — overrideable so tests can drive prompts without a tty.
	In  io.Reader
	Out io.Writer

	// Injectable hooks for tests. Nil falls back to the real thing.
	readPassphrase func(prompt string) (string, error)
}

// initCmd builds the `mys init` subcommand.
func initCmd(requester *string) *cobra.Command {
	opts := &initOptions{}
	c := &cobra.Command{
		Use:   "init",
		Short: "Set up GPG key, gopass store, policy, audit DB — end to end",
		Long: `mys init is the single entry point for a fresh install.

On a machine with neither a GPG key nor a gopass store, mys init will:

  1. generate an Ed25519 GPG key (or pick an existing one)
  2. initialise the gopass store against that key
  3. configure pinentry-touchid (macOS only, best-effort)
  4. write the default scope policy and create the audit DB
  5. optionally install the Claude Code skill
  6. optionally set up git sync

Re-running is idempotent: no duplicate keys, no config churn.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			opts.Requester = *requester
			// Cobra tracks which flags were explicitly set vs. defaulted —
			// we need that for the „prompt for skill install?" decision.
			opts.installSkillExplicit = cmd.Flags().Changed("install-skill")
			opts.withSyncExplicit = cmd.Flags().Changed("with-sync")
			if opts.Out == nil {
				opts.Out = cmd.OutOrStdout()
			}
			if opts.In == nil {
				opts.In = cmd.InOrStdin()
			}
			return runInit(ctx, opts)
		},
	}
	c.Flags().BoolVar(&opts.Yes, "yes", false,
		"fully non-interactive; use git-config name/email as defaults and fail if info is missing. "+
			"Implies --no-passphrase when a new key has to be generated (there is no TTY to prompt). "+
			"For a passphrase-protected key run interactively.")
	c.Flags().StringVar(&opts.Name, "name", "", "real name for a new GPG key (defaults to git config user.name)")
	c.Flags().StringVar(&opts.Email, "email", "", "email for a new GPG key (defaults to git config user.email)")
	c.Flags().BoolVar(&opts.NoPassphrase, "no-passphrase", false,
		"generate the new GPG key without a passphrase (useful with pinentry-touchid)")
	// --install-skill takes an optional value so both `--install-skill`
	// (implies global) and `--install-skill=local` work.
	c.Flags().BoolVar(&opts.InstallSkill, "install-skill", false,
		"also install the Claude Code skill (symlink .claude/skills/my-secrets → repo)")
	c.Flags().StringVar(&opts.SkillScope, "skill-scope", "global",
		"scope for --install-skill: global (~/.claude) or local (<cwd>/.claude)")
	c.Flags().BoolVar(&opts.WithSync, "with-sync", false,
		"run `mys sync setup` after the bootstrap")
	return c
}

// initState carries values produced by one step and consumed by later
// ones. Passed by pointer so each step can populate it.
type initState struct {
	KeyFingerprint string
	KeyUID         string
	KeyAlgorithm   string
	KeyIsNew       bool

	PolicyPath string
	AuditPath  string

	SkillDst   string
	SkillScope string

	SyncRepoURL string
}

// initStep is a single stage of the bootstrap. run must be callable
// multiple times (idempotency); skip lets the runner silently bypass a
// step whose preconditions are not met.
type initStep struct {
	name string
	run  func(ctx context.Context, opts *initOptions, state *initState) error
}

// runInit executes the stepwise runner. Each step prints its own
// [+]/[v]/[!]/[x] marker; on the first error the runner aborts.
func runInit(ctx context.Context, opts *initOptions) error {
	fmt.Fprintf(opts.Out, "mys init %s\n\n", Version)

	state := &initState{}
	steps := []initStep{
		{name: "detect or generate GPG key", run: stepGPG},
		{name: "initialise gopass store", run: stepGopass},
		{name: "configure pinentry-touchid", run: stepPinentry},
		{name: "write policy + audit", run: stepState},
		{name: "install Claude skill", run: stepSkill},
		{name: "set up git sync", run: stepSync},
	}
	if err := runSteps(ctx, opts, state, steps); err != nil {
		return err
	}

	// Final ready message.
	fmt.Fprintln(opts.Out)
	fmt.Fprintln(opts.Out, "mys is ready. Try:")
	fmt.Fprintln(opts.Out, "  mys add zuhause/wifi --user admin")
	fmt.Fprintln(opts.Out, "  mys doctor")
	fmt.Fprintln(opts.Out, "  mys sync setup")
	return nil
}

// runSteps runs the given sequence, printing a failure marker on the
// first error and wrapping the error with the step name. Extracted so
// tests can exercise the runner without touching GPG or gopass.
func runSteps(ctx context.Context, opts *initOptions, state *initState, steps []initStep) error {
	for _, s := range steps {
		if err := s.run(ctx, opts, state); err != nil {
			fmt.Fprintf(opts.Out, "[x] %s: %s\n", s.name, err.Error())
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

// ----- Step 1: GPG key -----

func stepGPG(ctx context.Context, opts *initOptions, state *initState) error {
	keys, err := gpgsetup.HasKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		// Pick the first existing key. If there are several and we are
		// interactive, ask; otherwise take [0].
		key := keys[0]
		if len(keys) > 1 && !opts.Yes {
			chosen, err := promptSelectKey(opts, keys)
			if err != nil {
				return err
			}
			key = chosen
		}
		state.KeyFingerprint = key.Fingerprint
		state.KeyUID = key.UID
		state.KeyAlgorithm = key.Algorithm
		fmt.Fprintf(opts.Out, "[v] GPG key found: %s (%s)\n",
			uidOrFingerprint(key), shortFpr(key.Fingerprint))
		return nil
	}

	// No keys — generate one.
	name, email, err := resolveNameEmail(opts)
	if err != nil {
		return err
	}
	pass := ""
	if !opts.NoPassphrase {
		p, err := resolvePassphrase(opts)
		if err != nil {
			return err
		}
		pass = p
	}
	if pass == "" {
		// Be explicit: an operator who runs --yes or --no-passphrase must
		// see that the key is generated without passphrase protection. The
		// security implication (losing the key file = losing every secret)
		// is too important to leave implicit.
		fmt.Fprintf(opts.Out, "[!] Generating key WITHOUT passphrase — rely on pinentry-touchid or file-system permissions for protection.\n")
	}
	fmt.Fprintf(opts.Out, "[+] Generating ed25519 GPG key for %s <%s>...\n", name, email)
	fpr, err := gpgsetup.GenerateKey(ctx, gpgsetup.GenerateOpts{
		Name:       name,
		Email:      email,
		Passphrase: pass,
	})
	if err != nil {
		return fmt.Errorf("generate GPG key: %w", err)
	}
	state.KeyFingerprint = fpr
	state.KeyUID = fmt.Sprintf("%s <%s>", name, email)
	state.KeyIsNew = true
	fmt.Fprintf(opts.Out, "[v] GPG key generated: %s (ed25519/%s)\n",
		state.KeyUID, shortFpr(fpr))
	return nil
}

// uidOrFingerprint is a small formatting helper: prefer the UID when
// available, fall back to the fingerprint to keep the line informative
// on keys with no uid attached.
func uidOrFingerprint(k gpgsetup.KeyInfo) string {
	if k.UID != "" {
		return k.UID
	}
	return k.Fingerprint
}

// shortFpr returns a compact id like "9A2C…310A" from a 40-hex
// fingerprint. Inputs shorter than 8 chars are returned as-is.
func shortFpr(fpr string) string {
	if len(fpr) < 8 {
		return fpr
	}
	return fpr[:4] + "..." + fpr[len(fpr)-4:]
}

// resolveNameEmail returns the name and email for a new key, consulting
// flags → git config → interactive prompt (in that order). In --yes mode
// an empty result is an error instead of a prompt.
func resolveNameEmail(opts *initOptions) (string, string, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = gitConfigGlobal("user.name")
	}
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		email = gitConfigGlobal("user.email")
	}
	if name == "" || email == "" {
		if opts.Yes {
			return "", "", fmt.Errorf(
				"cannot derive name/email in --yes mode; pass --name/--email or set git config user.name/user.email")
		}
		br := bufio.NewReader(opts.In)
		if name == "" {
			fmt.Fprint(opts.Out, "Full name for the new GPG key: ")
			line, err := br.ReadString('\n')
			if err != nil && err != io.EOF {
				return "", "", err
			}
			name = strings.TrimSpace(line)
		}
		if email == "" {
			fmt.Fprint(opts.Out, "Email for the new GPG key: ")
			line, err := br.ReadString('\n')
			if err != nil && err != io.EOF {
				return "", "", err
			}
			email = strings.TrimSpace(line)
		}
	}
	if name == "" {
		return "", "", errors.New("name is required")
	}
	if email == "" {
		return "", "", errors.New("email is required")
	}
	return name, email, nil
}

// resolvePassphrase prompts twice (hidden, via x/term) and checks the
// inputs match. Minimum length 8 to avoid obviously-weak passphrases.
func resolvePassphrase(opts *initOptions) (string, error) {
	if opts.readPassphrase != nil {
		// Single call in tests — test doubles don't need to prove the
		// confirmation loop, only that the hook is honoured.
		return opts.readPassphrase("Passphrase for the new key (empty for none): ")
	}
	if opts.Yes {
		// --yes without --no-passphrase defaults to no passphrase; the
		// rationale is stated in the flag help so operators choosing the
		// non-interactive path know.
		return "", nil
	}
	// Only prompt if stdin is a TTY; otherwise behave like --yes.
	fd := stdinFD()
	if fd < 0 || !term.IsTerminal(fd) {
		return "", nil
	}
	fmt.Fprint(opts.Out, "Passphrase for the new GPG key (press enter for none): ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(opts.Out)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(first) == 0 {
		return "", nil
	}
	if len(first) < 8 {
		return "", errors.New("passphrase too short (min 8 characters)")
	}
	fmt.Fprint(opts.Out, "Repeat passphrase: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(opts.Out)
	if err != nil {
		return "", fmt.Errorf("read passphrase (confirm): %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("passphrases do not match")
	}
	return string(first), nil
}

// stdinFD returns the integer fd for os.Stdin, or -1 when stdin is not
// a file (pipe/socket). Kept in a helper so callers don't have to deal
// with the syscall package.
func stdinFD() int {
	f, ok := interface{}(os.Stdin).(*os.File)
	if !ok || f == nil {
		return -1
	}
	return int(f.Fd())
}

// promptSelectKey lets the user pick between multiple existing keys.
// `--yes` mode never calls this — it uses keys[0].
func promptSelectKey(opts *initOptions, keys []gpgsetup.KeyInfo) (gpgsetup.KeyInfo, error) {
	fmt.Fprintln(opts.Out, "Multiple GPG keys found — pick one:")
	for i, k := range keys {
		fmt.Fprintf(opts.Out, "  [%d] %s (%s)\n", i+1, uidOrFingerprint(k), shortFpr(k.Fingerprint))
	}
	br := bufio.NewReader(opts.In)
	for {
		fmt.Fprintf(opts.Out, "Selection [1]: ")
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return gpgsetup.KeyInfo{}, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return keys[0], nil
		}
		for i := range keys {
			if fmt.Sprintf("%d", i+1) == line {
				return keys[i], nil
			}
		}
		fmt.Fprintln(opts.Out, "Invalid selection, try again.")
	}
}

// gitConfigGlobal returns the value of a global git config key, or ""
// on any error (missing git, unset key, etc.). Not fatal.
func gitConfigGlobal(key string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	out, err := exec.Command("git", "config", "--global", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// syscallStdin is kept as an explicit reference so the syscall import
// doesn't get removed by goimports. stdinFD uses os.Stdin directly, but
// we want the syscall import available for future TTY-aware branches
// (e.g. secondary prompts for the SSH key passphrase).
var _ = syscall.Stdin

// ----- Step 2: gopass init -----

func stepGopass(ctx context.Context, opts *initOptions, state *initState) error {
	if state.KeyFingerprint == "" {
		return errors.New("no GPG key fingerprint — cannot initialise gopass")
	}
	if gopassinit.IsInitialised() {
		dir, _ := gopassinit.DefaultStoreDir()
		fmt.Fprintf(opts.Out, "[v] gopass store already initialised at %s\n", prettyPath(dir))
		return nil
	}
	fmt.Fprintln(opts.Out, "[+] Initialising gopass store...")
	if err := gopassinit.Initialise(ctx, state.KeyFingerprint); err != nil {
		return err
	}
	dir, _ := gopassinit.DefaultStoreDir()
	fmt.Fprintf(opts.Out, "[v] gopass store initialised at %s\n", prettyPath(dir))
	return nil
}

// ----- Step 3: pinentry-touchid -----

func stepPinentry(ctx context.Context, opts *initOptions, _ *initState) error {
	if runtime.GOOS != "darwin" {
		// Silent skip on non-macOS — this is not a problem, it's just
		// not applicable.
		return nil
	}
	if _, err := exec.LookPath("pinentry-touchid"); err != nil {
		// Missing binary. In interactive mode explain what it is and
		// offer to install it via brew. In --yes mode just skip with a
		// short line so the log stays quiet.
		if opts.Yes {
			fmt.Fprintln(opts.Out, "[!] pinentry-touchid not installed (skipped in --yes mode)")
			return nil
		}
		install, err := promptInstallPinentryTouchID(opts)
		if err != nil {
			return err
		}
		if !install {
			fmt.Fprintln(opts.Out, "[!] pinentry-touchid übersprungen — Passphrase-Prompts bleiben textbasiert.")
			return nil
		}
		if err := installPinentryTouchIDViaBrew(ctx, opts); err != nil {
			fmt.Fprintf(opts.Out, "[!] pinentry-touchid Installation fehlgeschlagen: %s\n", err.Error())
			fmt.Fprintln(opts.Out, "    Manuell: `brew install pinentry-touchid` + Re-run von `mys init`.")
			return nil
		}
		// LookPath again after install.
		if _, err := exec.LookPath("pinentry-touchid"); err != nil {
			fmt.Fprintln(opts.Out, "[!] pinentry-touchid nach Installation nicht auf PATH — neue Shell öffnen und `mys init` nochmal laufen lassen.")
			return nil
		}
	}
	configured, err := gpgsetup.EnsurePinentryTouchID(ctx)
	if err != nil {
		fmt.Fprintf(opts.Out, "[!] pinentry-touchid: %s\n", err.Error())
		return nil
	}
	home, _ := os.UserHomeDir()
	confPath := filepath.Join(home, ".gnupg", "gpg-agent.conf")
	if configured {
		fmt.Fprintf(opts.Out, "[v] pinentry-touchid configured in %s\n", prettyPath(confPath))
	} else {
		fmt.Fprintf(opts.Out, "[v] pinentry-touchid already configured in %s\n", prettyPath(confPath))
	}
	return nil
}

// promptInstallPinentryTouchID explains what Touch-ID integration buys
// and asks whether to run `brew install pinentry-touchid` right now.
func promptInstallPinentryTouchID(opts *initOptions) (bool, error) {
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Touch-ID für GPG einrichten?")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "`pinentry-touchid` leitet GPG-Passphrase-Abfragen auf den")
	fmt.Fprintln(opts.Out, "Touch-ID-Sensor deines Mac um. Statt „Passphrase tippen")
	fmt.Fprintln(opts.Out, "im Terminal\" tippst du jede `mys get`/`mys totp`/Git-Sync-Entsperrung")
	fmt.Fprintln(opts.Out, "mit dem Finger weg — spürbar schneller, und die Passphrase")
	fmt.Fprintln(opts.Out, "liegt in der macOS-Keychain statt im Shell-Verlauf.")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Ohne pinentry-touchid funktioniert my-secrets genauso,")
	fmt.Fprintln(opts.Out, "nur eben mit Text-Passphrase-Prompt. Später nachrüstbar")
	fmt.Fprintln(opts.Out, "mit `brew install pinentry-touchid` + Re-run von `mys init`.")
	fmt.Fprintln(opts.Out, "")
	if _, err := exec.LookPath("brew"); err != nil {
		fmt.Fprintln(opts.Out, "`brew` ist nicht auf PATH — Installation wird hier übersprungen.")
		fmt.Fprintln(opts.Out, "Installiere Homebrew unter https://brew.sh und re-run.")
		return false, nil
	}
	br := bufio.NewReader(opts.In)
	for {
		fmt.Fprint(opts.Out, "Jetzt `brew install pinentry-touchid`? [j/N]: ")
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "n", "nein", "no":
			return false, nil
		case "j", "ja", "y", "yes":
			return true, nil
		}
		fmt.Fprintln(opts.Out, "Bitte j oder n.")
	}
}

// installPinentryTouchIDViaBrew runs `brew install pinentry-touchid`
// with stdout/stderr piped through opts.Out so the user sees the progress.
// Returns any non-zero exit as an error; the caller decides how to
// surface it.
func installPinentryTouchIDViaBrew(ctx context.Context, opts *initOptions) error {
	fmt.Fprintln(opts.Out, "[+] Installing pinentry-touchid via brew...")
	cmd := exec.CommandContext(ctx, "brew", "install", "pinentry-touchid")
	cmd.Stdout = opts.Out
	cmd.Stderr = opts.Out
	return cmd.Run()
}

// ----- Step 4: policy + audit DB + init audit row -----

func stepState(ctx context.Context, opts *initOptions, state *initState) error {
	pp, err := policy.WriteDefault()
	if err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	state.PolicyPath = pp
	ap, _ := audit.DefaultPath()
	state.AuditPath = ap

	// Opening the App verifies the store AND the audit DB side-effect-
	// creates the audit SQLite on first use. Also writes the init row.
	a, err := app.Open(ctx, opts.Requester)
	if err != nil {
		return err
	}
	defer a.Close(ctx)
	a.AuditInit(ctx, "mys init")
	// Touch the store to surface ErrNotInitialized early — before we
	// claim success.
	if err := verifyStoreOpens(ctx); err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "[v] policy file: %s\n", prettyPath(pp))
	fmt.Fprintf(opts.Out, "[v] audit DB:    %s\n", prettyPath(ap))
	return nil
}

// verifyStoreOpens does a cheap sanity check that the gopass store is
// usable post-init. A failure at this point usually points at a GPG
// agent problem (wrong key, pinentry mis-configured) rather than an
// issue with my-secrets itself.
func verifyStoreOpens(ctx context.Context) error {
	st, err := store.Open(ctx)
	if err != nil {
		return fmt.Errorf("open gopass store: %w", err)
	}
	return st.Close(ctx)
}

// ----- Step 5: skill install -----

func stepSkill(ctx context.Context, opts *initOptions, state *initState) error {
	scope, install, err := decideSkillInstall(opts)
	if err != nil {
		return err
	}
	if !install {
		return nil
	}
	// Build a synthetic *cobra.Command for installSkillAt to satisfy
	// its current signature. The command object is only used for its
	// Out writer, which installSkillAt does not actually touch.
	fake := &cobra.Command{}
	dst, _, err := installSkillAt(fake, scope, "")
	if err != nil {
		return fmt.Errorf("install skill: %w", err)
	}
	state.SkillDst = dst
	state.SkillScope = scope
	fmt.Fprintf(opts.Out, "[v] claude skill linked to %s (scope=%s)\n", prettyPath(dst), scope)
	writeSkillInstallAudit(ctx, opts.Requester, scope, dst)
	return nil
}

// decideSkillInstall returns (scope, install, err). The rules:
//
//   - --install-skill explicit: install with the given --skill-scope
//     (default global). Non-interactive, no prompt.
//   - --yes without --install-skill: skip (the user opted into fully
//     non-interactive and did not ask for the skill).
//   - interactive, --install-skill not explicit: prompt for g/l/n.
func decideSkillInstall(opts *initOptions) (string, bool, error) {
	if opts.installSkillExplicit {
		if !opts.InstallSkill {
			return "", false, nil
		}
		s, err := normaliseSkillScope(opts.SkillScope)
		return s, err == nil, err
	}
	if opts.Yes {
		return "", false, nil
	}
	return promptSkillInstall(opts)
}

// promptSkillInstall shows the g/l/n picker with the explanation the
// coordinator specified. Default is g (global).
func promptSkillInstall(opts *initOptions) (string, bool, error) {
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Claude Code Skill installieren?")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Der Skill verlinkt ~/.claude/skills/my-secrets (oder ein projekt-")
	fmt.Fprintln(opts.Out, "spezifisches .claude/skills/my-secrets) auf dieses Repo. Damit")
	fmt.Fprintln(opts.Out, "weiß Claude Code automatisch, wie es mit my-secrets umgehen soll —")
	fmt.Fprintln(opts.Out, "Secrets werden ausschließlich über den audit-gated MCP-Server")
	fmt.Fprintln(opts.Out, "gelesen, nie direkt aus ~/.password-store.")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "  [g]lobal  — ~/.claude/skills/my-secrets (empfohlen: gilt für alle Projekte)")
	fmt.Fprintln(opts.Out, "  [l]okal   — <CWD>/.claude/skills/my-secrets (nur aktuelles Projekt)")
	fmt.Fprintln(opts.Out, "  [n]ein    — überspringen")
	fmt.Fprintln(opts.Out, "")
	br := bufio.NewReader(opts.In)
	for {
		fmt.Fprint(opts.Out, "Auswahl [g/l/n] (default: g): ")
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", false, err
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "g", "global":
			return skillScopeGlobal, true, nil
		case "l", "local", "lokal":
			return skillScopeLocal, true, nil
		case "n", "no", "nein":
			return "", false, nil
		}
		fmt.Fprintln(opts.Out, "Ungültige Auswahl — bitte g, l oder n.")
	}
}

// writeSkillInstallAudit is best-effort — a missing audit DB must not
// fail the install. The app layer already logged the init event, so
// even if this row is lost the user sees the install on stdout.
func writeSkillInstallAudit(ctx context.Context, requester, scope, dst string) {
	a, err := app.OpenAuditOnly()
	if err != nil {
		return
	}
	defer a.Close(ctx)
	d := caller.Identify(requester)
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:    audit.ActionSkillInstall,
		ActorKind: string(d.Kind),
		Result:    audit.ResultOK,
		Reason:    fmt.Sprintf("scope=%s path=%s", scope, dst),
	})
}

// ----- Step 6: optional sync setup -----

func stepSync(ctx context.Context, opts *initOptions, state *initState) error {
	// Decision tree matches the skill-install flow exactly:
	//   --with-sync           explicit yes, run wizard non-interactively if --yes
	//   --with-sync=false     explicit no, skip
	//   no flag + --yes       skip (non-interactive, no prompt)
	//   no flag + interactive prompt the user; run wizard on „y"
	shouldRun := opts.WithSync
	if !opts.withSyncExplicit && !opts.Yes {
		want, err := promptSync(opts)
		if err != nil {
			return err
		}
		shouldRun = want
	}
	if !shouldRun {
		return nil
	}
	// Errors from here on are fatal — the user asked for sync.
	cfg, err := syncpkg.RunWizard(ctx, syncpkg.WizardIO{In: opts.In, Out: opts.Out},
		syncpkg.WizardOptions{
			NonInteractive: opts.Yes,
		})
	if err != nil {
		return err
	}
	if cfg != nil && len(cfg.Remotes) > 0 {
		state.SyncRepoURL = cfg.Remotes[0].URL
		// Persist the config so the next run can see it.
		if err := syncpkg.Save("", cfg); err != nil {
			return err
		}
		fmt.Fprintf(opts.Out, "[v] git sync set up → %s\n", state.SyncRepoURL)
	}
	return nil
}

// promptSync asks the user whether to run the sync wizard right now.
// Output mirrors the skill-install prompt so both end-of-init questions
// feel the same. Returns true on y/yes/ja, false on the default (n).
func promptSync(opts *initOptions) (bool, error) {
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Git-Sync nach GitHub einrichten?")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Der Sync spiegelt die verschlüsselten gopass-Dateien in")
	fmt.Fprintln(opts.Out, "ein privates GitHub-Repo. Damit sind deine Secrets auf")
	fmt.Fprintln(opts.Out, "einem zweiten Gerät wiederherstellbar, falls dieser Rechner")
	fmt.Fprintln(opts.Out, "ausfällt. Ohne den GPG-Key bleiben die Dateien auf GitHub")
	fmt.Fprintln(opts.Out, "nutzloser Kryptotext — nur für dich lesbar.")
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Der Wizard fragt danach: ein gemeinsames Repo für alle")
	fmt.Fprintln(opts.Out, "Orgs, oder ein eigenes Repo pro Org (jasp, zuhause, …).")
	fmt.Fprintln(opts.Out, "Scope bleibt persönlich: für Team-Sharing gibt es Bitwarden.")
	fmt.Fprintln(opts.Out, "")
	br := bufio.NewReader(opts.In)
	for {
		fmt.Fprint(opts.Out, "Jetzt einrichten? [j/N]: ")
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "n", "nein", "no":
			return false, nil
		case "j", "ja", "y", "yes":
			return true, nil
		}
		fmt.Fprintln(opts.Out, "Bitte j oder n.")
	}
}

// prettyPath replaces the user's HOME prefix with ~ for a more compact
// display. Falls back to the original path on any error.
func prettyPath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	if p == home {
		return "~"
	}
	return p
}
