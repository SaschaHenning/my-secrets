// Wizard flow for `mys sync setup`. Each prompt is a small exported
// function so tests can drive the flow with injected io.Reader /
// io.Writer and assert on the rendered text.
package sync

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// ScopeDisclaimer is the hard scope anchor. It is printed at the start
// of the wizard and MUST NOT be removed or softened — the whole point
// of my-secrets is that it is PERSONAL. For team sharing, Bitwarden is
// the right tool.
const ScopeDisclaimer = `
Hinweis zum Einsatzzweck
────────────────────────
my-secrets ist ein PERSÖNLICHER Credential-Manager. Git-Sync dient der
Redundanz über deine EIGENEN Geräte — NICHT dem Teilen mit Kolleg:innen.
Für Team-Secrets nutze Bitwarden oder einen vergleichbaren Tresor mit
personalisiertem Login. Ein mit Kollegen geteilter GPG-Key kann nicht
zwischen Menschen unterscheiden und wäre aus Audit-Sicht eine schwarze
Box.
`

// WizardIO bundles the streams the wizard reads from and writes to.
// Tests construct a WizardIO with strings.Reader / bytes.Buffer to drive
// the prompts deterministically.
type WizardIO struct {
	In  io.Reader
	Out io.Writer
}

// WizardOptions are the non-prompt knobs the wizard honours.
type WizardOptions struct {
	// NonInteractive skips every prompt, answers every yes/no question
	// with its default, and runs the layout implied by Layout. Used by
	// CI tests and by `mys sync setup --yes`.
	NonInteractive bool
	// Layout forces a specific layout in non-interactive mode. If empty
	// and NonInteractive is true, defaults to LayoutSingle.
	Layout Layout
	// RemoteStyle forces the URL style. Defaults to RemoteSSH.
	RemoteStyle RemoteStyle
	// SingleRepoName overrides the default repo name in LayoutSingle.
	SingleRepoName string
	// Orgs lists the orgs present in the store. Required for
	// LayoutPerOrg; the wizard prompts the user to confirm each.
	Orgs []string
	// Owner overrides the detected `gh` user. Set by tests.
	Owner string
	// Runner injects subprocess behaviour. Tests substitute a fake;
	// nil uses ExecRunner.
	Runner Runner
	// DryRun: skip every subprocess call (gh/gopass). Tests use this
	// together with a non-nil Runner that records the attempted calls.
	DryRun bool
}

// RunWizard executes the full setup flow. On success it returns the
// Config it persisted. Intended to be called from the CLI.
func RunWizard(ctx context.Context, io WizardIO, opts WizardOptions) (*Config, error) {
	br := bufio.NewReader(io.In)

	fmt.Fprint(io.Out, ScopeDisclaimer)
	if !opts.NonInteractive {
		ok, err := PromptYesNo(br, io.Out, "Verstanden — weiter mit dem Setup?", true)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("setup abgebrochen")
		}
	}

	layout, err := PromptLayout(br, io.Out, opts)
	if err != nil {
		return nil, err
	}

	owner := opts.Owner
	if owner == "" {
		got, err := GhCurrentUser(ctx, opts.Runner)
		if err != nil {
			return nil, err
		}
		owner = got
	}

	// Default remote style: whatever the user's gh CLI is already
	// using. If `gh auth status` reports https, we stick with https —
	// otherwise ssh. This avoids silently picking ssh on machines
	// where the user has never set up an SSH key, or where port 22 to
	// GitHub is firewalled.
	style := opts.RemoteStyle
	if style == "" {
		style = DetectRemoteStyle(ctx, opts.Runner)
		fmt.Fprintf(io.Out, "Git-Protokoll laut `gh auth status`: %s\n", style)
	}

	cfg := &Config{Version: 1, Layout: layout, Owner: owner}

	switch layout {
	case LayoutSingle:
		name := opts.SingleRepoName
		if name == "" {
			name = SingleRepoDefaultName
		}
		if !opts.NonInteractive {
			got, err := PromptString(br, io.Out,
				fmt.Sprintf("Repo-Name für den Store [%s]:", name), name)
			if err != nil {
				return nil, err
			}
			name = got
		}
		if err := configureRepo(ctx, io.Out, opts, cfg, DefaultStoreMount, owner, name, style); err != nil {
			return nil, err
		}
	case LayoutPerOrg:
		orgs := opts.Orgs
		if len(orgs) == 0 {
			return nil, fmt.Errorf("per-org layout gewählt, aber keine Orgs gefunden — lege zuerst Einträge unter einem Org-Prefix an")
		}
		for _, org := range orgs {
			name := PerOrgRepoName(org)
			if !opts.NonInteractive {
				got, err := PromptString(br, io.Out,
					fmt.Sprintf("Repo-Name für Org %q [%s]:", org, name), name)
				if err != nil {
					return nil, err
				}
				name = got
			}
			if err := configureRepo(ctx, io.Out, opts, cfg, org, owner, name, style); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unbekanntes Layout: %q", layout)
	}

	// Initial sync — surfaces GPG prompt once, right after setup.
	if !opts.DryRun {
		for _, r := range cfg.Remotes {
			fmt.Fprintf(io.Out, "Initialer Sync für Mount %q...\n", r.Mount)
			if _, err := GopassSync(ctx, opts.Runner, r.Mount); err != nil {
				return nil, fmt.Errorf("initial sync for %q: %w", r.Mount, err)
			}
			cfg.MarkSynced(r.Mount, time.Now())
		}
	}

	return cfg, nil
}

// PromptLayout asks the user to choose single-repo vs per-org. In
// non-interactive mode it returns opts.Layout (default LayoutSingle).
func PromptLayout(br *bufio.Reader, out io.Writer, opts WizardOptions) (Layout, error) {
	if opts.NonInteractive {
		if opts.Layout == "" {
			return LayoutSingle, nil
		}
		return opts.Layout, nil
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Layout wählen:")
	fmt.Fprintln(out, "  [1] Ein einziges Repo für den ganzen Store (empfohlen)")
	fmt.Fprintln(out, "  [2] Ein Repo pro Org (gopass-Mounts)")
	for {
		answer, err := PromptString(br, out, "Auswahl [1]:", "1")
		if err != nil {
			return "", err
		}
		switch strings.TrimSpace(answer) {
		case "1", "single", "s":
			return LayoutSingle, nil
		case "2", "per-org", "org":
			return LayoutPerOrg, nil
		}
		fmt.Fprintln(out, "Ungültige Auswahl — bitte 1 oder 2 eingeben.")
	}
}

// PromptYesNo reads a y/n answer. An empty input returns def.
func PromptYesNo(br *bufio.Reader, out io.Writer, question string, def bool) (bool, error) {
	suffix := "[Y/n]"
	if !def {
		suffix = "[y/N]"
	}
	fmt.Fprintf(out, "%s %s ", question, suffix)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	switch line {
	case "":
		return def, nil
	case "y", "yes", "j", "ja":
		return true, nil
	case "n", "no", "nein":
		return false, nil
	}
	return def, nil
}

// PromptString reads a single-line string answer. An empty input returns def.
func PromptString(br *bufio.Reader, out io.Writer, question, def string) (string, error) {
	fmt.Fprintf(out, "%s ", question)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// configureRepo runs the per-remote subprocess flow: ensure GH repo
// exists, init gopass git, add origin, record the remote in cfg.
func configureRepo(ctx context.Context, out io.Writer, opts WizardOptions, cfg *Config, mount, owner, name string, style RemoteStyle) error {
	url, err := BuildRemoteURL(style, owner, name)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Fprintf(out, "[dry-run] würde Repo %s/%s anlegen und als %s-Remote auf Mount %q setzen\n", owner, name, style, mount)
		cfg.UpdateRemote(mount, url)
		return nil
	}

	exists, err := GhRepoExists(ctx, opts.Runner, owner, name)
	if err != nil {
		return fmt.Errorf("check repo %s/%s: %w", owner, name, err)
	}
	if !exists {
		fmt.Fprintf(out, "Erstelle privates Repo %s/%s ...\n", owner, name)
		if _, err := GhRepoCreate(ctx, opts.Runner, owner, name); err != nil {
			return fmt.Errorf("create repo %s/%s: %w", owner, name, err)
		}
	} else {
		fmt.Fprintf(out, "Repo %s/%s existiert bereits — verwende es weiter.\n", owner, name)
	}

	fmt.Fprintf(out, "Initialisiere gopass-Git auf Mount %q ...\n", mount)
	if _, err := GopassGitInit(ctx, opts.Runner, mount); err != nil {
		// Already-initialised is fine; surface other errors.
		if !strings.Contains(err.Error(), "already") {
			return err
		}
	}
	fmt.Fprintf(out, "Setze Remote origin → %s\n", url)
	if _, err := GopassGitRemoteAdd(ctx, opts.Runner, mount, url); err != nil {
		if !strings.Contains(err.Error(), "already") {
			return err
		}
	}
	// If we picked HTTPS, make sure `gh` is registered as git's
	// credential helper so the first push succeeds without manual
	// setup. Quiet failure — the user can still run `gh auth setup-git`
	// by hand if this step is unavailable for some reason.
	if style == RemoteHTTPS {
		if _, err := opts.Runner.Run(ctx, "gh", "auth", "setup-git"); err == nil {
			fmt.Fprintln(out, "Git-Credential-Helper via `gh auth setup-git` gesetzt (HTTPS-Pushes gehen jetzt mit dem gh-Token).")
		}
	}
	cfg.UpdateRemote(mount, url)
	return nil
}
