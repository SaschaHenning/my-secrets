// Package main is the my-secrets CLI, web UI, and MCP server entrypoint.
// All three modes share the same app-layer orchestration so every access
// ends up in the same audit log.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/mcp"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/web"
	"github.com/spf13/cobra"
)

// Version is set via ldflags at build time. Fallback for `go run`.
var Version = "dev"

var (
	flagRequester string
	flagReveal    bool
	flagOrg       string
	flagTag       string
	flagKind      string
	flagField     string
	flagFormat    string
	flagLimit     int
	flagActor     string
	flagAction    string
	flagPort      int
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mys",
		Short:         "my-secrets — local credential manager with audit log",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	root.PersistentFlags().StringVar(&flagRequester, "requester", "",
		"explicit caller label (claude-code | human | script | ai). Cannot downgrade detected AI signals.")

	root.AddCommand(initCmd(), lsCmd(), searchCmd(), getCmd(), addCmd(),
		rotateCmd(), rmCmd(), auditCmd(), webCmd(), mcpCmd(), bwExportCmd(),
		installSkillCmd())
	return root
}

// --- init -----------------------------------------------------------------

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialise gopass, default org folders, policy, audit DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// 1. Check that gopass CLI is on PATH (we only use it for initial setup).
			if _, err := exec.LookPath("gopass"); err != nil {
				return fmt.Errorf("gopass binary not found on PATH — run `brew install gopass` first")
			}
			// 2. Ensure store exists — if not, run `gopass setup` interactively.
			ss, err := store.Open(ctx)
			if err != nil {
				if errors.Is(err, store.ErrNotInitialized) ||
					strings.Contains(err.Error(), "not initialized") {
					fmt.Fprintln(cmd.OutOrStdout(), "gopass store not initialised — run `gopass setup` first, then re-run `mys init`.")
					return nil
				}
				return err
			}
			_ = ss.Close(ctx)

			// 3. Write default policy if missing.
			pp, err := policy.WriteDefault()
			if err != nil {
				return fmt.Errorf("write policy: %w", err)
			}
			ap, _ := audit.DefaultPath()

			// 4. Open the app (which opens the audit DB) and write the init row.
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			a.AuditInit(ctx, "mys init")

			fmt.Fprintf(cmd.OutOrStdout(), "my-secrets initialised.\n  policy: %s\n  audit:  %s\n", pp, ap)
			return nil
		},
	}
}

// --- ls --------------------------------------------------------------------

func lsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ls",
		Short: "List secret paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			paths, err := a.List(ctx, flagOrg)
			if err != nil {
				return err
			}
			// Optional tag filter requires decrypting each entry's metadata.
			if flagTag != "" {
				filtered := make([]string, 0, len(paths))
				for _, p := range paths {
					e, err := a.Get(ctx, p)
					if err != nil {
						continue
					}
					for _, t := range e.Tags {
						if t == flagTag {
							filtered = append(filtered, p)
							break
						}
					}
				}
				paths = filtered
			}
			for _, p := range paths {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
	c.Flags().StringVar(&flagOrg, "org", "", "filter by org (top-level folder)")
	c.Flags().StringVar(&flagTag, "tag", "", "filter by tag (exact match); requires decrypting entries")
	return c
}

// --- search ----------------------------------------------------------------

func searchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search secret paths and metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			paths, err := a.Search(ctx, args[0])
			if err != nil {
				return err
			}
			for _, p := range paths {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
}

// --- get -------------------------------------------------------------------

func getCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "get <path>",
		Short: "Fetch a secret (password masked by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			e, err := a.Get(ctx, args[0])
			if err != nil {
				return err
			}
			return printEntry(cmd.OutOrStdout(), e, flagField, flagReveal, flagFormat)
		},
	}
	c.Flags().StringVar(&flagField, "field", "", "print only one field: password | username | url | notes")
	c.Flags().BoolVar(&flagReveal, "reveal", false, "reveal password in output (default: masked)")
	c.Flags().StringVar(&flagFormat, "format", "text", "output format: text | json | env")
	return c
}

func printEntry(w io.Writer, e *store.Entry, field string, reveal bool, format string) error {
	switch format {
	case "json":
		payload := map[string]any{
			"path":           e.Path,
			"org":            e.Org,
			"kind":           e.Kind,
			"username":       e.Username,
			"url":            e.URL,
			"github_project": e.GitHubProject,
			"tags":           e.Tags,
			"notes":          e.Notes,
		}
		if reveal {
			payload["password"] = e.Password
		} else {
			payload["password"] = store.MaskedPassword(e.Password)
		}
		return json.NewEncoder(w).Encode(payload)
	case "env":
		if e.Username != "" {
			fmt.Fprintf(w, "USERNAME=%s\n", shellQuote(e.Username))
		}
		if reveal {
			fmt.Fprintf(w, "PASSWORD=%s\n", shellQuote(e.Password))
		}
		if e.URL != "" {
			fmt.Fprintf(w, "URL=%s\n", shellQuote(e.URL))
		}
		return nil
	}
	// default: text
	if field != "" {
		switch field {
		case "password":
			if reveal {
				fmt.Fprintln(w, e.Password)
			} else {
				fmt.Fprintln(w, store.MaskedPassword(e.Password))
			}
		case "username":
			fmt.Fprintln(w, e.Username)
		case "url":
			fmt.Fprintln(w, e.URL)
		case "notes":
			fmt.Fprintln(w, e.Notes)
		default:
			return fmt.Errorf("unknown field %q", field)
		}
		return nil
	}
	fmt.Fprintf(w, "path:     %s\n", e.Path)
	fmt.Fprintf(w, "org:      %s\n", e.Org)
	fmt.Fprintf(w, "kind:     %s\n", e.Kind)
	fmt.Fprintf(w, "username: %s\n", e.Username)
	fmt.Fprintf(w, "url:      %s\n", e.URL)
	if e.GitHubProject != "" {
		fmt.Fprintf(w, "github:   %s\n", e.GitHubProject)
	}
	if len(e.Tags) > 0 {
		fmt.Fprintf(w, "tags:     %s\n", strings.Join(e.Tags, ", "))
	}
	if e.Notes != "" {
		fmt.Fprintf(w, "notes:    %s\n", e.Notes)
	}
	if reveal {
		fmt.Fprintf(w, "password: %s\n", e.Password)
	} else {
		fmt.Fprintf(w, "password: %s  (use --reveal to show)\n", store.MaskedPassword(e.Password))
	}
	return nil
}

func shellQuote(s string) string {
	if s == "" {
		return "\"\""
	}
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + "\""
}

// --- add -------------------------------------------------------------------

func addCmd() *cobra.Command {
	var (
		username, url, githubProj, notes string
		tagsRaw                          string
	)
	c := &cobra.Command{
		Use:   "add <path>",
		Short: "Add or overwrite an entry; reads the password from stdin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			pw, err := readPasswordStdin(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			e := &store.Entry{
				Path:          args[0],
				Org:           store.OrgOf(args[0]),
				Kind:          flagKind,
				Username:      username,
				URL:           url,
				GitHubProject: githubProj,
				Notes:         notes,
				Password:      pw,
			}
			if tagsRaw != "" {
				for _, t := range strings.Split(tagsRaw, ",") {
					e.Tags = append(e.Tags, strings.TrimSpace(t))
				}
			}
			if err := a.Add(ctx, e); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %s\n", e.Path)
			return nil
		},
	}
	c.Flags().StringVar(&flagKind, "kind", store.KindPassword, "kind of secret")
	c.Flags().StringVar(&username, "user", "", "username")
	c.Flags().StringVar(&url, "url", "", "URL")
	c.Flags().StringVar(&githubProj, "github", "", "related GitHub project (owner/name)")
	c.Flags().StringVar(&notes, "notes", "", "free-form notes")
	c.Flags().StringVar(&tagsRaw, "tags", "", "comma-separated tags")
	return c
}

func readPasswordStdin(errOut io.Writer) (string, error) {
	fi, _ := os.Stdin.Stat()
	isPiped := (fi.Mode() & os.ModeCharDevice) == 0
	if isPiped {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	// Interactive: prompt
	fmt.Fprint(errOut, "password: ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// --- rotate ----------------------------------------------------------------

func rotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <path>",
		Short: "Rotate password (reads new password from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			pw, err := readPasswordStdin(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			if err := a.Rotate(ctx, args[0], pw); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotated %s\n", args[0])
			return nil
		},
	}
}

// --- rm --------------------------------------------------------------------

func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <path>",
		Short: "Remove an entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			if err := a.Remove(ctx, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	}
}

// --- audit -----------------------------------------------------------------

func auditCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "audit",
		Short: "Audit log commands",
	}
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
				Actor: flagActor, Action: flagAction, Org: flagOrg, Limit: flagLimit,
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
	tail.Flags().StringVar(&flagActor, "actor", "", "filter actor_kind (human|ai|script)")
	tail.Flags().StringVar(&flagAction, "action", "", "filter action (get|list|...)")
	tail.Flags().StringVar(&flagOrg, "org", "", "filter org")
	tail.Flags().IntVar(&flagLimit, "limit", 50, "max rows")

	var sinceStr string
	since := &cobra.Command{
		Use:   "since <date>",
		Short: "Show entries since a date (YYYY-MM-DD or RFC3339 timestamp)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			sinceStr = args[0]
			t, err := parseSince(sinceStr)
			if err != nil {
				return err
			}
			a, err := app.OpenAuditOnly()
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			entries, err := a.Audit.Tail(ctx, audit.Filter{
				Actor: flagActor, Action: flagAction, Org: flagOrg,
				Since: t, Limit: flagLimit,
			})
			if err != nil {
				return err
			}
			if flagFormat == "json" {
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
	since.Flags().StringVar(&flagActor, "actor", "", "filter actor_kind")
	since.Flags().StringVar(&flagAction, "action", "", "filter action")
	since.Flags().StringVar(&flagOrg, "org", "", "filter org")
	since.Flags().IntVar(&flagLimit, "limit", 200, "max rows")
	since.Flags().StringVar(&flagFormat, "format", "text", "output format: text | json")

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

// --- web -------------------------------------------------------------------

func webCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "web",
		Short: "Start the localhost web UI",
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
			return web.Serve(ctx, a, flagPort, cmd.OutOrStdout())
		},
	}
	c.Flags().IntVar(&flagPort, "port", 7823, "listen port")
	return c
}

// --- mcp -------------------------------------------------------------------

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run as MCP server over stdio (AI tool entrypoint)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Force the AI classification regardless of env.
			a, err := app.Open(ctx, "claude-code")
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return mcp.Serve(ctx, a, os.Stdin, os.Stdout)
		},
	}
}

// --- bw-export -------------------------------------------------------------

func bwExportCmd() *cobra.Command {
	var (
		out     string
		confirm bool
	)
	c := &cobra.Command{
		Use:   "bw-export",
		Short: "Export entries as Bitwarden-compatible JSON (one-way, PLAINTEXT)",
		Long: `Exports every secret in the selected org to a Bitwarden-compatible JSON file.
The output is PLAINTEXT — do not leave it on disk.

Requires --reveal AND --i-understand to run. AI callers cannot invoke this
command; it is rejected for actor_kind=ai.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if !flagReveal || !confirm {
				return fmt.Errorf("bw-export requires both --reveal and --i-understand; refusing")
			}
			// Deny AI-flagged callers outright.
			detected := caller.Identify(flagRequester)
			if detected.Kind == caller.KindAI {
				return fmt.Errorf("bw-export is refused for AI callers")
			}
			a, err := app.Open(ctx, flagRequester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			paths, err := a.List(ctx, flagOrg)
			if err != nil {
				return err
			}
			items := make([]map[string]any, 0, len(paths))
			for _, p := range paths {
				e, err := a.Get(ctx, p)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "skip %s: %v\n", p, err)
					continue
				}
				items = append(items, map[string]any{
					"name":  p,
					"notes": e.Notes,
					"login": map[string]any{
						"username": e.Username,
						"password": e.Password,
						"uris": []map[string]any{
							{"uri": e.URL},
						},
					},
					"folderId": e.Org,
				})
			}
			payload := map[string]any{
				"encrypted": false,
				"folders":   []map[string]any{},
				"items":     items,
			}
			if out == "" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
			}
			// 0o600 — file must not be world- or group-readable.
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(payload)
		},
	}
	c.Flags().StringVar(&flagOrg, "org", "", "filter by org")
	c.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	c.Flags().BoolVar(&flagReveal, "reveal", false, "REQUIRED — acknowledge that output contains plaintext passwords")
	c.Flags().BoolVar(&confirm, "i-understand", false, "REQUIRED — confirm you understand plaintext will be written")
	return c
}

// --- install-skill ---------------------------------------------------------

func installSkillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-skill",
		Short: "Install the Claude Code skill into ~/.claude/skills/my-secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			// Look for the repo-relative skill directory by walking up from
			// the binary's location.
			src, err := findSkillSource()
			if err != nil {
				return err
			}
			dst := filepath.Join(home, ".claude", "skills", "my-secrets")
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			// If dst exists as a symlink or dir, replace it.
			_ = os.RemoveAll(dst)
			if err := os.Symlink(src, dst); err != nil {
				return fmt.Errorf("symlink skill: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "linked %s → %s\n", dst, src)
			return nil
		},
	}
}

func findSkillSource() (string, error) {
	// Expected layout: <repo>/skills/my-secrets/SKILL.md and binary in <repo>
	// or <repo>/cmd/mys. Search upward from CWD.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := cwd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "skills", "my-secrets")
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not locate skills/my-secrets directory upward from %s", cwd)
}
