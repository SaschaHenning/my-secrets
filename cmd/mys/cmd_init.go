package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// initCmd builds the `mys init` subcommand.
func initCmd(requester *string) *cobra.Command {
	var installSkillFlag bool
	c := &cobra.Command{
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
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			a.AuditInit(ctx, "mys init")

			fmt.Fprintf(cmd.OutOrStdout(), "my-secrets initialised.\n  policy: %s\n  audit:  %s\n", pp, ap)

			// 5. Optionally install the Claude Code skill in the same step so
			// users get a one-command setup. A failure here must surface as
			// an error — the flag has no value if it silently no-ops.
			if installSkillFlag {
				dst, _, err := installSkill(cmd)
				if err != nil {
					return fmt.Errorf("install skill: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  skill:  %s\n", dst)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&installSkillFlag, "install-skill", false,
		"also install the Claude Code skill (symlink ~/.claude/skills/my-secrets → repo)")
	return c
}
