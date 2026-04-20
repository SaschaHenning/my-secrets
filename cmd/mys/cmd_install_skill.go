package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Scope values for the skill install. "global" lives under ~/.claude,
// "local" under <cwd>/.claude so the skill only applies inside that
// project checkout.
const (
	skillScopeGlobal = "global"
	skillScopeLocal  = "local"
)

// installSkillCmd is a compatibility alias for `mys init --install-skill`.
// It remains a standalone subcommand so scripted setups (and existing docs)
// keep working, but internally it routes through the same helper so the
// behaviour can never drift between the two entry points.
func installSkillCmd() *cobra.Command {
	var scope string
	c := &cobra.Command{
		Use:   "install-skill",
		Short: "Install the Claude Code skill into ~/.claude/skills/my-secrets (or a local project)",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := normaliseSkillScope(scope)
			if err != nil {
				return err
			}
			dst, src, err := installSkillAt(cmd, s, "")
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "linked %s → %s\n", dst, src)
			return nil
		},
	}
	c.Flags().StringVar(&scope, "scope", skillScopeGlobal,
		"where to install: global (~/.claude) or local (<cwd>/.claude)")
	return c
}

// normaliseSkillScope trims/lowercases and validates the scope flag so
// both `--install-skill=local` on init and `--scope local` on the
// standalone command end up in the same state.
func normaliseSkillScope(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "g", "global":
		return skillScopeGlobal, nil
	case "l", "local":
		return skillScopeLocal, nil
	}
	return "", fmt.Errorf("unknown skill scope %q (use global or local)", s)
}

// installSkill is kept for callers that want the pre-existing behaviour
// (global install, silent on success). New code should call
// installSkillAt directly so the scope is explicit.
func installSkill(cmd *cobra.Command) (dst, src string, err error) {
	return installSkillAt(cmd, skillScopeGlobal, "")
}

// installSkillAt performs the skill-install side-effect for the given
// scope. It does not print anything — callers format their own output.
//
// scope is one of skillScopeGlobal / skillScopeLocal. cwdOverride is
// intended for tests; production callers pass "" and the function
// uses os.Getwd().
func installSkillAt(cmd *cobra.Command, scope, cwdOverride string) (dst, src string, err error) {
	src, err = findSkillSource()
	if err != nil {
		return "", "", err
	}
	dst, err = skillInstallPath(scope, cwdOverride)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", "", err
	}
	// Remove any existing entry (symlink OR directory) so repeated
	// installs always end at a fresh link pointing at the current repo.
	_ = os.RemoveAll(dst)
	if err := os.Symlink(src, dst); err != nil {
		return "", "", fmt.Errorf("symlink skill: %w", err)
	}
	return dst, src, nil
}

// skillInstallPath returns the target path for the given scope.
func skillInstallPath(scope, cwdOverride string) (string, error) {
	switch scope {
	case skillScopeGlobal:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "skills", "my-secrets"), nil
	case skillScopeLocal:
		cwd := cwdOverride
		if cwd == "" {
			wd, err := os.Getwd()
			if err != nil {
				return "", err
			}
			cwd = wd
		}
		return filepath.Join(cwd, ".claude", "skills", "my-secrets"), nil
	}
	return "", fmt.Errorf("unknown skill scope %q", scope)
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
