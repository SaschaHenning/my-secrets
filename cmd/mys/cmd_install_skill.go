package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// installSkillCmd is a compatibility alias for `mys init --install-skill`.
// It remains a standalone subcommand so scripted setups (and existing docs)
// keep working, but internally it routes through the same helper so the
// behaviour can never drift between the two entry points.
func installSkillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-skill",
		Short: "Install the Claude Code skill into ~/.claude/skills/my-secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, src, err := installSkill(cmd)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "linked %s → %s\n", dst, src)
			return nil
		},
	}
}

// installSkill performs the skill-install side-effect used by both
// `mys install-skill` and `mys init --install-skill`. It intentionally does
// not print anything — callers format their own output so the two commands
// can keep their distinct messages.
func installSkill(cmd *cobra.Command) (dst, src string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	src, err = findSkillSource()
	if err != nil {
		return "", "", err
	}
	dst = filepath.Join(home, ".claude", "skills", "my-secrets")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", "", err
	}
	_ = os.RemoveAll(dst)
	if err := os.Symlink(src, dst); err != nil {
		return "", "", fmt.Errorf("symlink skill: %w", err)
	}
	return dst, src, nil
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
