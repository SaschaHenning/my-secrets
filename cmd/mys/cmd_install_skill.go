package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// installSkillCmd builds the `mys install-skill` subcommand.
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
