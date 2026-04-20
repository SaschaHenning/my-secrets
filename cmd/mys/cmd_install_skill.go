package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// skillAssets holds the skill files that ship with the binary. Embedding
// them means `mys install-skill` works from any working directory and
// does not need the repo checkout to be present — which is the whole
// point of an installed CLI.
//
//go:embed skills_embed/my-secrets/*
var skillAssets embed.FS

// skillEmbedRoot is the on-disk path inside the embed.FS that mirrors
// the repo's skills/my-secrets/ directory. Kept as a const so tests can
// agree on the layout without poking at embed internals.
const skillEmbedRoot = "skills_embed/my-secrets"

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
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s (from %s)\n", dst, src)
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

// installSkillAt writes the embedded skill files into the scope-specific
// destination. It replaces any previous install (symlink or directory)
// so repeated calls are idempotent.
//
// The `src` return value is a short description of where the skill
// content came from — useful for logging. Embedded content reports
// "embedded assets".
func installSkillAt(cmd *cobra.Command, scope, cwdOverride string) (dst, src string, err error) {
	dst, err = skillInstallPath(scope, cwdOverride)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", "", err
	}
	// Remove any previous install (may be a symlink from an older mys
	// version or a directory from a partial write).
	_ = os.RemoveAll(dst)

	if err := writeEmbeddedSkill(dst); err != nil {
		return "", "", fmt.Errorf("write skill: %w", err)
	}
	return dst, "embedded assets", nil
}

// writeEmbeddedSkill copies every file under skillEmbedRoot out of the
// embed.FS into dst, preserving relative paths. Files are created with
// 0644 and intermediate directories with 0755.
func writeEmbeddedSkill(dst string) error {
	return fs.WalkDir(skillAssets, skillEmbedRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(skillEmbedRoot, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := skillAssets.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
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
