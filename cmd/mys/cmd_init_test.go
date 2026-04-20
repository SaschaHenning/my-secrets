package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestInstallSkillHelper exercises the installSkill helper in isolation:
// it must locate a repo-relative skills/my-secrets directory, create the
// ~/.claude/skills parent, and place a symlink at ~/.claude/skills/my-secrets
// pointing at that source directory.
func TestInstallSkillHelper(t *testing.T) {
	// Build a fake "repo" that contains a skills/my-secrets directory so
	// findSkillSource can locate it via its upward CWD walk.
	repo := t.TempDir()
	skillSrc := filepath.Join(repo, "skills", "my-secrets")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatalf("mkdir skill source: %v", err)
	}
	// A sentinel file so we can assert the link resolves to real content.
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	// Redirect HOME so the helper writes into a disposable directory.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	// findSkillSource walks upward from CWD, so chdir into the fake repo.
	t.Chdir(repo)

	cmd := &cobra.Command{Use: "test"}
	dst, src, err := installSkill(cmd)
	if err != nil {
		t.Fatalf("installSkill: %v", err)
	}

	wantDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets")
	if dst != wantDst {
		t.Fatalf("dst = %q, want %q", dst, wantDst)
	}

	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("lstat dst: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("dst is not a symlink: mode=%v", fi.Mode())
	}

	target, err := os.Readlink(dst)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	// Helper must return the same path it symlinked to.
	if target != src {
		t.Fatalf("symlink target %q != returned src %q", target, src)
	}
	// The target (and returned src) must end in /skills/my-secrets.
	wantSuffix := filepath.Join("skills", "my-secrets")
	if !strings.HasSuffix(target, wantSuffix) {
		t.Fatalf("symlink target %q does not end with %q", target, wantSuffix)
	}
}
