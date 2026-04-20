package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInstallSkillCmd_ScopeLocal drives `mys install-skill --scope local`
// against a fake repo and verifies the symlink lands in the project
// cwd, not in HOME.
func TestInstallSkillCmd_ScopeLocal(t *testing.T) {
	repo := t.TempDir()
	skillSrc := filepath.Join(repo, "skills", "my-secrets")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(repo)

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", "local"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// The repo cwd is the same as `repo`, so the expected target is
	// <repo>/.claude/skills/my-secrets.
	wantDst := filepath.Join(repo, ".claude", "skills", "my-secrets")
	if fi, err := os.Lstat(wantDst); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("local install missing: err=%v fi=%v", err, fi)
	}
	// HOME must NOT have been touched.
	homeDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets")
	if _, err := os.Lstat(homeDst); err == nil {
		t.Fatalf("local install leaked into HOME: %s exists", homeDst)
	}
}

// TestInstallSkillCmd_ScopeGlobal drives `mys install-skill` (default
// scope) and asserts HOME gets the symlink.
func TestInstallSkillCmd_ScopeGlobal(t *testing.T) {
	repo := t.TempDir()
	skillSrc := filepath.Join(repo, "skills", "my-secrets")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(repo)

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	// No --scope → defaults to global.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	wantDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets")
	if fi, err := os.Lstat(wantDst); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("global install missing: err=%v fi=%v", err, fi)
	}
}

// TestInstallSkillCmd_ScopeInvalid asserts typo'd scopes fail loudly.
func TestInstallSkillCmd_ScopeInvalid(t *testing.T) {
	repo := t.TempDir()
	skillSrc := filepath.Join(repo, "skills", "my-secrets")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Chdir(repo)

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", "space"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("unknown scope should error")
	}
}
