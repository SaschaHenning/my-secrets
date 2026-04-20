package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInstallSkillCmd_ScopeLocal drives `mys install-skill --scope local`
// and verifies the embedded skill content lands in the project cwd, not
// in HOME.
func TestInstallSkillCmd_ScopeLocal(t *testing.T) {
	project := t.TempDir()
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(project)

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", "local"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	wantDst := filepath.Join(project, ".claude", "skills", "my-secrets")
	if _, err := os.Stat(filepath.Join(wantDst, "SKILL.md")); err != nil {
		t.Fatalf("local install missing SKILL.md: %v", err)
	}
	// HOME must NOT have been touched.
	homeDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets")
	if _, err := os.Stat(homeDst); err == nil {
		t.Fatalf("local install leaked into HOME: %s exists", homeDst)
	}
}

// TestInstallSkillCmd_ScopeGlobal drives `mys install-skill` (default
// scope) and asserts HOME gets the files.
func TestInstallSkillCmd_ScopeGlobal(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	wantDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets")
	if _, err := os.Stat(filepath.Join(wantDst, "SKILL.md")); err != nil {
		t.Fatalf("global install missing SKILL.md: %v", err)
	}
}

// TestInstallSkillCmd_ScopeInvalid asserts typo'd scopes fail loudly.
func TestInstallSkillCmd_ScopeInvalid(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	cmd := installSkillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", "space"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("unknown scope should error")
	}
}

// TestInstallSkillCmd_IdempotentReinstall runs the install twice and
// verifies the second pass overwrites cleanly without error.
func TestInstallSkillCmd_IdempotentReinstall(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Chdir(t.TempDir())

	cmd := installSkillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	cmd2 := installSkillCmd()
	cmd2.SetOut(&out)
	cmd2.SetErr(&out)
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second execute: %v", err)
	}
	wantDst := filepath.Join(fakeHome, ".claude", "skills", "my-secrets", "SKILL.md")
	if _, err := os.Stat(wantDst); err != nil {
		t.Fatalf("missing after reinstall: %v", err)
	}
}
