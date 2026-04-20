package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/gpgsetup"
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
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
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
	if target != src {
		t.Fatalf("symlink target %q != returned src %q", target, src)
	}
	wantSuffix := filepath.Join("skills", "my-secrets")
	if !strings.HasSuffix(target, wantSuffix) {
		t.Fatalf("symlink target %q does not end with %q", target, wantSuffix)
	}
}

// TestInstallSkillAt_LocalScope installs into a CWD-relative location
// and verifies the symlink lands under <cwd>/.claude/skills/my-secrets.
func TestInstallSkillAt_LocalScope(t *testing.T) {
	repo := t.TempDir()
	skillSrc := filepath.Join(repo, "skills", "my-secrets")
	if err := os.MkdirAll(skillSrc, 0o755); err != nil {
		t.Fatalf("mkdir skill source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillSrc, "SKILL.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	// Distinct project cwd — local install should land here, NOT in HOME.
	projectCwd := filepath.Join(repo, "project-x")
	if err := os.MkdirAll(projectCwd, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Chdir(repo) // findSkillSource walks up from here

	cmd := &cobra.Command{Use: "test"}
	dst, _, err := installSkillAt(cmd, skillScopeLocal, projectCwd)
	if err != nil {
		t.Fatalf("installSkillAt local: %v", err)
	}
	wantDst := filepath.Join(projectCwd, ".claude", "skills", "my-secrets")
	if dst != wantDst {
		t.Fatalf("dst = %q, want %q", dst, wantDst)
	}
	if fi, err := os.Lstat(dst); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("dst is not a symlink: err=%v fi=%v", err, fi)
	}
}

// TestNormaliseSkillScope covers the accepted input shapes.
func TestNormaliseSkillScope(t *testing.T) {
	cases := map[string]string{
		"":       skillScopeGlobal,
		"g":      skillScopeGlobal,
		"global": skillScopeGlobal,
		" G ":    skillScopeGlobal,
		"l":      skillScopeLocal,
		"LOCAL":  skillScopeLocal,
	}
	for in, want := range cases {
		got, err := normaliseSkillScope(in)
		if err != nil {
			t.Errorf("normaliseSkillScope(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normaliseSkillScope(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normaliseSkillScope("session"); err == nil {
		t.Fatalf("unknown scope should error")
	}
}

// TestDecideSkillInstall_ExplicitYes ensures --install-skill without a
// prompt installs at the requested scope.
func TestDecideSkillInstall_ExplicitYes(t *testing.T) {
	opts := &initOptions{
		installSkillExplicit: true,
		InstallSkill:         true,
		SkillScope:           "local",
	}
	scope, install, err := decideSkillInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !install || scope != skillScopeLocal {
		t.Fatalf("want (local, true), got (%q, %v)", scope, install)
	}
}

// TestDecideSkillInstall_YesNoFlag ensures --yes without --install-skill
// silently skips the step.
func TestDecideSkillInstall_YesNoFlag(t *testing.T) {
	opts := &initOptions{Yes: true}
	_, install, err := decideSkillInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	if install {
		t.Fatalf("--yes without --install-skill should not install")
	}
}

// TestDecideSkillInstall_InteractiveDefault: pressing enter picks
// global.
func TestDecideSkillInstall_InteractiveDefault(t *testing.T) {
	var out bytes.Buffer
	opts := &initOptions{
		In:  strings.NewReader("\n"),
		Out: &out,
	}
	scope, install, err := decideSkillInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !install || scope != skillScopeGlobal {
		t.Fatalf("default should be global install, got (%q, %v)", scope, install)
	}
	if !strings.Contains(out.String(), "Claude Code Skill installieren?") {
		t.Fatalf("prompt text missing from output: %s", out.String())
	}
}

// TestDecideSkillInstall_InteractiveLocal verifies the l branch.
func TestDecideSkillInstall_InteractiveLocal(t *testing.T) {
	var out bytes.Buffer
	opts := &initOptions{
		In:  strings.NewReader("l\n"),
		Out: &out,
	}
	scope, install, err := decideSkillInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !install || scope != skillScopeLocal {
		t.Fatalf("l should map to local install, got (%q, %v)", scope, install)
	}
}

// TestDecideSkillInstall_InteractiveNo verifies the n branch.
func TestDecideSkillInstall_InteractiveNo(t *testing.T) {
	var out bytes.Buffer
	opts := &initOptions{
		In:  strings.NewReader("n\n"),
		Out: &out,
	}
	_, install, err := decideSkillInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	if install {
		t.Fatalf("n should skip install")
	}
}

// TestResolveNameEmail_YesMissing makes sure --yes refuses when git
// config is empty.
func TestResolveNameEmail_YesMissing(t *testing.T) {
	// Point git config at an empty home so user.name/user.email are
	// unset.
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("XDG_CONFIG_HOME", empty)
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")

	opts := &initOptions{Yes: true}
	_, _, err := resolveNameEmail(opts)
	if err == nil {
		t.Fatalf("--yes with no git config should error")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should mention --yes: %v", err)
	}
}

// TestResolveNameEmail_FromFlags is the simplest case: both flags
// provided, so no git config or prompt is consulted.
func TestResolveNameEmail_FromFlags(t *testing.T) {
	opts := &initOptions{
		Name:  "Sascha Henning",
		Email: "garry@jasp.eu",
	}
	name, email, err := resolveNameEmail(opts)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Sascha Henning" || email != "garry@jasp.eu" {
		t.Fatalf("got %q / %q", name, email)
	}
}

// TestStepwiseRunner_ShortCircuitsOnError wires a synthetic list of
// steps (not the production ones) and asserts that the runner stops at
// the first error, prints its marker, and surfaces the error wrapped
// with the step name.
func TestStepwiseRunner_ShortCircuitsOnError(t *testing.T) {
	var out bytes.Buffer
	var ranNames []string

	steps := []initStep{
		{name: "step one", run: func(ctx context.Context, o *initOptions, s *initState) error {
			ranNames = append(ranNames, "one")
			return nil
		}},
		{name: "step two", run: func(ctx context.Context, o *initOptions, s *initState) error {
			ranNames = append(ranNames, "two")
			return errors.New("boom")
		}},
		{name: "step three", run: func(ctx context.Context, o *initOptions, s *initState) error {
			ranNames = append(ranNames, "three")
			return nil
		}},
	}

	opts := &initOptions{Out: &out, In: strings.NewReader("")}
	state := &initState{}
	err := runSteps(context.Background(), opts, state, steps)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "step two") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error should wrap step name and cause: %v", err)
	}
	if got := strings.Join(ranNames, ","); got != "one,two" {
		t.Fatalf("step three should not run after step two errored; ran: %q", got)
	}
	if !strings.Contains(out.String(), "[x] step two: boom") {
		t.Fatalf("failure marker missing from output: %s", out.String())
	}
}

// TestStepwiseRunner_AllSucceed runs three trivial no-op steps end to
// end and asserts the runner invokes them in order.
func TestStepwiseRunner_AllSucceed(t *testing.T) {
	var order []string
	steps := []initStep{
		{name: "a", run: func(ctx context.Context, o *initOptions, s *initState) error { order = append(order, "a"); return nil }},
		{name: "b", run: func(ctx context.Context, o *initOptions, s *initState) error { order = append(order, "b"); return nil }},
		{name: "c", run: func(ctx context.Context, o *initOptions, s *initState) error { order = append(order, "c"); return nil }},
	}
	opts := &initOptions{Out: &bytes.Buffer{}, In: strings.NewReader("")}
	if err := runSteps(context.Background(), opts, &initState{}, steps); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if strings.Join(order, ",") != "a,b,c" {
		t.Fatalf("order = %v", order)
	}
}

// TestShortFpr exercises the compact fingerprint formatter so we catch
// regressions in the UI strings cheaply.
func TestShortFpr(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"ABCDEF":   "ABCDEF",
		"ABCDEFGH": "ABCD...EFGH",
		"ABCDEF0123456789ABCDEF0123456789ABCDEF01": "ABCD...EF01",
	}
	for in, want := range cases {
		if got := shortFpr(in); got != want {
			t.Errorf("shortFpr(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUidOrFingerprint covers both branches — known uid and missing uid.
func TestUidOrFingerprint(t *testing.T) {
	withUID := gpgsetup.KeyInfo{UID: "User <u@e.com>", Fingerprint: "AB"}
	if got := uidOrFingerprint(withUID); got != "User <u@e.com>" {
		t.Errorf("uid branch: %q", got)
	}
	onlyFpr := gpgsetup.KeyInfo{Fingerprint: "ABCD"}
	if got := uidOrFingerprint(onlyFpr); got != "ABCD" {
		t.Errorf("fpr branch: %q", got)
	}
}

// TestPrettyPath shortens HOME paths with ~.
func TestPrettyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	nested := filepath.Join(home, ".config", "my-secrets", "audit.sqlite")
	if got := prettyPath(nested); got != "~/.config/my-secrets/audit.sqlite" {
		t.Fatalf("prettyPath nested = %q", got)
	}
	if got := prettyPath("/etc/passwd"); got != "/etc/passwd" {
		t.Fatalf("prettyPath outside = %q", got)
	}
}
