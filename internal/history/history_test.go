package history

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// initGitRepo creates a bare-minimum git repo in dir with local
// user.name/user.email, independent of any global git config the test
// runner's environment may or may not have.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
}

func commitFile(t *testing.T, dir, relPath, content, message string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", relPath},
		{"commit", "-q", "-m", message},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

func TestLog_RootStore(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	commitFile(t, dir, "jasp/github.gpg", "v1", "add jasp/github")
	commitFile(t, dir, "jasp/github.gpg", "v2", "rotate jasp/github")
	// Unrelated entry — must not show up in jasp/github's history.
	commitFile(t, dir, "jasp/aws.gpg", "v1", "add jasp/aws")

	t.Setenv("PASSWORD_STORE_DIR", dir)

	revs, err := Log(context.Background(), "jasp/github", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 2 {
		t.Fatalf("want 2 revisions, got %d: %+v", len(revs), revs)
	}
	// Most recent first.
	if revs[0].Message != "rotate jasp/github" {
		t.Errorf("revs[0].Message = %q, want the newer commit first", revs[0].Message)
	}
	if revs[1].Message != "add jasp/github" {
		t.Errorf("revs[1].Message = %q, want the older commit second", revs[1].Message)
	}
	for _, r := range revs {
		if r.Hash == "" {
			t.Error("revision hash must not be empty")
		}
		if r.When.IsZero() {
			t.Error("revision timestamp must not be zero")
		}
	}
}

func TestLog_LimitRespected(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	for i := 0; i < 5; i++ {
		commitFile(t, dir, "jasp/github.gpg", string(rune('a'+i)), "commit")
	}
	t.Setenv("PASSWORD_STORE_DIR", dir)

	revs, err := Log(context.Background(), "jasp/github", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 2 {
		t.Fatalf("want 2 revisions (limit), got %d", len(revs))
	}
}

func TestLog_NoHistoryForUnknownPath(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	commitFile(t, dir, "jasp/github.gpg", "v1", "add")
	t.Setenv("PASSWORD_STORE_DIR", dir)

	revs, err := Log(context.Background(), "jasp/never-existed", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 0 {
		t.Errorf("want 0 revisions for a path with no history, got %d", len(revs))
	}
}

func TestLog_GitMissing_FailsSoft(t *testing.T) {
	// Point PATH at an empty directory so exec.LookPath("git") fails,
	// simulating a machine without git installed. Log must degrade to
	// "no history" rather than erroring the whole page.
	t.Setenv("PATH", t.TempDir())
	revs, err := Log(context.Background(), "jasp/github", 10)
	if err != nil {
		t.Fatalf("Log must fail soft when git is missing, got error: %v", err)
	}
	if revs != nil {
		t.Errorf("want nil revisions when git is missing, got %+v", revs)
	}
}

// TestLog_MountAwareStripsOrgPrefix is the regression test for the
// trickiest part of this package: gopass's root.Store strips the mount
// alias from the on-disk relative path, so an entry at logical path
// "acme/aws/root" lives at "aws/root.gpg" relative to the acme mount's
// own repo root — NOT "acme/aws/root.gpg". If resolveDir's stripping
// logic were wrong, this test would find zero history (git log would be
// asked for a file that never existed in that repo).
func TestLog_MountAwareStripsOrgPrefix(t *testing.T) {
	requireGit(t)
	mountDir := t.TempDir()
	initGitRepo(t, mountDir)
	// Committed WITHOUT the "acme/" prefix — exactly what gopass's mount
	// stripping produces on disk.
	commitFile(t, mountDir, "aws/root.gpg", "v1", "add acme aws root")

	prev := mountPathLookup
	mountPathLookup = func(_ context.Context, org string) (string, error) {
		if org == "acme" {
			return mountDir, nil
		}
		return "", nil
	}
	t.Cleanup(func() { mountPathLookup = prev })

	revs, err := Log(context.Background(), "acme/aws/root", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 || revs[0].Message != "add acme aws root" {
		t.Fatalf("expected 1 revision from the mount repo, got %+v", revs)
	}
}

// TestLog_MountLookupEmptyFallsBackToRootStore covers an org with no
// dedicated mount — mountPathLookup returning "" (not an error) must
// fall back to the default root store, not fail.
func TestLog_MountLookupEmptyFallsBackToRootStore(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	commitFile(t, dir, "jasp/github.gpg", "v1", "add jasp/github")
	t.Setenv("PASSWORD_STORE_DIR", dir)

	prev := mountPathLookup
	mountPathLookup = func(context.Context, string) (string, error) { return "", nil }
	t.Cleanup(func() { mountPathLookup = prev })

	revs, err := Log(context.Background(), "jasp/github", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 {
		t.Fatalf("want 1 revision via root-store fallback, got %d", len(revs))
	}
}

func TestParseLog_SkipsMalformedLines(t *testing.T) {
	good := "abc123" + fieldSep + "2026-01-01T00:00:00+00:00" + fieldSep + "a message"
	malformed := "missing-fields-only-one-sep" + fieldSep + "not-a-timestamp"
	out := []byte(good + "\n" + malformed + "\n")

	revs := parseLog(out)
	if len(revs) != 1 {
		t.Fatalf("want 1 valid revision (malformed line skipped), got %d: %+v", len(revs), revs)
	}
	if revs[0].Hash != "abc123" || revs[0].Message != "a message" {
		t.Errorf("unexpected parse result: %+v", revs[0])
	}
	wantTime, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00+00:00")
	if !revs[0].When.Equal(wantTime) {
		t.Errorf("When = %v, want %v", revs[0].When, wantTime)
	}
}

func TestParseLog_EmptyOutput(t *testing.T) {
	if got := parseLog(nil); got != nil {
		t.Errorf("parseLog(nil) = %+v, want nil", got)
	}
	if got := parseLog([]byte("")); got != nil {
		t.Errorf("parseLog(empty) = %+v, want nil", got)
	}
}
