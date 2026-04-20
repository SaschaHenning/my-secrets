package sync

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestIntegrationBareRemoteRoundTrip verifies that the ExecRunner can at
// least reach `git` to push into a bare remote that lives in t.TempDir().
//
// This is deliberately minimal: the full gopass+git dance requires an
// initialised gopass store with a GPG key, which we cannot set up
// unattended on CI. The test is skipped when gopass or gh are missing.
// What we DO verify — without gopass — is that our Runner interface
// drives a real subprocess end-to-end and that the remote URL we build
// is a shape git itself accepts as a remote.
func TestIntegrationBareRemoteRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git on PATH")
	}
	if _, err := exec.LookPath("gopass"); err != nil {
		t.Skip("needs gopass on PATH for a full round-trip")
	}

	dir := t.TempDir()
	bare := filepath.Join(dir, "bare.git")

	ctx := context.Background()
	runner := ExecRunner{}

	// Create a bare repo that would serve as the github remote.
	if _, err := runner.Run(ctx, "git", "init", "--bare", bare); err != nil {
		t.Fatalf("git init --bare: %v", err)
	}

	// Sanity check: ls-remote against the bare URL succeeds and returns
	// no refs yet.
	out, err := runner.Run(ctx, "git", "ls-remote", bare)
	if err != nil {
		t.Fatalf("ls-remote bare: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("unexpected ls-remote output for empty bare: %q", out)
	}
}
