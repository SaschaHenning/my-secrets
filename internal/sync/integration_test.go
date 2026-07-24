package sync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
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

func TestIntegrationSharedMountLocalBareRemote(t *testing.T) {
	for _, binary := range []string{"git", "gpg", "gopass"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("needs %s on PATH", binary)
		}
	}

	root := t.TempDir()
	gnupgHome, err := os.MkdirTemp("/tmp", "mys-shared-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(gnupgHome) })
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "config")
	dataHome := filepath.Join(root, "data")
	rootStore := filepath.Join(root, "root-store")
	for _, dir := range []string{home, configHome, dataHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("GNUPGHOME", gnupgHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("PASSWORD_STORE_DIR", rootStore)
	t.Setenv("GIT_AUTHOR_NAME", "mys integration")
	t.Setenv("GIT_AUTHOR_EMAIL", "mys-integration@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "mys integration")
	t.Setenv("GIT_COMMITTER_EMAIL", "mys-integration@example.invalid")
	t.Setenv("GPG_TTY", "")

	aliceFingerprint := generateSharedTestKey(t, root, "Alice Shared", "alice-shared@example.invalid")
	bobFingerprint := generateSharedTestKey(t, root, "Bob Shared", "bob-shared@example.invalid")

	initCmd := exec.Command("gopass", "init", "--path", rootStore, "--crypto", "gpgcli", aliceFingerprint)
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("gopass root init: %v\n%s", err, output)
	}

	manifestDir := filepath.Join(root, "manifest")
	keyDir := filepath.Join(manifestDir, ".public-keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	exportSharedPublicKey(t, filepath.Join(keyDir, "alice.asc"), aliceFingerprint)
	exportSharedPublicKey(t, filepath.Join(keyDir, "bob.asc"), bobFingerprint)
	manifestPath := filepath.Join(manifestDir, teamkeys.Filename)
	if err := teamkeys.Save(manifestPath, &teamkeys.File{Version: 1, Members: []teamkeys.Member{
		{
			Name:        "Alice Shared",
			Email:       "alice-shared@example.invalid",
			Fingerprint: aliceFingerprint,
			PublicKey:   ".public-keys/alice.asc",
		},
		{
			Name:        "Bob Shared",
			Email:       "bob-shared@example.invalid",
			Fingerprint: bobFingerprint,
			PublicKey:   ".public-keys/bob.asc",
		},
	}}); err != nil {
		t.Fatal(err)
	}

	remotePath := filepath.Join(root, "shared.git")
	if output, err := exec.Command("git", "init", "--bare", "--initial-branch=main", remotePath).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, output)
	}
	sharedStore := filepath.Join(dataHome, "gopass", "stores", "jasp")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := ProvisionSharedMount(ctx, SharedProvisionOptions{
		Config: &Config{
			Version: 1,
			Layout:  LayoutSingle,
			Remotes: []StoreRemote{{Mount: DefaultStoreMount, URL: filepath.Join(root, "personal.git")}},
		},
		Mount:        "jasp",
		StorePath:    sharedStore,
		TeamKeysPath: manifestPath,
		RemoteURL:    remotePath,
		Runner:       ExecRunner{},
	})
	if err != nil {
		t.Fatalf("ProvisionSharedMount: %v", err)
	}
	if !result.Config.IsSharedMount("jasp") {
		t.Fatalf("shared marker missing: %+v", result.Config.Remotes)
	}
	recipients, err := readGPGID(filepath.Join(result.StorePath, ".gpg-id"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fingerprint := range []string{aliceFingerprint, bobFingerprint} {
		if !recipientSetContains(recipients, fingerprint) {
			t.Fatalf("recipient %s missing from %v", fingerprint, recipients)
		}
	}
	if output, err := exec.Command("git", "--git-dir", remotePath,
		"rev-parse", "--verify", "refs/heads/main").CombinedOutput(); err != nil {
		t.Fatalf("remote main missing: %v\n%s", err, output)
	}
	manifestAtRemote, err := exec.Command("git", "--git-dir", remotePath,
		"show", "main:"+teamkeys.Filename).Output()
	if err != nil {
		t.Fatalf("team-keys.yaml not committed to remote: %v", err)
	}
	if !strings.Contains(string(manifestAtRemote), aliceFingerprint) ||
		!strings.Contains(string(manifestAtRemote), bobFingerprint) {
		t.Fatalf("remote manifest does not contain both fingerprints:\n%s", manifestAtRemote)
	}
}

func generateSharedTestKey(t *testing.T, root, name, email string) string {
	t.Helper()
	batchPath := filepath.Join(root, strings.ReplaceAll(email, "@", "_")+".batch")
	batch := fmt.Sprintf(`%%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: %s
Name-Email: %s
Expire-Date: 1d
%%commit
`, name, email)
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("gpg", "--batch", "--quiet", "--generate-key", batchPath).CombinedOutput(); err != nil {
		t.Fatalf("gpg generate-key %s: %v\n%s", email, err, output)
	}
	output, err := exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys", email).Output()
	if err != nil {
		t.Fatalf("gpg list-secret-keys %s: %v", email, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			return strings.ToUpper(fields[9])
		}
	}
	t.Fatalf("no fingerprint generated for %s", email)
	return ""
}

func exportSharedPublicKey(t *testing.T, path, fingerprint string) {
	t.Helper()
	output, err := exec.Command("gpg", "--batch", "--armor", "--export", fingerprint).Output()
	if err != nil {
		t.Fatalf("gpg export %s: %v", fingerprint, err)
	}
	if err := os.WriteFile(path, output, 0o644); err != nil {
		t.Fatal(err)
	}
}
