// Package gopassinit bootstraps a fresh gopass store against a specific
// GPG key id. It is only used by `mys init`; once the store exists,
// the rest of my-secrets talks to gopass as a Go library.
//
// Bootstrapping requires the `gopass` binary on PATH because the init
// flow touches global config (~/.config/gopass/config), the store
// directory, and a first git commit — all of which the gopass CLI
// handles atomically. Re-implementing that in-process is not worth it.
package gopassinit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultStoreDir returns the path of the default gopass store:
// $PASSWORD_STORE_DIR if set, otherwise ~/.password-store.
func DefaultStoreDir() (string, error) {
	if p := os.Getenv("PASSWORD_STORE_DIR"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".password-store"), nil
}

// IsInitialised reports whether a usable gopass store already exists
// at DefaultStoreDir(). We look for the .gpg-id file rather than just
// the directory — an empty `~/.password-store` left over from a failed
// run would otherwise confuse the init step.
func IsInitialised() bool {
	dir, err := DefaultStoreDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, ".gpg-id"))
	return err == nil
}

// Initialise runs `gopass init --crypto gpgcli <keyID>` so the user's
// default gopass store is encrypted to the given key. No-op if the
// store is already initialised.
//
// The keyID is passed as a single positional argument; callers should
// pass the full fingerprint (40 hex chars) so gopass can pick the
// right key unambiguously. gopass's `init` subcommand is itself
// non-interactive once a gpg-id is supplied — there is no `--yes`
// flag to pass here (older docs notwithstanding).
func Initialise(ctx context.Context, keyID string) error {
	return initialiseWithBin(ctx, "gopass", keyID)
}

// initialiseWithBin is the testable variant. gopassBin may be replaced
// with a stub binary in integration tests.
func initialiseWithBin(ctx context.Context, gopassBin, keyID string) error {
	if strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("gopass init: keyID required")
	}
	if IsInitialised() {
		return nil
	}
	if _, err := exec.LookPath(gopassBin); err != nil {
		return fmt.Errorf("gopass binary not found on PATH — run `brew install gopass` first")
	}
	// `--crypto gpgcli` matches the current gopass CLI's naming. The
	// fingerprint is the only positional arg.
	cmd := exec.CommandContext(ctx, gopassBin,
		"init",
		"--crypto", "gpgcli",
		keyID,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gopass init: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GpgIDFile returns the path to the .gpg-id file that records which
// key the store is encrypted to. Useful for integration tests that
// need to verify the fingerprint landed where expected.
func GpgIDFile() (string, error) {
	dir, err := DefaultStoreDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".gpg-id"), nil
}
