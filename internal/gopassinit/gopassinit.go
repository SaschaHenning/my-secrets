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

// DefaultStoreDir returns the path of the default gopass store in the
// order gopass itself uses:
//
//  1. $PASSWORD_STORE_DIR if set.
//  2. The path reported by `gopass config mounts.path` — gopass
//     v1.16+ persists its active store path here, which may differ
//     from the conventional ~/.password-store.
//  3. ~/.password-store as the final fallback.
//
// This is what "where does gopass actually keep my secrets" resolves to.
func DefaultStoreDir() (string, error) {
	if p := os.Getenv("PASSWORD_STORE_DIR"); p != "" {
		return p, nil
	}
	if _, err := exec.LookPath("gopass"); err == nil {
		if out, err := exec.Command("gopass", "config", "mounts.path").Output(); err == nil {
			if path := strings.TrimSpace(string(out)); path != "" {
				return path, nil
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".password-store"), nil
}

// IsInitialised reports whether a usable gopass store already exists.
//
// Lookup order mirrors what gopass itself does:
//  1. If PASSWORD_STORE_DIR is set, check <that>/.gpg-id.
//  2. Otherwise, ask `gopass config mounts.path` — this respects the
//     user's persistent gopass config (~/.config/gopass/config), which
//     is where a previous `gopass init`/test run may have stashed a
//     non-default store path.
//  3. Fall back to ~/.password-store/.gpg-id.
//
// Step 2 is what catches the „my store lives at /tmp/... per gopass
// config, but ~/.password-store does not exist" case. Without it
// `mys init` would try to init a store gopass already considers
// initialised, fail, and leave the user stuck.
func IsInitialised() bool {
	return isInitialisedWithBin("gopass")
}

func isInitialisedWithBin(gopassBin string) bool {
	// Explicit env-var always wins — matches gopass's own precedence.
	if env := os.Getenv("PASSWORD_STORE_DIR"); env != "" {
		_, err := os.Stat(filepath.Join(env, ".gpg-id"))
		return err == nil
	}
	// Ask gopass for its configured store path. If the binary is there
	// and the config lookup works, trust the path it returned.
	if _, lerr := exec.LookPath(gopassBin); lerr == nil {
		if out, err := exec.Command(gopassBin, "config", "mounts.path").Output(); err == nil {
			path := strings.TrimSpace(string(out))
			if path != "" {
				_, statErr := os.Stat(filepath.Join(path, ".gpg-id"))
				return statErr == nil
			}
		}
	}
	// Final fallback: the conventional ~/.password-store location.
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".password-store", ".gpg-id"))
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
	if isInitialisedWithBin(gopassBin) {
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
		// gopass itself might know about the store even if our pre-check
		// missed it (user ran `gopass init` by hand, weird config state,
		// etc.). Treat its „already initialized" response as success so
		// a re-run of `mys init` does not block the user.
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "already initialized") {
			return nil
		}
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
