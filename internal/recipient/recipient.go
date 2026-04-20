// Package recipient wraps gpg and gopass subprocesses to manage the set of
// GPG keys that can decrypt the password store.
//
// Scope: this is deliberately a thin, audited wrapper intended for your own
// additional devices or hardware tokens (for example a second laptop, or a
// YubiKey). Adding a colleague's key is the wrong trust model — a new
// recipient can decrypt every secret in the store, including entries under
// private/**. Team sharing belongs in Bitwarden.
package recipient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Recipient is a GPG key currently registered as a gopass store recipient.
type Recipient struct {
	Fingerprint string
	UIDs        []string
	Expires     time.Time
}

// runner is the minimal subprocess dependency used by this package.
// Tests swap it out with an in-memory stub.
type runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %s: %w: %s", name,
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// defaultRunner is the package-level runner. Tests override it via
// WithRunner, production code leaves it at execRunner{}.
var defaultRunner runner = execRunner{}

// WithRunner returns a copy of the current default-runner override and
// swaps in `r` for subsequent calls. Only tests use this.
func WithRunner(r runner) (restore func()) {
	prev := defaultRunner
	defaultRunner = r
	return func() { defaultRunner = prev }
}

// Import reads a GPG key from disk, imports it into the user's keyring via
// `gpg --import`, and returns its primary fingerprint and first UID. `path`
// may also be a directory containing .asc/.gpg files — gpg handles both.
func Import(ctx context.Context, path string) (fingerprint, uid string, err error) {
	if path == "" {
		return "", "", errors.New("empty key path")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return "", "", fmt.Errorf("stat key file: %w", statErr)
	}
	if _, err := defaultRunner.Run(ctx, "gpg", "--batch", "--import", path); err != nil {
		return "", "", fmt.Errorf("gpg import: %w", err)
	}
	out, err := defaultRunner.Run(ctx, "gpg", "--with-colons", "--show-keys", path)
	if err != nil {
		return "", "", fmt.Errorf("gpg show-keys: %w", err)
	}
	fingerprint, uid = parseFirstFprUID(out)
	if fingerprint == "" {
		return "", "", errors.New("no fingerprint found in key file")
	}
	return fingerprint, uid, nil
}

// Add registers `fingerprint` as a gopass recipient. Gopass re-encrypts
// every secret in the store for the new recipient set.
func Add(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("empty fingerprint")
	}
	if _, err := defaultRunner.Run(ctx, "gopass", "recipients", "add", fingerprint); err != nil {
		return fmt.Errorf("gopass recipients add: %w", err)
	}
	return nil
}

// Remove drops `fingerprint` from the gopass recipient set.
func Remove(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("empty fingerprint")
	}
	if _, err := defaultRunner.Run(ctx, "gopass", "recipients", "remove", fingerprint); err != nil {
		return fmt.Errorf("gopass recipients remove: %w", err)
	}
	return nil
}

// List returns the current gopass recipients enriched with UID and expiry
// data from the user's GPG keyring.
func List(ctx context.Context) ([]Recipient, error) {
	out, err := defaultRunner.Run(ctx, "gopass", "recipients")
	if err != nil {
		return nil, fmt.Errorf("gopass recipients: %w", err)
	}
	fprs := parseGopassRecipients(out)
	recipients := make([]Recipient, 0, len(fprs))
	for _, fpr := range fprs {
		r := Recipient{Fingerprint: fpr}
		colonOut, err := defaultRunner.Run(ctx, "gpg",
			"--with-colons", "--fixed-list-mode", "--list-keys", fpr)
		if err == nil {
			r.UIDs, r.Expires = parseKeyDetails(colonOut)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

// parseFirstFprUID extracts the first primary fingerprint (fpr) and first
// UID (uid) from `gpg --with-colons` output. See doc/DETAILS in the GnuPG
// source for the record layout.
func parseFirstFprUID(b []byte) (fpr, uid string) {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	sawPrimary := false
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub":
			sawPrimary = true
		case "fpr":
			if sawPrimary && fpr == "" && len(fields) > 9 {
				fpr = fields[9]
			}
		case "uid":
			if uid == "" && len(fields) > 9 {
				uid = unescapeColon(fields[9])
			}
		}
		if fpr != "" && uid != "" {
			break
		}
	}
	return fpr, uid
}

// parseKeyDetails collects ALL UIDs for the first primary key and its
// latest expiry date. The primary pub record's field 7 (expiration time,
// seconds since epoch) is the authoritative value for the master key.
func parseKeyDetails(b []byte) ([]string, time.Time) {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var uids []string
	var expires time.Time
	sawPrimary := false
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub":
			// Second pub record would mean another key — stop to keep
			// the result scoped to the requested fingerprint.
			if sawPrimary {
				return uids, expires
			}
			sawPrimary = true
			if len(fields) > 6 {
				if ts := parseEpoch(fields[6]); !ts.IsZero() {
					expires = ts
				}
			}
		case "uid":
			if sawPrimary && len(fields) > 9 {
				uids = append(uids, unescapeColon(fields[9]))
			}
		}
	}
	return uids, expires
}

// parseGopassRecipients extracts 40-char uppercase hex fingerprints from
// `gopass recipients` output. Gopass prints a tree-like structure (one
// "gopass" root, then "- <fpr>" entries). We ignore indentation and
// tree-drawing characters and just scan for anything that looks like a
// full fingerprint.
func parseGopassRecipients(b []byte) []string {
	var fprs []string
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// Walk the line collecting runs of hex chars of length 40.
		for _, tok := range tokenize(line) {
			if isFingerprint(tok) {
				up := strings.ToUpper(tok)
				if _, ok := seen[up]; !ok {
					seen[up] = struct{}{}
					fprs = append(fprs, up)
				}
			}
		}
	}
	return fprs
}

// tokenize returns whitespace / tree-char separated tokens from a line.
func tokenize(line string) []string {
	f := func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', '-', '|', '└', '├', '│', '─', ',', '(', ')':
			return true
		}
		return false
	}
	return strings.FieldsFunc(line, f)
}

func isFingerprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// unescapeColon reverses GnuPG's colon-listing escape (\xNN, \c, \n).
// Only the small subset needed for common UID characters is implemented —
// everything else falls through unchanged.
func unescapeColon(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			var v byte
			for j := 0; j < 2; j++ {
				c := s[i+2+j]
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= c - '0'
				case c >= 'a' && c <= 'f':
					v |= c - 'a' + 10
				case c >= 'A' && c <= 'F':
					v |= c - 'A' + 10
				default:
					b.WriteByte(s[i])
					goto next
				}
			}
			b.WriteByte(v)
			i += 3
			continue
		next:
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseEpoch(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return time.Time{}
		}
		n = n*10 + int64(c-'0')
	}
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}
