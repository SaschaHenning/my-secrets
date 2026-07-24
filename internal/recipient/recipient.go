// Package recipient wraps gpg and gopass subprocesses to manage the set of
// GPG keys that can decrypt the password store.
//
// Scope: this is deliberately a thin, audited wrapper. The legacy operations
// manage the user's default store. Foreign recipients are only accepted for
// an explicitly shared, non-root mount with a valid team-key manifest.
package recipient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
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
	return AddToMount(ctx, "", fingerprint)
}

// AddToMount registers fingerprint as a recipient of mount. Empty and root
// mounts retain the legacy default-store argv exactly.
func AddToMount(ctx context.Context, mount, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("empty fingerprint")
	}
	args := []string{"recipients", "add"}
	if mount != "" && mount != syncpkg.DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, fingerprint)
	if _, err := defaultRunner.Run(ctx, "gopass", args...); err != nil {
		return fmt.Errorf("gopass recipients add: %w", err)
	}
	return nil
}

// Remove drops `fingerprint` from the gopass recipient set.
func Remove(ctx context.Context, fingerprint string) error {
	return RemoveFromMount(ctx, "", fingerprint)
}

// RemoveFromMount drops fingerprint from the recipient set of mount. Empty
// and root mounts retain the legacy default-store argv exactly.
func RemoveFromMount(ctx context.Context, mount, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("empty fingerprint")
	}
	args := []string{"recipients", "remove"}
	if mount != "" && mount != syncpkg.DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, fingerprint)
	if _, err := defaultRunner.Run(ctx, "gopass", args...); err != nil {
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
	return enrichRecipients(ctx, parseGopassRecipients(out)), nil
}

// ListFromMount returns the recipients of mount. Gopass has no supported
// `recipients --store` form, so named mounts are resolved to their live path
// and read from that store's .gpg-id file.
func ListFromMount(ctx context.Context, mount string) ([]Recipient, error) {
	if mount == "" || mount == syncpkg.DefaultStoreMount {
		return List(ctx)
	}
	mountPath, err := syncpkg.GopassMountPath(ctx, defaultRunner, mount)
	if err != nil {
		return nil, fmt.Errorf("resolve gopass mount %q: %w", mount, err)
	}
	gpgIDPath := filepath.Join(mountPath, ".gpg-id")
	out, err := os.ReadFile(gpgIDPath)
	if err != nil {
		return nil, fmt.Errorf("read recipients for mount %q: %w", mount, err)
	}
	return enrichRecipients(ctx, parseGPGIDRecipients(out)), nil
}

func enrichRecipients(ctx context.Context, fprs []string) []Recipient {
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
	return recipients
}

// ForeignInfo describes how a foreign fingerprint appears in the shared
// mount's team-key manifest. An unlisted fingerprint is represented by
// Listed=false and is not itself an error.
type ForeignInfo struct {
	Fingerprint string
	Name        string
	Email       string
	Listed      bool
}

// ValidateSharedMount fails closed unless mount is a live, non-root gopass
// mount explicitly marked shared and containing a valid team-key manifest.
func ValidateSharedMount(ctx context.Context, mount string, cfg *syncpkg.Config) error {
	_, err := loadSharedManifest(ctx, mount, cfg)
	return err
}

// InspectForeign looks up fingerprint in a validated shared mount's team-key
// manifest. A valid but unlisted fingerprint returns Listed=false.
func InspectForeign(
	ctx context.Context,
	mount, fingerprint string,
	cfg *syncpkg.Config,
) (ForeignInfo, error) {
	fingerprint, err := normalizeForeignFingerprint(fingerprint)
	if err != nil {
		return ForeignInfo{}, err
	}
	manifest, err := loadSharedManifest(ctx, mount, cfg)
	if err != nil {
		return ForeignInfo{}, err
	}
	info := ForeignInfo{Fingerprint: fingerprint}
	member, ok := manifest.FindFingerprint(fingerprint)
	if !ok {
		return info, nil
	}
	info.Name = member.Name
	info.Email = member.Email
	info.Listed = true
	return info, nil
}

// AddForeign adds a foreign fingerprint only after revalidating the shared
// mount immediately before invoking gopass. The caller must have obtained
// human confirmation before calling this function.
func AddForeign(
	ctx context.Context,
	mount, fingerprint string,
	cfg *syncpkg.Config,
) error {
	fingerprint, err := normalizeForeignFingerprint(fingerprint)
	if err != nil {
		return err
	}
	mount = strings.TrimSpace(mount)
	if err := ValidateSharedMount(ctx, mount, cfg); err != nil {
		return err
	}
	return addConfirmedToMount(ctx, mount, fingerprint)
}

func addConfirmedToMount(ctx context.Context, mount, fingerprint string) error {
	if _, err := syncpkg.GopassRecipientsAddConfirmed(
		ctx,
		defaultRunner,
		mount,
		fingerprint,
	); err != nil {
		return fmt.Errorf("gopass recipients add: %w", err)
	}
	return nil
}

func loadSharedManifest(
	ctx context.Context,
	mount string,
	cfg *syncpkg.Config,
) (*teamkeys.File, error) {
	mount = strings.TrimSpace(mount)
	if mount == "" || mount == syncpkg.DefaultStoreMount {
		return nil, errors.New("shared recipient mount must be non-root")
	}
	if cfg == nil || !cfg.IsSharedMount(mount) {
		return nil, fmt.Errorf("mount %q is not configured as shared", mount)
	}
	mountPath, err := syncpkg.GopassMountPath(ctx, defaultRunner, mount)
	if err != nil {
		return nil, fmt.Errorf("resolve shared mount %q: %w", mount, err)
	}
	manifestPath := filepath.Join(mountPath, teamkeys.Filename)
	manifest, err := teamkeys.Load(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("load %s for shared mount %q: %w",
			teamkeys.Filename, mount, err)
	}
	return manifest, nil
}

func normalizeForeignFingerprint(fingerprint string) (string, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
	if !isFingerprint(fingerprint) {
		return "", fmt.Errorf("invalid fingerprint %q: expected 40 hexadecimal characters",
			fingerprint)
	}
	return fingerprint, nil
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
		// Walk the line collecting hex tokens. gopass 1.16+ prints only
		// 16-char short key IDs ("0xABCD1234..."), older releases printed
		// full 40-char fingerprints. Accept both shapes and — if we see a
		// short ID — resolve it to the full fingerprint via gpg so the
		// rest of the flow can treat everything uniformly.
		for _, tok := range tokenize(line) {
			tok = strings.TrimPrefix(tok, "0x")
			tok = strings.TrimPrefix(tok, "0X")
			if !isHexID(tok) {
				continue
			}
			up := strings.ToUpper(tok)
			if len(up) == 16 {
				if full := resolveShortID(up); full != "" {
					up = full
				}
			}
			if _, ok := seen[up]; !ok {
				seen[up] = struct{}{}
				fprs = append(fprs, up)
			}
		}
	}
	return dropShadowShortIDs(fprs)
}

// dropShadowShortIDs drops a 16-character short ID when the matching
// 40-character fingerprint is also present.
func dropShadowShortIDs(fprs []string) []string {
	fulls := map[string]struct{}{}
	for _, f := range fprs {
		if len(f) == 40 {
			fulls[f[len(f)-16:]] = struct{}{}
		}
	}
	out := fprs[:0]
	for _, f := range fprs {
		if len(f) == 16 {
			if _, isShadow := fulls[f]; isShadow {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// parseGPGIDRecipients extracts and deduplicates the 16- and 40-character
// hexadecimal key IDs accepted by gopass .gpg-id files. Inline comments and
// an optional 0x prefix are ignored.
func parseGPGIDRecipients(b []byte) []string {
	var fprs []string
	seen := map[string]struct{}{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, field := range bytes.Fields(line) {
			id := string(field)
			id = strings.TrimPrefix(id, "0x")
			id = strings.TrimPrefix(id, "0X")
			if !isHexID(id) {
				continue
			}
			id = strings.ToUpper(id)
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			fprs = append(fprs, id)
		}
	}
	return dropShadowShortIDs(fprs)
}

// resolveShortID calls `gpg --with-colons --list-keys <short>` to expand
// a 16-char key id into its 40-char fingerprint. Returns an empty string
// if gpg is missing or the lookup fails — caller keeps the short form
// in that case so the user at least sees something.
func resolveShortID(short string) string {
	if _, err := exec.LookPath("gpg"); err != nil {
		return ""
	}
	out, err := exec.Command("gpg", "--with-colons", "--list-keys", short).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 10 && len(parts[9]) == 40 {
				return strings.ToUpper(parts[9])
			}
		}
	}
	return ""
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
	return isHexID(s)
}

// isHexID returns true for 16- or 40-character all-hex tokens. gopass
// 1.16+ emits short key IDs (16 chars); older versions and gpg itself
// emit full fingerprints (40 chars). Both are accepted so the recipient
// parser works across versions.
func isHexID(s string) bool {
	if len(s) != 16 && len(s) != 40 {
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
