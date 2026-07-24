// Package store wraps the gopass library with a small, purpose-built API
// for my-secrets. All access goes through the app layer; this package
// focuses on the storage primitives.
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/api"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

// Interface defines the storage operations used by the app layer.
// Both the real gopass-backed *Store and the in-memory fake in the
// subpackage store/fake implement this interface, so app/mcp/web code
// paths can be exercised in tests without a live GPG setup.
type Interface interface {
	Close(ctx context.Context) error
	List(ctx context.Context, org string) ([]string, error)
	Search(ctx context.Context, query string, allow func(path string) bool) (allowed, denied []string, err error)
	SearchObserved(
		ctx context.Context,
		query string,
		allow func(path string) bool,
		observer SearchObserver,
	) (allowed, denied []string, err error)
	Get(ctx context.Context, path string) (*Entry, error)
	Set(ctx context.Context, e *Entry) error
	Remove(ctx context.Context, path string) error
	Rotate(ctx context.Context, path, newPassword string) error
	Orgs(ctx context.Context) ([]string, error)
}

// SearchObserver is called after SearchObserved successfully decrypts an
// entry to inspect its metadata. Pure path matches do not require decryption
// and therefore do not trigger the observer.
type SearchObserver func(path string)

// MountPathResolver resolves a configured gopass mount to its live directory.
type MountPathResolver func(context.Context, string) (string, error)

type mountBinding struct {
	path string
	info os.FileInfo
}

// MountSnapshot is an immutable view of the real paths and filesystem
// identities of a set of gopass mounts.
type MountSnapshot struct {
	bindings map[string]mountBinding
}

// BoundSession couples a store with the exact mount snapshot captured by its
// opener. Callers must use ResolveMountPath instead of consulting live config.
type BoundSession struct {
	store    Interface
	snapshot MountSnapshot
}

type anchoredStore struct {
	Interface
	release   func() error
	closeOnce sync.Once
	closeErr  error
}

var _ Interface = (*anchoredStore)(nil)

var gopassOpenGate = func() chan struct{} {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return gate
}()

const boundStoreCleanupTimeout = 5 * time.Second

// CaptureMountSnapshot resolves and stats every mount. The real path and the
// directory identity are both retained so a same-path directory replacement
// is distinguishable from a stable mount.
func CaptureMountSnapshot(
	ctx context.Context,
	mounts []string,
	resolve MountPathResolver,
) (MountSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolve == nil {
		return MountSnapshot{}, errors.New("mount path resolver is required")
	}
	snapshot := MountSnapshot{
		bindings: make(map[string]mountBinding, len(mounts)),
	}
	for _, mount := range mounts {
		if err := ctx.Err(); err != nil {
			return MountSnapshot{}, err
		}
		if mount == "" || strings.TrimSpace(mount) != mount {
			return MountSnapshot{}, fmt.Errorf("invalid mount name %q", mount)
		}
		if _, duplicate := snapshot.bindings[mount]; duplicate {
			return MountSnapshot{}, fmt.Errorf("duplicate mount %q", mount)
		}
		resolved, err := resolve(ctx, mount)
		if err != nil {
			return MountSnapshot{}, fmt.Errorf(
				"resolve gopass mount %q: %w",
				mount,
				err,
			)
		}
		if strings.TrimSpace(resolved) == "" {
			return MountSnapshot{}, fmt.Errorf(
				"resolve gopass mount %q: empty path",
				mount,
			)
		}
		absolute, err := filepath.Abs(resolved)
		if err != nil {
			return MountSnapshot{}, fmt.Errorf(
				"make gopass mount %q absolute: %w",
				mount,
				err,
			)
		}
		realPath, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return MountSnapshot{}, fmt.Errorf(
				"resolve real gopass mount %q path: %w",
				mount,
				err,
			)
		}
		info, err := os.Stat(realPath)
		if err != nil {
			return MountSnapshot{}, fmt.Errorf(
				"stat real gopass mount %q path: %w",
				mount,
				err,
			)
		}
		if !info.IsDir() {
			return MountSnapshot{}, fmt.Errorf(
				"gopass mount %q path is not a directory",
				mount,
			)
		}
		snapshot.bindings[mount] = mountBinding{
			path: realPath,
			info: info,
		}
	}
	return snapshot, nil
}

// ResolveMountPath resolves exclusively from the frozen snapshot.
func (snapshot MountSnapshot) ResolveMountPath(
	ctx context.Context,
	mount string,
) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	binding, ok := snapshot.bindings[mount]
	if !ok {
		return "", fmt.Errorf("gopass mount %q is not in the store session", mount)
	}
	current, err := os.Stat(binding.path)
	if err != nil {
		return "", fmt.Errorf("stat bound gopass mount %q: %w", mount, err)
	}
	if binding.info == nil || !os.SameFile(binding.info, current) {
		return "", fmt.Errorf("bound gopass mount %q identity changed", mount)
	}
	return binding.path, nil
}

func (snapshot MountSnapshot) verify(ctx context.Context) error {
	mounts := make([]string, 0, len(snapshot.bindings))
	for mount := range snapshot.bindings {
		mounts = append(mounts, mount)
	}
	sort.Strings(mounts)
	for _, mount := range mounts {
		if _, err := snapshot.ResolveMountPath(ctx, mount); err != nil {
			return err
		}
	}
	return nil
}

// ResolveMountPath resolves a mount from the immutable store-session snapshot.
func (session *BoundSession) ResolveMountPath(
	ctx context.Context,
	mount string,
) (string, error) {
	if session == nil {
		return "", errors.New("bound store session is required")
	}
	return session.snapshot.ResolveMountPath(ctx, mount)
}

// SecretStore returns the store opened as part of this bound session.
func (session *BoundSession) SecretStore() Interface {
	if session == nil {
		return nil
	}
	return session.store
}

func (store *anchoredStore) Close(ctx context.Context) error {
	if store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.closeOnce.Do(func() {
		var closeErr error
		if store.Interface != nil {
			closeErr = store.Interface.Close(ctx)
		}
		var releaseErr error
		if store.release != nil {
			releaseErr = store.release()
		}
		store.closeErr = errors.Join(closeErr, releaseErr)
	})
	return store.closeErr
}

type Store struct {
	gp *api.Gopass
}

// Compile-time assertion: *Store satisfies Interface.
var _ Interface = (*Store)(nil)

// Kinds classify the type of secret stored.
const (
	KindPassword = "password"
	KindAPIKey   = "api_key"
	KindToken    = "token"
	KindSSHKey   = "ssh_key"
	KindEnv      = "env"
	KindNote     = "note"
	KindTOTP     = "totp"
)

// Entry is the in-memory representation of a stored secret plus its metadata.
// The password lives in Password; everything else is metadata and is safe to
// log/display.
//
// RotateAfter and RotatedAt implement the rotation-reminder feature: an
// entry with a non-empty RotateAfter ("90d", "6m", "1y") opts in to the
// staleness checks that `mys ls --stale` and `mys doctor` perform.
// RotatedAt is maintained automatically by App.Add and App.Rotate — it
// is not a user-facing field.
//
// For Kind=="totp" entries, Password holds the raw base32 TOTP seed and the
// TOTP* fields carry the associated metadata (issuer, label, algorithm,
// digits, period). Zero values of the numeric TOTP fields mean „library
// default" (SHA1 / 6 digits / 30 seconds).
type Entry struct {
	Path          string
	Org           string
	Kind          string
	Username      string
	URL           string
	GitHubProject string
	Tags          []string
	Notes         string
	Password      string
	RotateAfter   string    // e.g. "90d", "6m", "1y" — empty = no policy.
	RotatedAt     time.Time // last rotation timestamp (UTC); zero = never.
	// TOTP metadata — populated when Kind == KindTOTP.
	TOTPIssuer    string
	TOTPLabel     string
	TOTPAlgorithm string
	TOTPDigits    int
	TOTPPeriod    int
	// Domain is the canonical host associated with this entry, e.g.
	// "aws.amazon.com" or "mail.jasp.eu". If left empty at Add/Rotate time
	// and URL is non-empty, the app layer populates it from URL via
	// DeriveDomain so domain-based search works out of the box.
	Domain string
	// Fields carries arbitrary structured extras like account_id, region,
	// tenant, etc. Keys are validated at the CLI layer against
	// ^[a-z][a-z0-9_]{0,30}$ to keep the serialised form predictable.
	// Values stored under keys whose name contains "password" or "secret"
	// are intentionally kept out of free-text search — see fake.entryMatches
	// and search handling in the store/fake layer.
	Fields map[string]string
}

// fieldKeyPrefix is the gopass-secret key prefix used for entries in
// Entry.Fields. Keeping the prefix out of band of the well-known keys
// (username, url, kind, github_project, notes, tags, domain) avoids any
// chance of collision when older entries are read back.
const fieldKeyPrefix = "field."

func open(ctx context.Context) (*Store, error) {
	gp, err := api.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("open gopass: %w", err)
	}
	return &Store{gp: gp}, nil
}

// Open opens the existing gopass store. Callers must have previously run
// `gopass setup` (the store initialisation flow). Returns ErrNotInitialized
// otherwise.
func Open(ctx context.Context) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := acquireGopassOpen(ctx); err != nil {
		return nil, err
	}
	defer releaseGopassOpen()
	return open(ctx)
}

// OpenBound opens a store and captures its mount resolver as one access
// session. The global lock anchor excludes compliant mys mutations until the
// returned SecretStore is closed, while the process gate serializes api.New.
//
// The gopass public API does not expose the mount map loaded by api.New, so
// callers must treat this opener as the integration authority instead of
// stitching a store together with later live-config observations. Deliberate
// mutation by an external raw-gopass process remains outside this package's
// advisory boundary.
func OpenBound(
	ctx context.Context,
	mounts []string,
	resolve MountPathResolver,
) (*BoundSession, error) {
	return openBoundAnchored(
		ctx,
		mounts,
		resolve,
		lockanchor.Acquire,
		func(ctx context.Context) (Interface, error) {
			return open(ctx)
		},
	)
}

type acquireAnchorFunc func(context.Context) (func() error, error)

func openBoundAnchored(
	ctx context.Context,
	mounts []string,
	resolve MountPathResolver,
	acquireAnchor acquireAnchorFunc,
	openStore func(context.Context) (Interface, error),
) (*BoundSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if acquireAnchor == nil {
		return nil, errors.New("stable lock anchor acquirer is required")
	}
	release, err := acquireAnchor(ctx)
	if err != nil {
		if release != nil {
			err = errors.Join(err, release())
		}
		return nil, err
	}
	if release == nil {
		return nil, errors.New("stable lock anchor acquirer returned nil release")
	}

	session, err := openBound(ctx, mounts, resolve, openStore)
	if err != nil {
		return nil, errors.Join(err, release())
	}
	if session == nil || session.store == nil {
		return nil, errors.Join(
			errors.New("store opener returned incomplete bound session"),
			release(),
		)
	}
	session.store = &anchoredStore{
		Interface: session.store,
		release:   release,
	}
	return session, nil
}

func openBound(
	ctx context.Context,
	mounts []string,
	resolve MountPathResolver,
	openStore func(context.Context) (Interface, error),
) (*BoundSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if openStore == nil {
		return nil, errors.New("store opener is required")
	}
	if err := acquireGopassOpen(ctx); err != nil {
		return nil, err
	}
	defer releaseGopassOpen()

	snapshot, err := CaptureMountSnapshot(ctx, mounts, resolve)
	if err != nil {
		return nil, err
	}
	opened, openErr := openStore(ctx)
	if openErr != nil {
		if opened == nil {
			return nil, openErr
		}
		return nil, errors.Join(openErr, closeBoundStore(ctx, opened))
	}
	if opened == nil {
		return nil, errors.New("store opener returned nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closeBoundStore(ctx, opened))
	}
	if err := snapshot.verify(ctx); err != nil {
		return nil, errors.Join(err, closeBoundStore(ctx, opened))
	}
	return &BoundSession{
		store:    opened,
		snapshot: snapshot,
	}, nil
}

func acquireGopassOpen(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gopassOpenGate:
		return nil
	}
}

func releaseGopassOpen() {
	gopassOpenGate <- struct{}{}
}

func closeBoundStore(ctx context.Context, opened Interface) error {
	closeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		boundStoreCleanupTimeout,
	)
	defer cancel()
	return opened.Close(closeCtx)
}

// ErrNotInitialized is re-exported from the gopass API for callers that need
// to detect the uninitialised-store condition without importing gopass.
var ErrNotInitialized = api.ErrNotInitialized

func (s *Store) Close(ctx context.Context) error {
	if s == nil || s.gp == nil {
		return nil
	}
	return s.gp.Close(ctx)
}

// List returns all secret paths, optionally filtered by an org prefix.
// An empty org means no filter.
func (s *Store) List(ctx context.Context, org string) ([]string, error) {
	all, err := s.gp.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	if org == "" {
		sort.Strings(all)
		return all, nil
	}
	prefix := strings.TrimSuffix(org, "/") + "/"
	out := make([]string, 0, len(all))
	for _, p := range all {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Search returns all secret paths whose path or metadata contains the query
// (case-insensitive). An empty query matches nothing.
//
// The allow callback, if non-nil, is consulted for every candidate path
// BEFORE the entry is decrypted. Paths for which allow returns false are
// never passed to gp.Get — i.e. denied secrets never enter process memory.
// Such paths are returned in the denied slice so callers (typically the
// app layer) can write per-path audit rows without themselves having to
// enumerate the store.
//
// When allow is nil no policy filter is applied and every candidate path
// is inspected as before; denied will then be empty.
func (s *Store) Search(ctx context.Context, query string, allow func(path string) bool) (allowed []string, denied []string, err error) {
	return s.SearchObserved(ctx, query, allow, nil)
}

// SearchObserved behaves like Search and reports only paths whose metadata
// was actually decrypted. The callback runs synchronously after gp.Get
// succeeds, regardless of whether the decrypted metadata matches the query.
func (s *Store) SearchObserved(
	ctx context.Context,
	query string,
	allow func(path string) bool,
	observer SearchObserver,
) (allowed []string, denied []string, err error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil, nil
	}
	all, err := s.gp.List(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list for search: %w", err)
	}
	q := strings.ToLower(query)
	allowed = make([]string, 0)
	denied = make([]string, 0)
	for _, p := range all {
		pathMatches := strings.Contains(strings.ToLower(p), q)
		if allow != nil && !allow(p) {
			// Policy denies this path. Never decrypt, and never surface it
			// in allowed even if the query matches the path literally —
			// policy has absolute priority.
			denied = append(denied, p)
			continue
		}
		if pathMatches {
			allowed = append(allowed, p)
			continue
		}
		// Inspect metadata without decrypting? Decrypting is the only way for
		// gopass — we accept the cost for explicit searches, but only on
		// paths that policy has cleared.
		sec, gerr := s.gp.Get(ctx, p, "latest")
		if gerr != nil {
			return nil, nil, fmt.Errorf("decrypt %q for search: %w", p, gerr)
		}
		if observer != nil {
			observer(p)
		}
		if secretMatches(sec, q) {
			allowed = append(allowed, p)
		}
	}
	sort.Strings(allowed)
	sort.Strings(denied)
	return allowed, denied, nil
}

func secretMatches(sec gopass.Secret, q string) bool {
	if sec == nil {
		return false
	}
	for _, k := range sec.Keys() {
		lk := strings.ToLower(k)
		if strings.Contains(lk, q) {
			return true
		}
		// Values of secret-like keys (a field literally named "password",
		// "secret", or "field.password" / "field.api_secret" etc.) must not
		// be searchable — the key name is, the value is not. Same guard the
		// fake store applies, kept in sync here.
		if isSecretLikeKey(lk) {
			continue
		}
		if v, ok := sec.Get(k); ok && strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(sec.Body()), q) {
		return true
	}
	return false
}

// isSecretLikeKey is the shared rule: any key whose terminal segment
// contains "password" or "secret" is treated as value-opaque for search.
// We strip the field. prefix first so "field.api_secret" is classified
// by the suffix ("api_secret") rather than the prefix.
func isSecretLikeKey(lowerKey string) bool {
	name := strings.TrimPrefix(lowerKey, fieldKeyPrefix)
	for _, marker := range secretLikeKeyMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// secretLikeKeyMarkers are substrings that mark a custom Fields key as
// value-opaque. Kept as a blocklist (not an allowlist of known-safe
// names) so existing non-secret custom fields never start rendering as
// "*** unexpected mask" just because they weren't anticipated — but the
// list must stay broad enough to cover the common credential-shaped
// field names a user is realistically going to type, since these values
// get rendered in the web UI's masked view with no Touch-ID gate at all
// (unlike Password, which always requires a fresh reveal).
var secretLikeKeyMarkers = []string{
	"password", "secret", "token", "api_key", "apikey",
	"private_key", "privatekey", "credential",
}

// IsSecretLikeFieldKey is the exported form of isSecretLikeKey, for
// consumers outside this package that need to apply the same
// value-opaque rule — e.g. the web UI masking custom Fields values the
// same way it always masks Password, rather than rendering them raw.
func IsSecretLikeFieldKey(key string) bool {
	return isSecretLikeKey(strings.ToLower(key))
}

// Get returns the decrypted entry at path.
func (s *Store) Get(ctx context.Context, path string) (*Entry, error) {
	sec, err := s.gp.Get(ctx, path, "latest")
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", path, err)
	}
	return entryFromSecret(path, sec), nil
}

// Set writes (creates or updates) the entry at e.Path.
func (s *Store) Set(ctx context.Context, e *Entry) error {
	if e == nil || e.Path == "" {
		return fmt.Errorf("set: entry path required")
	}
	sec := secrets.New()
	sec.SetPassword(e.Password)
	setIfNotEmpty(sec, "username", e.Username)
	setIfNotEmpty(sec, "url", e.URL)
	setIfNotEmpty(sec, "kind", e.Kind)
	setIfNotEmpty(sec, "github_project", e.GitHubProject)
	setIfNotEmpty(sec, "notes", e.Notes)
	setIfNotEmpty(sec, "rotate_after", e.RotateAfter)
	if !e.RotatedAt.IsZero() {
		// Always persist in RFC3339 UTC so parsing is unambiguous.
		_ = sec.Set("rotated_at", e.RotatedAt.UTC().Format(time.RFC3339))
	}
	// Domain is canonicalised before persisting so every on-disk value
	// is comparable byte-for-byte regardless of how the user spelt it
	// when calling `mys add --domain`.
	if d := NormalizeDomain(e.Domain); d != "" {
		_ = sec.Set("domain", d)
	}
	if len(e.Tags) > 0 {
		// Store tags as a single comma-separated header; gopass Get returns
		// the first value for a key anyway.
		_ = sec.Set("tags", strings.Join(e.Tags, ","))
	}
	// TOTP metadata.
	setIfNotEmpty(sec, "totp_issuer", e.TOTPIssuer)
	setIfNotEmpty(sec, "totp_label", e.TOTPLabel)
	setIfNotEmpty(sec, "totp_algorithm", e.TOTPAlgorithm)
	if e.TOTPDigits > 0 {
		_ = sec.Set("totp_digits", fmt.Sprintf("%d", e.TOTPDigits))
	}
	if e.TOTPPeriod > 0 {
		_ = sec.Set("totp_period", fmt.Sprintf("%d", e.TOTPPeriod))
	}
	// Fields are serialised as field.<key>: <value> headers. We iterate a
	// sorted key list so the on-disk representation is deterministic across
	// rewrites — helpful for diff-based auditing of the gopass git tree.
	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_ = sec.Set(fieldKeyPrefix+k, e.Fields[k])
		}
	}
	return s.gp.Set(ctx, e.Path, sec)
}

func setIfNotEmpty(sec gopass.Secret, key, value string) {
	if value == "" {
		return
	}
	_ = sec.Set(key, value)
}

// Remove deletes a secret.
func (s *Store) Remove(ctx context.Context, path string) error {
	return s.gp.Remove(ctx, path)
}

// Rotate writes a new password, keeping metadata intact.
func (s *Store) Rotate(ctx context.Context, path, newPassword string) error {
	e, err := s.Get(ctx, path)
	if err != nil {
		return err
	}
	e.Password = newPassword
	return s.Set(ctx, e)
}

// Orgs returns the unique top-level folder names seen in the store.
func (s *Store) Orgs(ctx context.Context) ([]string, error) {
	all, err := s.gp.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list for orgs: %w", err)
	}
	seen := map[string]struct{}{}
	for _, p := range all {
		if i := strings.Index(p, "/"); i > 0 {
			seen[p[:i]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for o := range seen {
		out = append(out, o)
	}
	sort.Strings(out)
	return out, nil
}

// OrgOf returns the top-level folder (org) for a given path, or an empty
// string if the path has no folder component.
func OrgOf(path string) string {
	if i := strings.Index(path, "/"); i > 0 {
		return path[:i]
	}
	return ""
}

func entryFromSecret(path string, sec gopass.Secret) *Entry {
	e := &Entry{
		Path:     path,
		Org:      OrgOf(path),
		Password: sec.Password(),
	}
	if v, ok := sec.Get("username"); ok {
		e.Username = v
	}
	if v, ok := sec.Get("url"); ok {
		e.URL = v
	}
	if v, ok := sec.Get("kind"); ok {
		e.Kind = v
	}
	if v, ok := sec.Get("github_project"); ok {
		e.GitHubProject = v
	}
	if v, ok := sec.Get("notes"); ok {
		e.Notes = v
	}
	if v, ok := sec.Get("tags"); ok && v != "" {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		e.Tags = parts
	}
	if v, ok := sec.Get("rotate_after"); ok {
		e.RotateAfter = v
	}
	if v, ok := sec.Get("rotated_at"); ok && v != "" {
		// Silently ignore parse errors — an unparseable timestamp is
		// treated as "no rotation history" rather than an operational
		// error, so reminders degrade gracefully.
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			e.RotatedAt = t.UTC()
		}
	}
	if v, ok := sec.Get("totp_issuer"); ok {
		e.TOTPIssuer = v
	}
	if v, ok := sec.Get("totp_label"); ok {
		e.TOTPLabel = v
	}
	if v, ok := sec.Get("totp_algorithm"); ok {
		e.TOTPAlgorithm = v
	}
	if v, ok := sec.Get("totp_digits"); ok && v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			e.TOTPDigits = n
		}
	}
	if v, ok := sec.Get("totp_period"); ok && v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			e.TOTPPeriod = n
		}
	}
	if v, ok := sec.Get("domain"); ok {
		// Defensive: canonicalise even when we read it back, so a legacy
		// entry written before the Set-normalisation lands here as a
		// predictable lowercase host.
		e.Domain = NormalizeDomain(v)
	}
	// Harvest any field.<key> headers into the Fields map. We do the prefix
	// check on the raw key so no other header-space collisions leak in.
	for _, k := range sec.Keys() {
		if !strings.HasPrefix(k, fieldKeyPrefix) {
			continue
		}
		name := strings.TrimPrefix(k, fieldKeyPrefix)
		if name == "" {
			continue
		}
		v, ok := sec.Get(k)
		if !ok {
			continue
		}
		if e.Fields == nil {
			e.Fields = make(map[string]string)
		}
		e.Fields[name] = v
	}
	return e
}

// MaskedPassword returns a masked preview of the password — useful for CLI
// output when --reveal is not set.
func MaskedPassword(s string) string {
	if s == "" {
		return ""
	}
	var b bytes.Buffer
	for range s {
		b.WriteByte('*')
	}
	return b.String()
}
