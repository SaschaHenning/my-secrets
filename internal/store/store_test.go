package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

func TestOrgOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"jasp/github", "jasp"},
		{"zuhause/proxmox/root", "zuhause"},
		{"top-level", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := OrgOf(tc.in); got != tc.want {
			t.Errorf("OrgOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskedPassword(t *testing.T) {
	if MaskedPassword("") != "" {
		t.Error("empty input should produce empty masked output")
	}
	if m := MaskedPassword("secret"); m != "******" {
		t.Errorf("MaskedPassword(\"secret\") = %q, want \"******\"", m)
	}
}

// TestInterfaceAssertion is a compile-time check that *Store satisfies
// Interface. The var _ declaration does the same thing at compile time, but
// a runtime check gives nicer error messages should the Interface drift.
func TestInterfaceAssertion(t *testing.T) {
	var _ Interface = (*Store)(nil)
}

// buildSecret constructs a gopass.Secret in memory (no GPG required).
func buildSecret(password string, kv map[string]string) *secrets.AKV {
	sec := secrets.NewAKV()
	sec.SetPassword(password)
	for k, v := range kv {
		_ = sec.Set(k, v)
	}
	return sec
}

func TestEntryFromSecret(t *testing.T) {
	sec := buildSecret("p1", map[string]string{
		"username":       "alice",
		"url":            "https://example.com",
		"kind":           KindAPIKey,
		"github_project": "owner/repo",
		"notes":          "primary",
		"tags":           "one, two , three",
	})
	e := entryFromSecret("jasp/github", sec)
	if e.Path != "jasp/github" || e.Org != "jasp" {
		t.Errorf("path/org = %q/%q", e.Path, e.Org)
	}
	if e.Password != "p1" {
		t.Errorf("password = %q", e.Password)
	}
	if e.Username != "alice" || e.URL != "https://example.com" || e.Kind != KindAPIKey {
		t.Errorf("metadata not copied: %+v", e)
	}
	if e.GitHubProject != "owner/repo" {
		t.Errorf("github_project = %q", e.GitHubProject)
	}
	if e.Notes != "primary" {
		t.Errorf("notes = %q", e.Notes)
	}
	if !reflect.DeepEqual(e.Tags, []string{"one", "two", "three"}) {
		t.Errorf("tags = %v", e.Tags)
	}
}

func TestEntryFromSecret_EmptyMetadata(t *testing.T) {
	// A freshly-created secret with just a password produces an entry with
	// empty metadata fields.
	sec := buildSecret("pw-only", nil)
	e := entryFromSecret("toplevel", sec)
	if e.Path != "toplevel" || e.Org != "" {
		t.Errorf("path/org = %q/%q", e.Path, e.Org)
	}
	if e.Password != "pw-only" {
		t.Errorf("password = %q", e.Password)
	}
	if e.Username != "" || e.URL != "" || e.Kind != "" || e.GitHubProject != "" ||
		e.Notes != "" || e.Tags != nil {
		t.Errorf("unexpected metadata: %+v", e)
	}
}

func TestSecretMatches(t *testing.T) {
	sec := buildSecret("shh", map[string]string{
		"username": "alice",
		"url":      "https://example.com",
		"notes":    "primary account",
	})
	// secretMatches expects its query pre-lowercased (contract with the
	// caller Search(), which lowercases before invoking).
	cases := []struct {
		q    string
		want bool
	}{
		{"alice", true},    // matches username value
		{"username", true}, // matches a key name
		{"primary", true},  // matches notes value
		{"does-not-match", false},
		{"example", true}, // matches url value
	}
	for _, tc := range cases {
		if got := secretMatches(sec, tc.q); got != tc.want {
			t.Errorf("secretMatches(%q) = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestSecretMatches_Nil(t *testing.T) {
	if secretMatches(nil, "anything") {
		t.Error("nil secret must never match")
	}
}

func TestSetIfNotEmpty(t *testing.T) {
	sec := secrets.NewAKV()
	setIfNotEmpty(sec, "k", "")
	if _, ok := sec.Get("k"); ok {
		t.Error("empty value must not be set")
	}
	setIfNotEmpty(sec, "k", "v")
	if v, _ := sec.Get("k"); v != "v" {
		t.Errorf("Get(k) = %q, want v", v)
	}
}

func TestEntryFromSecret_TOTPFields(t *testing.T) {
	sec := buildSecret("JBSWY3DPEHPK3PXP", map[string]string{
		"kind":           KindTOTP,
		"totp_issuer":    "GitHub",
		"totp_label":     "sascha",
		"totp_algorithm": "SHA256",
		"totp_digits":    "8",
		"totp_period":    "60",
	})
	e := entryFromSecret("jasp/github-2fa", sec)
	if e.Kind != KindTOTP {
		t.Errorf("kind = %q, want totp", e.Kind)
	}
	if e.Password != "JBSWY3DPEHPK3PXP" {
		t.Errorf("seed = %q", e.Password)
	}
	if e.TOTPIssuer != "GitHub" {
		t.Errorf("issuer = %q", e.TOTPIssuer)
	}
	if e.TOTPLabel != "sascha" {
		t.Errorf("label = %q", e.TOTPLabel)
	}
	if e.TOTPAlgorithm != "SHA256" {
		t.Errorf("algorithm = %q", e.TOTPAlgorithm)
	}
	if e.TOTPDigits != 8 {
		t.Errorf("digits = %d", e.TOTPDigits)
	}
	if e.TOTPPeriod != 60 {
		t.Errorf("period = %d", e.TOTPPeriod)
	}
}

func TestEntryFromSecret_TOTPFieldsMissing(t *testing.T) {
	// A regular (non-TOTP) entry must leave all TOTP fields zero.
	sec := buildSecret("p1", map[string]string{
		"username": "alice",
		"kind":     KindPassword,
	})
	e := entryFromSecret("jasp/github", sec)
	if e.TOTPIssuer != "" || e.TOTPLabel != "" || e.TOTPAlgorithm != "" ||
		e.TOTPDigits != 0 || e.TOTPPeriod != 0 {
		t.Errorf("TOTP fields leaked on non-TOTP entry: %+v", e)
	}
}

func TestEntryFromSecret_DomainAndFields(t *testing.T) {
	sec := buildSecret("p1", map[string]string{
		"username":         "alice",
		"domain":           "aws.amazon.com",
		"field.account_id": "123456",
		"field.region":     "eu-central-1",
		"field.api_secret": "do-not-leak",
	})
	e := entryFromSecret("jasp/aws", sec)
	if e.Domain != "aws.amazon.com" {
		t.Errorf("domain = %q, want aws.amazon.com", e.Domain)
	}
	if len(e.Fields) != 3 {
		t.Fatalf("fields = %+v", e.Fields)
	}
	if e.Fields["account_id"] != "123456" {
		t.Errorf("account_id = %q", e.Fields["account_id"])
	}
	if e.Fields["region"] != "eu-central-1" {
		t.Errorf("region = %q", e.Fields["region"])
	}
	if e.Fields["api_secret"] != "do-not-leak" {
		t.Errorf("api_secret value must be preserved on read: %q", e.Fields["api_secret"])
	}
}

func TestSecretMatches_SecretLikeFieldValueHidden(t *testing.T) {
	sec := buildSecret("shh", map[string]string{
		"username":         "alice",
		"field.account_id": "12345",
		"field.api_secret": "leaky-value",
	})
	// The account_id VALUE is searchable.
	if !secretMatches(sec, "12345") {
		t.Error("account_id value should match")
	}
	// The api_secret VALUE must NOT be searchable.
	if secretMatches(sec, "leaky-value") {
		t.Error("api_secret value leaked through search")
	}
	// The api_secret KEY still matches.
	if !secretMatches(sec, "api_secret") {
		t.Error("api_secret key name should match")
	}
}

func TestIsSecretLikeFieldKey(t *testing.T) {
	secretLike := []string{
		"password", "field.password", "db_password",
		"secret", "api_secret", "client_secret",
		"token", "access_token", "refresh_token",
		"api_key", "apikey",
		"private_key", "privatekey",
		"credential", "credentials",
	}
	for _, k := range secretLike {
		if !IsSecretLikeFieldKey(k) {
			t.Errorf("IsSecretLikeFieldKey(%q) = false, want true", k)
		}
	}
	safe := []string{"account_id", "region", "tenant", "username", "url", "notes"}
	for _, k := range safe {
		if IsSecretLikeFieldKey(k) {
			t.Errorf("IsSecretLikeFieldKey(%q) = true, want false", k)
		}
	}
}

// Close on a nil Store must not panic.
func TestStore_Close_Nil(t *testing.T) {
	var s *Store
	if err := s.Close(nil); err != nil {
		t.Errorf("close on nil store: %v", err)
	}
	s2 := &Store{}
	if err := s2.Close(nil); err != nil {
		t.Errorf("close on zero store: %v", err)
	}
}

func TestMountSnapshotResolverDetectsSamePathDirectoryReplacement(t *testing.T) {
	parent := t.TempDir()
	mountPath := filepath.Join(parent, "jasp")
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver := func(context.Context, string) (string, error) {
		return mountPath, nil
	}

	snapshot, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		resolver,
	)
	if err != nil {
		t.Fatalf("capture before: %v", err)
	}
	oldPath := filepath.Join(parent, "jasp-old")
	if err := os.Rename(mountPath, oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := snapshot.ResolveMountPath(
		context.Background(),
		"jasp",
	); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("resolve error = %v, want identity drift", err)
	}
}

func TestMountSnapshotResolverIsFrozenAndContextAware(t *testing.T) {
	mountPath := t.TempDir()
	resolverCalls := 0
	snapshot, err := CaptureMountSnapshot(
		nil,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			resolverCalls++
			return mountPath, nil
		},
	)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	got, err := snapshot.ResolveMountPath(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("resolve frozen path: %v", err)
	}
	want, err := filepath.EvalSymlinks(mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || resolverCalls != 1 {
		t.Fatalf(
			"path/calls = %q/%d, want %q/1",
			got,
			resolverCalls,
			want,
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := snapshot.ResolveMountPath(ctx, "jasp"); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("cancelled resolve error = %v", err)
	}
	if _, err := snapshot.ResolveMountPath(
		context.Background(),
		"missing",
	); err == nil {
		t.Fatal("missing mount resolved without error")
	}
}

func TestCaptureMountSnapshotRejectsInvalidMountNames(t *testing.T) {
	mountPath := t.TempDir()
	for _, mounts := range [][]string{
		{""},
		{" jasp"},
		{"jasp "},
		{"jasp", "jasp"},
	} {
		if _, err := CaptureMountSnapshot(
			context.Background(),
			mounts,
			func(context.Context, string) (string, error) {
				return mountPath, nil
			},
		); err == nil {
			t.Fatalf("mounts %q accepted", mounts)
		}
	}
}

func TestCaptureMountSnapshotFailsClosedOnResolverAndPathErrors(t *testing.T) {
	if _, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		nil,
	); err == nil {
		t.Fatal("nil resolver was accepted")
	}

	resolveErr := errors.New("resolver failed")
	if _, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return "", resolveErr
		},
	); !errors.Is(err, resolveErr) {
		t.Fatalf("resolver error = %v, want %v", err, resolveErr)
	}
	if _, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return " \t", nil
		},
	); err == nil {
		t.Fatal("blank resolver path was accepted")
	}
	if _, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return filepath.Join(t.TempDir(), "missing"), nil
		},
	); err == nil {
		t.Fatal("missing resolver path was accepted")
	}
	filePath := filepath.Join(t.TempDir(), "mount-file")
	if err := os.WriteFile(filePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureMountSnapshot(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return filePath, nil
		},
	); err == nil {
		t.Fatal("file resolver path was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureMountSnapshot(
		ctx,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			t.Fatal("resolver called after cancellation")
			return "", nil
		},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled capture error = %v", err)
	}
}

func TestNilBoundSessionIsUnavailable(t *testing.T) {
	var session *BoundSession
	if session.SecretStore() != nil {
		t.Fatal("nil session returned a store")
	}
	if _, err := session.ResolveMountPath(nil, "jasp"); err == nil {
		t.Fatal("nil session resolved a mount")
	}
}

type boundCloseProbe struct {
	*Store
	mu          sync.Mutex
	closeCalls  int
	closeCtxErr error
	hasDeadline bool
	closeErr    error
}

func (probe *boundCloseProbe) Close(ctx context.Context) error {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	probe.closeCalls++
	probe.closeCtxErr = ctx.Err()
	_, probe.hasDeadline = ctx.Deadline()
	return probe.closeErr
}

func TestOpenBoundPairsStoreWithFrozenResolverAndAcceptsNilContext(t *testing.T) {
	mountPath := t.TempDir()
	livePath := mountPath
	resolverCalls := 0
	probe := &Store{}

	session, err := openBound(
		nil,
		[]string{"jasp"},
		func(ctx context.Context, _ string) (string, error) {
			if ctx == nil {
				t.Fatal("resolver received nil context")
			}
			resolverCalls++
			return livePath, nil
		},
		func(ctx context.Context) (Interface, error) {
			if ctx == nil {
				t.Fatal("opener received nil context")
			}
			return probe, nil
		},
	)
	if err != nil {
		t.Fatalf("open bound: %v", err)
	}
	livePath = t.TempDir()
	got, err := session.ResolveMountPath(nil, "jasp")
	if err != nil {
		t.Fatalf("resolve bound mount: %v", err)
	}
	want, err := filepath.EvalSymlinks(mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if session.SecretStore() != probe || got != want || resolverCalls != 1 {
		t.Fatalf(
			"store/path/calls = %p/%q/%d, want %p/%q/1",
			session.SecretStore(),
			got,
			resolverCalls,
			probe,
			want,
		)
	}
}

func TestOpenBoundSerializesConcurrentCaptureAndOpen(t *testing.T) {
	mountPath := t.TempDir()
	var active int32
	var maxActive int32
	const sessions = 8
	var wait sync.WaitGroup
	errs := make(chan error, sessions)
	wait.Add(sessions)
	for range sessions {
		go func() {
			defer wait.Done()
			_, err := openBound(
				context.Background(),
				[]string{"jasp"},
				func(context.Context, string) (string, error) {
					return mountPath, nil
				},
				func(context.Context) (Interface, error) {
					now := atomic.AddInt32(&active, 1)
					for {
						previous := atomic.LoadInt32(&maxActive)
						if now <= previous ||
							atomic.CompareAndSwapInt32(&maxActive, previous, now) {
							break
						}
					}
					time.Sleep(5 * time.Millisecond)
					atomic.AddInt32(&active, -1)
					return &Store{}, nil
				},
			)
			errs <- err
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent open: %v", err)
		}
	}
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("concurrent open sections = %d, want 1", got)
	}
}

func TestOpenBoundClosesStoreAfterCancellationDuringOpen(t *testing.T) {
	mountPath := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	probe := &boundCloseProbe{Store: &Store{}}

	session, err := openBound(
		ctx,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		func(context.Context) (Interface, error) {
			cancel()
			return probe, nil
		},
	)
	if session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("session/error = %+v/%v, want cancellation", session, err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.closeCalls != 1 || probe.closeCtxErr != nil || !probe.hasDeadline {
		t.Fatalf(
			"close = calls:%d err:%v deadline:%t",
			probe.closeCalls,
			probe.closeCtxErr,
			probe.hasDeadline,
		)
	}
}

func TestOpenBoundClosesStoreWhenMountIdentityChangesDuringOpen(t *testing.T) {
	parent := t.TempDir()
	mountPath := filepath.Join(parent, "jasp")
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("close failed")
	probe := &boundCloseProbe{
		Store:    &Store{},
		closeErr: closeErr,
	}

	session, err := openBound(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		func(context.Context) (Interface, error) {
			if err := os.Rename(
				mountPath,
				filepath.Join(parent, "jasp-old"),
			); err != nil {
				return nil, err
			}
			if err := os.Mkdir(mountPath, 0o700); err != nil {
				return nil, err
			}
			return probe, nil
		},
	)
	if session != nil ||
		err == nil ||
		!strings.Contains(err.Error(), "identity changed") ||
		!errors.Is(err, closeErr) {
		t.Fatalf("session/error = %+v/%v, want identity and close failures", session, err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.closeCalls != 1 || probe.closeCtxErr != nil || !probe.hasDeadline {
		t.Fatalf(
			"close = calls:%d err:%v deadline:%t",
			probe.closeCalls,
			probe.closeCtxErr,
			probe.hasDeadline,
		)
	}
}

func TestOpenBoundRejectsMissingOpenerBeforeResolving(t *testing.T) {
	resolverCalls := 0
	session, err := openBound(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			resolverCalls++
			return t.TempDir(), nil
		},
		nil,
	)
	if session != nil || err == nil {
		t.Fatalf("session/error = %+v/%v, want missing opener", session, err)
	}
	if resolverCalls != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolverCalls)
	}
}

func TestOpenBoundHonorsCancelledContextBeforeProductionOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session, err := OpenBound(
		ctx,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			t.Fatal("resolver called after cancellation")
			return "", nil
		},
	)
	if session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("session/error = %+v/%v, want cancellation", session, err)
	}
}

func TestOpenBoundAnchorRemainsHeldUntilSessionStoreClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mountPath := t.TempDir()
	session, err := openBoundAnchored(
		ctx,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		lockanchor.Acquire,
		func(context.Context) (Interface, error) {
			return &Store{}, nil
		},
	)
	if err != nil {
		t.Fatalf("open anchored session: %v", err)
	}

	type acquireResult struct {
		release func() error
		err     error
	}
	secondCtx, secondCancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer secondCancel()
	second := make(chan acquireResult, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		release, acquireErr := lockanchor.Acquire(secondCtx)
		second <- acquireResult{release: release, err: acquireErr}
	}()
	<-started
	select {
	case result := <-second:
		if result.release != nil {
			_ = result.release()
		}
		t.Fatalf("second anchor acquired before store close: %v", result.err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := session.SecretStore().Close(nil); err != nil {
		t.Fatalf("close anchored store: %v", err)
	}
	select {
	case result := <-second:
		if result.err != nil {
			t.Fatalf("acquire after store close: %v", result.err)
		}
		if result.release == nil {
			t.Fatal("acquire after store close returned nil release")
		}
		if err := result.release(); err != nil {
			t.Fatalf("release second anchor: %v", err)
		}
	case <-secondCtx.Done():
		t.Fatalf("second anchor remained blocked after store close: %v", secondCtx.Err())
	}
}

func TestAnchoredStoreCloseJoinsErrorsAndRunsExactlyOnce(t *testing.T) {
	mountPath := t.TempDir()
	closeErr := errors.New("store close failed")
	releaseErr := errors.New("anchor release failed")
	probe := &boundCloseProbe{
		Store:    &Store{},
		closeErr: closeErr,
	}
	releaseCalls := 0
	session, err := openBoundAnchored(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		func(context.Context) (func() error, error) {
			return func() error {
				releaseCalls++
				return releaseErr
			}, nil
		},
		func(context.Context) (Interface, error) {
			return probe, nil
		},
	)
	if err != nil {
		t.Fatalf("open anchored session: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		err := session.SecretStore().Close(nil)
		if !errors.Is(err, closeErr) || !errors.Is(err, releaseErr) {
			t.Fatalf("close attempt %d error = %v", attempt, err)
		}
	}
	probe.mu.Lock()
	closeCalls := probe.closeCalls
	closeCtxErr := probe.closeCtxErr
	probe.mu.Unlock()
	if closeCalls != 1 || closeCtxErr != nil || releaseCalls != 1 {
		t.Fatalf(
			"close/release = %d/%d, close context error %v",
			closeCalls,
			releaseCalls,
			closeCtxErr,
		)
	}
}

func TestOpenBoundAnchoredReleasesAfterPartialOpenFailure(t *testing.T) {
	mountPath := t.TempDir()
	openErr := errors.New("open failed")
	closeErr := errors.New("close failed")
	releaseErr := errors.New("release failed")
	probe := &boundCloseProbe{
		Store:    &Store{},
		closeErr: closeErr,
	}
	releaseCalls := 0
	session, err := openBoundAnchored(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		func(context.Context) (func() error, error) {
			return func() error {
				releaseCalls++
				return releaseErr
			}, nil
		},
		func(context.Context) (Interface, error) {
			return probe, openErr
		},
	)
	if session != nil ||
		!errors.Is(err, openErr) ||
		!errors.Is(err, closeErr) ||
		!errors.Is(err, releaseErr) {
		t.Fatalf("session/error = %+v/%v, want joined failures", session, err)
	}
	probe.mu.Lock()
	closeCalls := probe.closeCalls
	closeCtxErr := probe.closeCtxErr
	hasDeadline := probe.hasDeadline
	probe.mu.Unlock()
	if closeCalls != 1 ||
		closeCtxErr != nil ||
		!hasDeadline ||
		releaseCalls != 1 {
		t.Fatalf(
			"close/release = %d/%d, context:%v deadline:%t",
			closeCalls,
			releaseCalls,
			closeCtxErr,
			hasDeadline,
		)
	}
}

func TestOpenBoundAnchoredRejectsInvalidAcquirerResults(t *testing.T) {
	mountPath := t.TempDir()
	acquireErr := errors.New("anchor unavailable")
	releaseCalls := 0
	tests := []struct {
		name    string
		acquire acquireAnchorFunc
		want    error
	}{
		{
			name:    "missing acquirer",
			acquire: nil,
		},
		{
			name: "error with defensive release",
			acquire: func(context.Context) (func() error, error) {
				return func() error {
					releaseCalls++
					return nil
				}, acquireErr
			},
			want: acquireErr,
		},
		{
			name: "nil release",
			acquire: func(context.Context) (func() error, error) {
				return nil, nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			openCalls := 0
			session, err := openBoundAnchored(
				context.Background(),
				[]string{"jasp"},
				func(context.Context, string) (string, error) {
					return mountPath, nil
				},
				test.acquire,
				func(context.Context) (Interface, error) {
					openCalls++
					return &Store{}, nil
				},
			)
			if session != nil || err == nil {
				t.Fatalf("session/error = %+v/%v, want fail-closed", session, err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if openCalls != 0 {
				t.Fatalf("store opened %d times", openCalls)
			}
		})
	}
	if releaseCalls != 1 {
		t.Fatalf("defensive release calls = %d, want 1", releaseCalls)
	}
}

func TestOpenBoundClosesPartialStoreAndJoinsOpenError(t *testing.T) {
	mountPath := t.TempDir()
	openErr := errors.New("open failed")
	closeErr := errors.New("close failed")
	probe := &boundCloseProbe{
		Store:    &Store{},
		closeErr: closeErr,
	}

	session, err := openBound(
		context.Background(),
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			return mountPath, nil
		},
		func(context.Context) (Interface, error) {
			return probe, openErr
		},
	)
	if session != nil ||
		!errors.Is(err, openErr) ||
		!errors.Is(err, closeErr) {
		t.Fatalf("session/error = %+v/%v, want joined open and close errors", session, err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.closeCalls != 1 || probe.closeCtxErr != nil || !probe.hasDeadline {
		t.Fatalf(
			"close = calls:%d err:%v deadline:%t",
			probe.closeCalls,
			probe.closeCtxErr,
			probe.hasDeadline,
		)
	}
}

func TestOpenBoundCancelledWaiterDoesNotInvokeResolverOrOpener(t *testing.T) {
	<-gopassOpenGate
	defer releaseGopassOpen()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolverCalls := 0
	openCalls := 0
	session, err := openBound(
		ctx,
		[]string{"jasp"},
		func(context.Context, string) (string, error) {
			resolverCalls++
			return t.TempDir(), nil
		},
		func(context.Context) (Interface, error) {
			openCalls++
			return &Store{}, nil
		},
	)
	if session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("session/error = %+v/%v, want cancellation", session, err)
	}
	if resolverCalls != 0 || openCalls != 0 {
		t.Fatalf("resolver/open calls = %d/%d, want 0/0", resolverCalls, openCalls)
	}
}
