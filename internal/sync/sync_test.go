package sync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedRunner is a scriptable Runner used by the AutoSync/PushAll tests.
// It records every invocation so tests can assert on the argv and maps
// a command template to a canned result. Any unmatched call returns
// errUnexpected.
type scriptedRunner struct {
	calls    [][]string
	results  map[string]scriptedResult
	fallback scriptedResult
}

type scriptedResult struct {
	out []byte
	err error
	// block=true makes Run respect ctx.Done() and return ctx.Err() once
	// the context fires. Used to exercise the timeout path.
	block bool
}

func (f *scriptedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	key := name
	for _, a := range args {
		key += " " + a
	}
	res, ok := f.results[key]
	if !ok {
		res = f.fallback
	}
	if res.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return res.out, res.err
}

func writeTempSyncConfig(t *testing.T, c *Config) string {
	t.Helper()
	dir := t.TempDir()
	// Point HOME at the tempdir so DefaultPath() resolves under it.
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, ".config", "my-secrets", "sync.yaml")
	if err := Save(path, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

func TestPushAll_Success(t *testing.T) {
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Layout:  LayoutPerOrg,
		Remotes: []StoreRemote{
			{Mount: "jasp", URL: "git@github.com:me/jasp-secrets.git"},
			{Mount: "zuhause", URL: "git@github.com:me/zuhause-secrets.git"},
		},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync --store jasp":    {out: []byte("ok")},
		"gopass sync --store zuhause": {out: []byte("ok")},
	}}
	if err := PushAll(context.Background(), r); err != nil {
		t.Fatalf("PushAll: %v", err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("want 2 gopass calls, got %d: %v", len(r.calls), r.calls)
	}
}

func TestPushAll_RemoteError(t *testing.T) {
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{
			{Mount: "jasp", URL: "git@github.com:me/jasp-secrets.git"},
		},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync --store jasp": {err: errors.New("network unreachable")},
	}}
	err := PushAll(context.Background(), r)
	if err == nil {
		t.Fatal("want error from failing remote, got nil")
	}
}

func TestPushAll_NoRemotes(t *testing.T) {
	writeTempSyncConfig(t, &Config{Version: 1})
	r := &scriptedRunner{}
	if err := PushAll(context.Background(), r); err != nil {
		t.Fatalf("PushAll with no remotes should be a no-op, got err=%v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("want 0 calls, got %d", len(r.calls))
	}
}

func TestAutoSync_Success(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{{Mount: "root", URL: "x"}},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync": {out: []byte("ok")}, // root → no --store arg
	}}
	skipped, err := AutoSync(context.Background(), r, "add jasp/foo")
	if err != nil {
		t.Fatalf("AutoSync: %v", err)
	}
	if skipped {
		t.Error("want skipped=false on a configured remote")
	}
	if len(r.calls) != 1 {
		t.Errorf("want 1 sync call, got %d", len(r.calls))
	}
}

func TestAutoSync_Error(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{{Mount: "root", URL: "x"}},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync": {err: errors.New("boom")},
	}}
	skipped, err := AutoSync(context.Background(), r, "add x")
	if skipped {
		t.Error("want skipped=false on runner error")
	}
	if err == nil {
		t.Fatal("want err from failing sync")
	}
}

func TestAutoSync_Timeout(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{{Mount: "root", URL: "x"}},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync": {block: true},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	skipped, err := AutoSync(ctx, r, "add x")
	if skipped {
		t.Error("want skipped=false when runner runs into a timeout")
	}
	if err == nil {
		t.Fatal("want timeout error")
	}
}

func TestAutoSync_EnvOff(t *testing.T) {
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{{Mount: "root", URL: "x"}},
	})
	for _, v := range []string{"0", "false", "FALSE", "off", "no"} {
		t.Run("MYS_AUTO_SYNC="+v, func(t *testing.T) {
			t.Setenv("MYS_AUTO_SYNC", v)
			r := &scriptedRunner{}
			skipped, err := AutoSync(context.Background(), r, "add x")
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !skipped {
				t.Error("want skipped=true when MYS_AUTO_SYNC is off")
			}
			if len(r.calls) != 0 {
				t.Errorf("want 0 runner calls, got %d", len(r.calls))
			}
		})
	}
}

func TestAutoSync_EnvOn(t *testing.T) {
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{{Mount: "root", URL: "x"}},
	})
	for _, v := range []string{"", "1", "true", "yes", "on", "anything"} {
		t.Run("MYS_AUTO_SYNC="+v, func(t *testing.T) {
			t.Setenv("MYS_AUTO_SYNC", v)
			r := &scriptedRunner{results: map[string]scriptedResult{
				"gopass sync": {out: []byte("ok")},
			}}
			skipped, _ := AutoSync(context.Background(), r, "add x")
			if skipped {
				t.Errorf("want skipped=false for value %q", v)
			}
		})
	}
}

func TestAutoSync_NoRemotes(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{Version: 1})
	r := &scriptedRunner{}
	skipped, err := AutoSync(context.Background(), r, "add x")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !skipped {
		t.Error("want skipped=true when no remotes configured")
	}
}

func TestAutoSync_SkipsSharedRemotes(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{
			{Mount: "jasp", URL: "shared", Shared: true},
			{Mount: DefaultStoreMount, URL: "personal"},
		},
	})
	r := &scriptedRunner{results: map[string]scriptedResult{
		"gopass sync": {out: []byte("ok")},
	}}
	skipped, err := AutoSync(context.Background(), r, "add private/example")
	if err != nil {
		t.Fatalf("AutoSync: %v", err)
	}
	if skipped {
		t.Fatal("expected the personal remote to be synced")
	}
	if len(r.calls) != 1 || strings.Join(r.calls[0], " ") != "gopass sync" {
		t.Fatalf("calls = %v, want only the personal root sync", r.calls)
	}
}

func TestAutoSync_OnlySharedRemoteIsSkipped(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	writeTempSyncConfig(t, &Config{
		Version: 1,
		Remotes: []StoreRemote{
			{Mount: "jasp", URL: "shared", Shared: true},
		},
	})
	r := &scriptedRunner{}
	skipped, err := AutoSync(context.Background(), r, "add private/example")
	if err != nil {
		t.Fatalf("AutoSync: %v", err)
	}
	if !skipped {
		t.Fatal("expected shared-only auto-sync to be skipped")
	}
	if len(r.calls) != 0 {
		t.Fatalf("shared remote must not auto-sync after a personal write: %v", r.calls)
	}
}

func TestAutoSync_NoConfigFile(t *testing.T) {
	t.Setenv("MYS_AUTO_SYNC", "")
	// Point HOME at a tempdir that has no sync.yaml.
	t.Setenv("HOME", t.TempDir())
	r := &scriptedRunner{}
	skipped, err := AutoSync(context.Background(), r, "add x")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !skipped {
		t.Error("want skipped=true when sync config file does not exist")
	}
}

func TestIsAutoSyncDisabled(t *testing.T) {
	cases := map[string]bool{
		"":        false,
		"1":       false,
		"true":    false,
		"yes":     false,
		"on":      false,
		"0":       true,
		"false":   true,
		"FALSE":   true,
		"  off  ": true,
		"No":      true,
	}
	for v, want := range cases {
		t.Run(v, func(t *testing.T) {
			t.Setenv("MYS_AUTO_SYNC", v)
			if got := IsAutoSyncDisabled(); got != want {
				t.Errorf("IsAutoSyncDisabled(%q) = %v, want %v", v, got, want)
			}
		})
	}
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync.yaml")

	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	in := &Config{
		Version: 1,
		Layout:  LayoutPerOrg,
		Owner:   "alice",
		Remotes: []StoreRemote{
			{
				Mount:    "jasp",
				URL:      "git@github.com:alice/jasp-secrets.git",
				LastSync: now,
				Shared:   true,
				TeamAudit: &TeamAuditConfig{
					URL:                "git@github.com:alice/jasp-audit.git",
					SigningFingerprint: strings.Repeat("A", 40),
				},
			},
			{Mount: "zuhause", URL: "https://github.com/alice/zuhause-secrets.git"},
		},
	}

	if err := Save(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Layout != in.Layout {
		t.Errorf("layout mismatch: got %q want %q", out.Layout, in.Layout)
	}
	if out.Owner != in.Owner {
		t.Errorf("owner mismatch: got %q want %q", out.Owner, in.Owner)
	}
	if len(out.Remotes) != 2 {
		t.Fatalf("remotes: got %d want 2", len(out.Remotes))
	}
	if out.Remotes[0].Mount != "jasp" {
		t.Errorf("remote[0].mount: got %q", out.Remotes[0].Mount)
	}
	if !out.Remotes[0].LastSync.Equal(now) {
		t.Errorf("last_sync round-trip: got %v want %v", out.Remotes[0].LastSync, now)
	}
	if !out.Remotes[0].Shared {
		t.Error("shared marker did not round-trip")
	}
	if out.Remotes[0].TeamAudit == nil ||
		out.Remotes[0].TeamAudit.URL != in.Remotes[0].TeamAudit.URL ||
		out.Remotes[0].TeamAudit.SigningFingerprint !=
			in.Remotes[0].TeamAudit.SigningFingerprint {
		t.Fatalf("team_audit did not round-trip: %+v", out.Remotes[0].TeamAudit)
	}
	if out.Remotes[1].Shared {
		t.Error("personal remote unexpectedly became shared")
	}
}

func TestNormalizeTeamAuditFingerprint(t *testing.T) {
	const lower = "0123456789abcdef0123456789abcdef01234567"
	got, err := NormalizeTeamAuditFingerprint("  " + lower + "  ")
	if err != nil {
		t.Fatalf("NormalizeTeamAuditFingerprint: %v", err)
	}
	if want := strings.ToUpper(lower); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}

	for _, invalid := range []string{
		"",
		"1234",
		strings.Repeat("G", 40),
		strings.Repeat("A", 39),
		strings.Repeat("A", 41),
	} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := NormalizeTeamAuditFingerprint(invalid); err == nil {
				t.Fatalf("expected %q to be rejected", invalid)
			}
		})
	}
}

func TestGhRepoVisibilityFailsClosed(t *testing.T) {
	binaryDir := t.TempDir()
	ghPath := filepath.Join(binaryDir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", binaryDir)

	tests := []struct {
		name           string
		response       scriptedResult
		wantVisibility RepoVisibility
		wantExists     bool
		wantError      bool
	}{
		{
			name:           "private",
			response:       scriptedResult{out: []byte("PRIVATE\n")},
			wantVisibility: RepoVisibilityPrivate,
			wantExists:     true,
		},
		{
			name:           "public",
			response:       scriptedResult{out: []byte("PUBLIC\n")},
			wantVisibility: RepoVisibilityPublic,
			wantExists:     true,
		},
		{
			name:           "internal",
			response:       scriptedResult{out: []byte("INTERNAL\n")},
			wantVisibility: RepoVisibilityInternal,
			wantExists:     true,
		},
		{
			name:     "not found",
			response: scriptedResult{err: errors.New("HTTP 404")},
		},
		{
			name:      "API error",
			response:  scriptedResult{err: errors.New("API unavailable")},
			wantError: true,
		},
		{
			name:      "unexpected output",
			response:  scriptedResult{out: []byte("UNKNOWN\n")},
			wantError: true,
		},
		{
			name:      "empty output",
			response:  scriptedResult{},
			wantError: true,
		},
	}
	const command = "gh repo view jasp/mys-audit --json visibility --jq .visibility"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{results: map[string]scriptedResult{
				command: test.response,
			}}
			visibility, exists, err := GhRepoVisibility(
				context.Background(),
				runner,
				"jasp",
				"mys-audit",
			)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError=%v", err, test.wantError)
			}
			if visibility != test.wantVisibility || exists != test.wantExists {
				t.Fatalf(
					"visibility = %q exists=%v, want %q exists=%v",
					visibility,
					exists,
					test.wantVisibility,
					test.wantExists,
				)
			}
		})
	}
}

func TestGhRepoCreateUsesPrivateNonInteractiveArguments(t *testing.T) {
	binaryDir := t.TempDir()
	ghPath := filepath.Join(binaryDir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", binaryDir)

	runner := &scriptedRunner{results: map[string]scriptedResult{
		"gh repo create jasp/mys-audit --private": {
			out: []byte("created\n"),
		},
	}}
	if _, err := GhRepoCreate(
		context.Background(),
		runner,
		"jasp",
		"mys-audit",
	); err != nil {
		t.Fatalf("GhRepoCreate: %v", err)
	}
	if len(runner.calls) != 1 ||
		strings.Join(runner.calls[0], " ") !=
			"gh repo create jasp/mys-audit --private" {
		t.Fatalf("create calls = %v", runner.calls)
	}
}

func TestConfigValidation(t *testing.T) {
	validAudit := &TeamAuditConfig{
		URL:                "file:///tmp/jasp-audit.git",
		SigningFingerprint: strings.Repeat("A", 40),
	}
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "duplicate mount",
			cfg: &Config{Remotes: []StoreRemote{
				{Mount: "jasp", URL: "one"},
				{Mount: "jasp", URL: "two"},
			}},
			want: "duplicate",
		},
		{
			name: "empty mount",
			cfg:  &Config{Remotes: []StoreRemote{{Mount: " ", URL: "one"}}},
			want: "empty",
		},
		{
			name: "padded mount",
			cfg:  &Config{Remotes: []StoreRemote{{Mount: " jasp", URL: "one"}}},
			want: "whitespace",
		},
		{
			name: "root cannot be shared",
			cfg:  &Config{Remotes: []StoreRemote{{Mount: DefaultStoreMount, Shared: true}}},
			want: "root",
		},
		{
			name: "shared mount cannot escape top level",
			cfg:  &Config{Remotes: []StoreRemote{{Mount: "../jasp", Shared: true}}},
			want: "invalid character",
		},
		{
			name: "valid shared mount",
			cfg:  &Config{Remotes: []StoreRemote{{Mount: "jasp", Shared: true}}},
		},
		{
			name: "team audit requires shared mount",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", TeamAudit: validAudit,
			}}},
			want: "team audit",
		},
		{
			name: "root cannot have team audit",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: DefaultStoreMount, URL: "file:///tmp/store.git",
				Shared: true, TeamAudit: validAudit,
			}}},
			want: "root",
		},
		{
			name: "team audit url required",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					SigningFingerprint: strings.Repeat("A", 40),
				},
			}}},
			want: "team audit",
		},
		{
			name: "team audit fingerprint required",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{URL: "file:///tmp/audit.git"},
			}}},
			want: "fingerprint",
		},
		{
			name: "team audit fingerprint must be canonical uppercase",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL:                "file:///tmp/audit.git",
					SigningFingerprint: strings.Repeat("a", 40),
				},
			}}},
			want: "fingerprint",
		},
		{
			name: "team audit repo differs from store repo",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL:                "file:///tmp/store.git",
					SigningFingerprint: strings.Repeat("A", 40),
				},
			}}},
			want: "must differ",
		},
		{
			name: "team audit local repo differs across url styles",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL:                "/tmp/store.git",
					SigningFingerprint: strings.Repeat("A", 40),
				},
			}}},
			want: "must differ",
		},
		{
			name: "team audit network repo differs across url styles",
			cfg: &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "git@github.com:jasp/audit.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL:                "ssh://git@github.com/jasp/audit",
					SigningFingerprint: strings.Repeat("A", 40),
				},
			}}},
			want: "must differ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestTeamAuditURLValidation(t *testing.T) {
	const fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
	valid := []string{
		"/tmp/jasp-audit.git",
		"file:///tmp/jasp-audit.git",
		"https://github.com/jasp/audit.git",
		"ssh://git@github.com/jasp/audit.git",
		"git@github.com:jasp/audit.git",
	}
	for _, auditURL := range valid {
		t.Run("valid "+auditURL, func(t *testing.T) {
			cfg := &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/jasp-store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL: auditURL, SigningFingerprint: fingerprint,
				},
			}}}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate(%q): %v", auditURL, err)
			}
		})
	}

	invalid := []string{
		"/",
		"relative/audit.git",
		"http://github.com/jasp/audit.git",
		"https://token@github.com/jasp/audit.git",
		"https://user:secret@github.com/jasp/audit.git",
		"https://github.com/jasp/audit.git?token=secret",
		"https://github.com/jasp/audit.git#fragment",
		"https:///jasp/audit.git",
		"ssh://git:secret@github.com/jasp/audit.git",
		"ssh:///jasp/audit.git",
		"ssh://bad$user@github.com/jasp/audit.git",
		"ssh://git@github.com/jasp/../audit.git",
		"file://remotehost/tmp/audit.git",
		"file:///",
		"file:audit.git",
		"file:///tmp/../audit.git",
		"ext::sh -c exploit",
		"-upload-pack=exploit",
		"git@github.com:",
		"git@github.com:jasp/../audit.git",
		"git@github.com:jasp/audit;touch-pwned.git",
		"git@github.com:jasp/audit.git\n--upload-pack=exploit",
	}
	for _, auditURL := range invalid {
		t.Run("invalid "+auditURL, func(t *testing.T) {
			cfg := &Config{Remotes: []StoreRemote{{
				Mount: "jasp", URL: "file:///tmp/jasp-store.git", Shared: true,
				TeamAudit: &TeamAuditConfig{
					URL: auditURL, SigningFingerprint: fingerprint,
				},
			}}}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected %q to be rejected", auditURL)
			}
			for _, sensitive := range []string{
				auditURL, "token", "secret", "exploit",
			} {
				if sensitive != "" && strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error disclosed rejected input %q: %v", sensitive, err)
				}
			}
		})
	}
}

func TestMergeSharedFrom(t *testing.T) {
	now := time.Date(2026, 7, 24, 17, 0, 0, 0, time.UTC)
	audit := &TeamAuditConfig{
		URL:                "file:///tmp/audit.git",
		SigningFingerprint: strings.Repeat("A", 40),
	}
	tests := []struct {
		name     string
		current  *Config
		previous *Config
		wantErr  string
		check    func(*testing.T, *Config)
	}{
		{
			name: "preserves only shared remotes",
			current: &Config{
				Version: 1,
				Layout:  LayoutSingle,
				Remotes: []StoreRemote{{Mount: DefaultStoreMount, URL: "new-personal.git"}},
			},
			previous: &Config{
				Version:  1,
				Revision: 7,
				Layout:   LayoutPerOrg,
				Remotes: []StoreRemote{
					{Mount: "old-personal", URL: "old.git"},
					{
						Mount: "jasp", URL: "shared.git", Shared: true,
						LastSync: now, TeamAudit: audit,
					},
				},
			},
			check: func(t *testing.T, got *Config) {
				t.Helper()
				if len(got.Remotes) != 2 {
					t.Fatalf("remotes = %+v, want personal plus shared", got.Remotes)
				}
				shared, ok := got.Remote("jasp")
				if !ok || !shared.Shared || shared.URL != "shared.git" ||
					!shared.LastSync.Equal(now) {
					t.Fatalf("preserved shared remote = %+v", shared)
				}
				if shared.TeamAudit == nil ||
					shared.TeamAudit.URL != "file:///tmp/audit.git" {
					t.Fatalf("preserved team audit = %+v", shared.TeamAudit)
				}
				var mergedAudit *TeamAuditConfig
				for i := range got.Remotes {
					if got.Remotes[i].Mount == "jasp" {
						mergedAudit = got.Remotes[i].TeamAudit
						break
					}
				}
				if mergedAudit == nil {
					t.Fatal("merged team audit was not retained")
				}
				mergedAudit.URL = "file:///tmp/mutated.git"
				if audit.URL != "file:///tmp/audit.git" {
					t.Fatal("MergeSharedFrom aliased the previous team-audit pointer")
				}
				if _, ok := got.Remote("old-personal"); ok {
					t.Fatal("stale personal remote was preserved")
				}
				if got.Revision != 7 {
					t.Fatalf("revision = %d, want loaded revision 7", got.Revision)
				}
			},
		},
		{
			name: "conflicting personal result fails closed",
			current: &Config{
				Version: 1,
				Remotes: []StoreRemote{{Mount: "jasp", URL: "personal.git"}},
			},
			previous: &Config{
				Version: 1,
				Remotes: []StoreRemote{{Mount: "jasp", URL: "shared.git", Shared: true}},
			},
			wantErr: "conflicts",
		},
		{
			name: "invalid previous config fails closed",
			current: &Config{
				Version: 1,
			},
			previous: &Config{
				Version: 1,
				Remotes: []StoreRemote{
					{Mount: "jasp", URL: "one.git", Shared: true},
					{Mount: "jasp", URL: "two.git", Shared: true},
				},
			},
			wantErr: "duplicate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.current.MergeSharedFrom(test.previous)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MergeSharedFrom: %v", err)
			}
			test.check(t, test.current)
		})
	}
}

func TestRemoteReturnsDeepCopy(t *testing.T) {
	cfg := &Config{Remotes: []StoreRemote{{
		Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
		TeamAudit: &TeamAuditConfig{
			URL:                "file:///tmp/audit.git",
			SigningFingerprint: strings.Repeat("A", 40),
		},
	}}}
	remote, ok := cfg.Remote("jasp")
	if !ok {
		t.Fatal("Remote did not find configured mount")
	}
	remote.TeamAudit.URL = "file:///tmp/mutated.git"
	if cfg.Remotes[0].TeamAudit.URL != "file:///tmp/audit.git" {
		t.Fatal("Remote returned an aliased team-audit pointer")
	}
}

func TestCloneStoreRemotesDeepCopiesTeamAudit(t *testing.T) {
	original := []StoreRemote{{
		Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
		TeamAudit: &TeamAuditConfig{
			URL:                "file:///tmp/audit.git",
			SigningFingerprint: strings.Repeat("A", 40),
		},
	}}
	cloned := cloneStoreRemotes(original)
	cloned[0].TeamAudit.URL = "file:///tmp/mutated.git"
	if original[0].TeamAudit.URL != "file:///tmp/audit.git" {
		t.Fatal("cloneStoreRemotes aliased the team-audit pointer")
	}
}

func TestLoadRejectsDuplicateMounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	body := []byte("version: 1\nlayout: per-org\nremotes:\n" +
		"  - mount: jasp\n    url: one\n" +
		"  - mount: jasp\n    url: two\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Load error = %v, want duplicate mount error", err)
	}
}

func TestLoadRejectsUnsafeYAML(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown top-level field",
			body: "version: 1\nlayout: per-org\nremotes: []\nlayuot: single\n",
		},
		{
			name: "unknown nested field",
			body: "version: 1\nremotes:\n" +
				"  - mount: jasp\n    url: /tmp/store.git\n    shraed: true\n",
		},
		{
			name: "unknown team audit field",
			body: "version: 1\nremotes:\n" +
				"  - mount: jasp\n    url: /tmp/store.git\n    shared: true\n" +
				"    team_audit:\n      url: /tmp/audit.git\n" +
				"      signing_fingeprint: " + strings.Repeat("A", 40) + "\n",
		},
		{
			name: "duplicate key",
			body: "version: 1\nversion: 1\nremotes: []\n",
		},
		{
			name: "multiple documents",
			body: "version: 1\nremotes: []\n---\nversion: 1\nremotes: []\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sync.yaml")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted %s", test.name)
			}
		})
	}
}

func TestLoadRejectsUnsafeFiles(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sync.yaml")
		if err := os.WriteFile(
			path, make([]byte, maxSyncConfigBytes+1), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil ||
			!strings.Contains(err.Error(), "too large") {
			t.Fatalf("Load oversized error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.yaml")
		link := filepath.Join(dir, "sync.yaml")
		if err := os.WriteFile(
			target, []byte("version: 1\nremotes: []\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link); err == nil ||
			!strings.Contains(err.Error(), "regular file") {
			t.Fatalf("Load symlink error = %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := Load(t.TempDir()); err == nil ||
			!strings.Contains(err.Error(), "regular file") {
			t.Fatalf("Load directory error = %v", err)
		}
	})
}

func TestSaveUpgradesLegacyConfigWithoutRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	body := []byte("version: 1\nlayout: per-org\nowner: legacy\nremotes:\n" +
		"  - mount: jasp\n    url: file:///legacy.git\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatalf("load legacy config: %v", err)
	}
	if config.Revision != 0 {
		t.Fatalf("legacy revision = %d, want 0", config.Revision)
	}
	config.Owner = "upgraded"
	if err := Save(path, config); err != nil {
		t.Fatalf("save legacy config: %v", err)
	}
	if config.Revision != 1 {
		t.Fatalf("saved revision = %d, want 1", config.Revision)
	}
	persisted, err := Load(path)
	if err != nil {
		t.Fatalf("reload upgraded config: %v", err)
	}
	if persisted.Owner != "upgraded" || persisted.Revision != 1 {
		t.Fatalf("upgraded config = %+v", persisted)
	}
}

func TestIsSharedMountFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		cfg   *Config
		mount string
		want  bool
	}{
		{"shared", &Config{Remotes: []StoreRemote{{Mount: "jasp", Shared: true}}}, "jasp", true},
		{"personal", &Config{Remotes: []StoreRemote{{Mount: "jasp"}}}, "jasp", false},
		{"root", &Config{Remotes: []StoreRemote{{Mount: DefaultStoreMount, Shared: true}}}, DefaultStoreMount, false},
		{"duplicate", &Config{Remotes: []StoreRemote{{Mount: "jasp", Shared: true}, {Mount: "jasp", Shared: true}}}, "jasp", false},
		{"nil", nil, "jasp", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsSharedMount(tc.mount); got != tc.want {
				t.Fatalf("IsSharedMount(%q) = %v, want %v", tc.mount, got, tc.want)
			}
		})
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil config")
	}
	if c.Version != 1 {
		t.Errorf("version default: got %d want 1", c.Version)
	}
	if len(c.Remotes) != 0 {
		t.Errorf("expected empty remotes, got %d", len(c.Remotes))
	}
}

func TestBuildRemoteURL(t *testing.T) {
	cases := []struct {
		name      string
		style     RemoteStyle
		owner     string
		repo      string
		want      string
		shouldErr bool
	}{
		{"ssh", RemoteSSH, "alice", "my-secrets-store", "git@github.com:alice/my-secrets-store.git", false},
		{"ssh with .git suffix stripped", RemoteSSH, "alice", "repo.git", "git@github.com:alice/repo.git", false},
		{"https", RemoteHTTPS, "bob", "jasp-secrets", "https://github.com/bob/jasp-secrets.git", false},
		{"missing owner", RemoteSSH, "", "x", "", true},
		{"missing repo", RemoteSSH, "a", "", "", true},
		{"unknown style", RemoteStyle("weird"), "a", "b", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := BuildRemoteURL(c.style, c.owner, c.repo)
			if c.shouldErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestPerOrgRepoName(t *testing.T) {
	cases := map[string]string{
		"jasp":    "jasp-secrets",
		"zuhause": "zuhause-secrets",
		" trim ":  "trim-secrets",
	}
	for in, want := range cases {
		if got := PerOrgRepoName(in); got != want {
			t.Errorf("PerOrgRepoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpdateRemoteAppendsAndReplaces(t *testing.T) {
	c := &Config{}
	c.UpdateRemote("jasp", "url-a")
	if len(c.Remotes) != 1 || c.Remotes[0].URL != "url-a" {
		t.Fatalf("append failed: %+v", c.Remotes)
	}
	c.UpdateRemote("jasp", "url-b")
	if len(c.Remotes) != 1 || c.Remotes[0].URL != "url-b" {
		t.Fatalf("replace failed: %+v", c.Remotes)
	}
	c.UpdateRemote("zuhause", "url-c")
	if len(c.Remotes) != 2 {
		t.Fatalf("second append failed: %+v", c.Remotes)
	}
}

func TestMarkSynced(t *testing.T) {
	c := &Config{Remotes: []StoreRemote{{Mount: "root"}}}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	c.MarkSynced("root", ts)
	if !c.Remotes[0].LastSync.Equal(ts) {
		t.Errorf("got %v want %v", c.Remotes[0].LastSync, ts)
	}
	// Unknown mount is a no-op (must not panic or append).
	c.MarkSynced("nope", ts)
	if len(c.Remotes) != 1 {
		t.Errorf("unknown mount mutated remotes: %+v", c.Remotes)
	}
}

func TestMarkSharedSyncedAndSaveMergesFreshConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	initial := &Config{
		Version: 1,
		Layout:  LayoutSingle,
		Owner:   "initial-owner",
		Remotes: []StoreRemote{{
			Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
		}},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	fresh, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	fresh.Owner = "concurrent-owner"
	fresh.Layout = LayoutPerOrg
	fresh.Remotes = append(fresh.Remotes, StoreRemote{
		Mount: "personal", URL: "file:///personal.git",
	})
	if err := Save(path, fresh); err != nil {
		t.Fatalf("save concurrent config: %v", err)
	}

	at := time.Date(2026, 7, 24, 10, 11, 12, 0, time.UTC)
	merged, err := MarkSharedSyncedAndSave(
		context.Background(), path, "jasp-shared", at,
	)
	if err != nil {
		t.Fatalf("MarkSharedSyncedAndSave: %v", err)
	}
	if merged.Owner != "concurrent-owner" || merged.Layout != LayoutPerOrg {
		t.Fatalf("fresh config fields were lost: %+v", merged)
	}
	if remote, ok := merged.Remote("personal"); !ok ||
		remote.URL != "file:///personal.git" {
		t.Fatalf("fresh remote was lost: %+v", merged.Remotes)
	}
	if remote, ok := merged.Remote("jasp-shared"); !ok ||
		!remote.LastSync.Equal(at) {
		t.Fatalf("LastSync = %+v, want %v", remote, at)
	}
	persisted, err := Load(path)
	if err != nil {
		t.Fatalf("reload merged config: %v", err)
	}
	if remote, ok := persisted.Remote("jasp-shared"); !ok ||
		!remote.LastSync.Equal(at) {
		t.Fatalf("persisted LastSync = %+v, want %v", remote, at)
	}
}

func TestMarkSharedSyncedAndSaveFailsWhenMountChangedToPersonal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	config := &Config{Version: 1, Remotes: []StoreRemote{{
		Mount: "jasp-shared", URL: "file:///personal.git",
	}}}
	if err := Save(path, config); err != nil {
		t.Fatalf("save config: %v", err)
	}

	_, err := MarkSharedSyncedAndSave(
		context.Background(), path, "jasp-shared", time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "no longer configured as shared") {
		t.Fatalf("error = %v, want sharing-mode refusal", err)
	}
	persisted, loadErr := Load(path)
	if loadErr != nil {
		t.Fatalf("reload config: %v", loadErr)
	}
	remote, ok := persisted.Remote("jasp-shared")
	if !ok || !remote.LastSync.IsZero() {
		t.Fatalf("personal mount was stamped: %+v", persisted.Remotes)
	}
}

func TestUpdateSharedTeamAuditAndSaveMergesFreshConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	initial := &Config{
		Version: 1,
		Layout:  LayoutSingle,
		Owner:   "initial-owner",
		Remotes: []StoreRemote{
			{
				Mount: "jasp", URL: "file:///tmp/store.git", Shared: true,
				LastSync: time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC),
			},
			{Mount: "personal", URL: "file:///tmp/personal.git"},
		},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	fresh, err := Load(path)
	if err != nil {
		t.Fatalf("load initial config: %v", err)
	}
	fresh.Owner = "concurrent-owner"
	fresh.Layout = LayoutPerOrg
	fresh.Remotes[1].URL = "file:///tmp/new-personal.git"
	if err := Save(path, fresh); err != nil {
		t.Fatalf("save concurrent config: %v", err)
	}
	beforeRevision := fresh.Revision

	updated, err := UpdateSharedTeamAuditAndSave(
		context.Background(),
		path,
		"jasp",
		TeamAuditConfig{
			URL:                "git@github.com:jasp/audit.git",
			SigningFingerprint: "0123456789abcdef0123456789abcdef01234567",
		},
	)
	if err != nil {
		t.Fatalf("UpdateSharedTeamAuditAndSave: %v", err)
	}
	if updated.Revision != beforeRevision+1 {
		t.Fatalf("revision = %d, want %d", updated.Revision, beforeRevision+1)
	}
	if updated.Owner != "concurrent-owner" || updated.Layout != LayoutPerOrg {
		t.Fatalf("fresh config fields were lost: %+v", updated)
	}
	if remote, ok := updated.Remote("personal"); !ok ||
		remote.URL != "file:///tmp/new-personal.git" {
		t.Fatalf("fresh personal remote was lost: %+v", updated.Remotes)
	}
	remote, ok := updated.Remote("jasp")
	if !ok || remote.TeamAudit == nil {
		t.Fatalf("team audit missing: %+v", updated.Remotes)
	}
	if remote.TeamAudit.SigningFingerprint !=
		"0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("fingerprint was not normalized: %+v", remote.TeamAudit)
	}
	if !remote.LastSync.Equal(initial.Remotes[0].LastSync) {
		t.Fatalf("LastSync was not preserved: %+v", remote)
	}
}

func TestUpdateSharedTeamAuditAndSaveSerializesConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	initial := &Config{Version: 1, Remotes: []StoreRemote{
		{Mount: "jasp", URL: "/tmp/jasp-store.git", Shared: true},
		{Mount: "sales", URL: "/tmp/sales-store.git", Shared: true},
	}}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, update := range []struct {
		mount string
		url   string
		fpr   string
	}{
		{"jasp", "/tmp/jasp-audit.git", strings.Repeat("A", 40)},
		{"sales", "/tmp/sales-audit.git", strings.Repeat("B", 40)},
	} {
		update := update
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := UpdateSharedTeamAuditAndSave(
				context.Background(), path, update.mount,
				TeamAuditConfig{
					URL: update.url, SigningFingerprint: update.fpr,
				},
			)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent update: %v", err)
		}
	}

	persisted, err := Load(path)
	if err != nil {
		t.Fatalf("load concurrent result: %v", err)
	}
	if persisted.Revision != initial.Revision+2 {
		t.Fatalf("revision = %d, want %d", persisted.Revision, initial.Revision+2)
	}
	for _, mount := range []string{"jasp", "sales"} {
		remote, ok := persisted.Remote(mount)
		if !ok || remote.TeamAudit == nil {
			t.Fatalf("%s audit update was lost: %+v", mount, persisted.Remotes)
		}
	}
}

func TestUpdateSharedTeamAuditAndSaveFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	initial := &Config{Version: 1, Remotes: []StoreRemote{
		{Mount: "personal", URL: "/tmp/personal.git"},
		{Mount: "jasp", URL: "/tmp/jasp-store.git", Shared: true},
	}}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	valid := TeamAuditConfig{
		URL: "/tmp/jasp-audit.git", SigningFingerprint: strings.Repeat("A", 40),
	}
	tests := []struct {
		name  string
		mount string
		audit TeamAuditConfig
	}{
		{name: "personal mount", mount: "personal", audit: valid},
		{name: "missing mount", mount: "missing", audit: valid},
		{
			name: "same repo", mount: "jasp",
			audit: TeamAuditConfig{
				URL:                "/tmp/jasp-store.git",
				SigningFingerprint: strings.Repeat("A", 40),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before, err := Load(path)
			if err != nil {
				t.Fatalf("load before update: %v", err)
			}
			if _, err := UpdateSharedTeamAuditAndSave(
				context.Background(), path, test.mount, test.audit,
			); err == nil {
				t.Fatal("expected update to fail closed")
			}
			after, err := Load(path)
			if err != nil {
				t.Fatalf("load after update: %v", err)
			}
			if after.Revision != before.Revision {
				t.Fatalf("failed update changed revision from %d to %d",
					before.Revision, after.Revision)
			}
		})
	}
}

func TestSaveRejectsOverlappingStaleWriterWithoutLosingLastSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	initial := &Config{
		Version: 1,
		Owner:   "initial-owner",
		Remotes: []StoreRemote{{
			Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
		}},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	staleWriter, err := Load(path)
	if err != nil {
		t.Fatalf("load first writer: %v", err)
	}
	at := time.Date(2026, 7, 24, 18, 19, 20, 0, time.UTC)
	if _, err := MarkSharedSyncedAndSave(
		context.Background(), path, "jasp-shared", at,
	); err != nil {
		t.Fatalf("save LastSync from second writer: %v", err)
	}

	staleWriter.Owner = "stale-owner"
	err = Save(path, staleWriter)
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("stale Save error = %v, want ErrConfigConflict", err)
	}

	persisted, err := Load(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if persisted.Owner != "initial-owner" {
		t.Fatalf("stale writer changed owner to %q", persisted.Owner)
	}
	remote, ok := persisted.Remote("jasp-shared")
	if !ok || !remote.LastSync.Equal(at) {
		t.Fatalf("LastSync lost after stale writer: %+v", remote)
	}

	persisted.Owner = "fresh-owner"
	if err := Save(path, persisted); err != nil {
		t.Fatalf("save after conflict did not release config lock: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload fresh write: %v", err)
	}
	remote, ok = reloaded.Remote("jasp-shared")
	if reloaded.Owner != "fresh-owner" || !ok || !remote.LastSync.Equal(at) {
		t.Fatalf("fresh write after conflict = %+v", reloaded)
	}
}

// Reconcile tests. The scriptedRunner covers each of the four paths
// documented on ReconcileWithRemote. We drive the control flow by the
// sequence of `gopass git ...` subcommands the function issues and
// verify the final call list matches the expected recovery strategy.

var errReconcileUnexpected = errors.New("unexpected runner call")

func runnerFor(r map[string]scriptedResult) *scriptedRunner {
	return &scriptedRunner{results: r, fallback: scriptedResult{err: errReconcileUnexpected}}
}

func keyStartsWith(calls [][]string, prefix ...string) bool {
	for _, c := range calls {
		if len(c) < len(prefix) {
			continue
		}
		ok := true
		for i := range prefix {
			if c[i] != prefix[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestReconcile_EmptyRemote(t *testing.T) {
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin": {},
		// rev-parse fails → no origin/main. gopass propagates git's
		// exit code; errUnexpected-identical error works for the
		// "branch missing" signal.
		"gopass git rev-parse --quiet --verify origin/main": {err: errors.New("no such ref")},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("empty remote path failed: %v", err)
	}
	if keyStartsWith(r.calls, "gopass", "git", "reset") {
		t.Errorf("must not reset on empty remote: %+v", r.calls)
	}
	if keyStartsWith(r.calls, "gopass", "git", "merge") {
		t.Errorf("must not merge on empty remote: %+v", r.calls)
	}
}

func TestReconcile_LocalAhead(t *testing.T) {
	// origin/main is an ancestor of HEAD — push will FF, nothing to do.
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin":                              {},
		"gopass git rev-parse --quiet --verify origin/main":    {},
		"gopass git merge-base --is-ancestor origin/main HEAD": {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("local-ahead path failed: %v", err)
	}
	if keyStartsWith(r.calls, "gopass", "git", "merge", "--ff-only") {
		t.Errorf("unexpected merge call on local-ahead path: %+v", r.calls)
	}
}

func TestReconcile_RemoteAhead_FastForward(t *testing.T) {
	// HEAD is an ancestor of origin/main — FF merge brings local up.
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin":                              {},
		"gopass git rev-parse --quiet --verify origin/main":    {},
		"gopass git merge-base --is-ancestor origin/main HEAD": {err: errors.New("not ancestor")},
		"gopass git merge-base --is-ancestor HEAD origin/main": {},
		"gopass git merge --ff-only origin/main":               {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("remote-ahead FF path failed: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "merge", "--ff-only") {
		t.Errorf("expected --ff-only merge on remote-ahead path: %+v", r.calls)
	}
}

func TestReconcile_Divergent_Pristine_Adopts(t *testing.T) {
	// Divergent + ls-files returns only fresh-init files → adopt.
	pristineFiles := []byte(".gitattributes\n.gpg-id\n.public-keys/foo.pub\n")
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin":                              {},
		"gopass git rev-parse --quiet --verify origin/main":    {},
		"gopass git merge-base --is-ancestor origin/main HEAD": {err: errors.New("diverged")},
		"gopass git merge-base --is-ancestor HEAD origin/main": {err: errors.New("diverged")},
		"gopass git ls-files":                                  {out: pristineFiles},
		"gopass git reset --hard origin/main":                  {},
		"gopass --yes recipients add ABCD":                     {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("pristine adopt path failed: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "reset", "--hard", "origin/main") {
		t.Errorf("expected reset --hard on adopt path: %+v", r.calls)
	}
	if !keyStartsWith(r.calls, "gopass", "--yes", "recipients", "add", "ABCD") {
		t.Errorf("expected recipients add on adopt path: %+v", r.calls)
	}
}

func TestReconcile_Divergent_WithContent_Merges(t *testing.T) {
	// A real secret lives in the store — we must not reset.
	contentFiles := []byte(".gitattributes\n.gpg-id\nzuhause/wifi.gpg\n")
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin":                              {},
		"gopass git rev-parse --quiet --verify origin/main":    {},
		"gopass git merge-base --is-ancestor origin/main HEAD": {err: errors.New("diverged")},
		"gopass git merge-base --is-ancestor HEAD origin/main": {err: errors.New("diverged")},
		"gopass git ls-files":                                  {out: contentFiles},
		"gopass git merge --allow-unrelated-histories --no-edit -m Merge remote store into local (mys reconcile) origin/main": {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("content merge path failed: %v", err)
	}
	if keyStartsWith(r.calls, "gopass", "git", "reset") {
		t.Errorf("must not reset when content exists: %+v", r.calls)
	}
}

func TestReconcile_PristineAdopt_NoFingerprint_SkipsRecipientsAdd(t *testing.T) {
	// Empty fingerprint: adopt still happens, but no recipient is
	// added — the caller is on its own (documented behaviour for the
	// standalone `mys sync setup` path that does not yet know the fpr).
	pristineFiles := []byte(".gitattributes\n.gpg-id\n")
	r := runnerFor(map[string]scriptedResult{
		"gopass git fetch origin":                              {},
		"gopass git rev-parse --quiet --verify origin/main":    {},
		"gopass git merge-base --is-ancestor origin/main HEAD": {err: errors.New("diverged")},
		"gopass git merge-base --is-ancestor HEAD origin/main": {err: errors.New("diverged")},
		"gopass git ls-files":                                  {out: pristineFiles},
		"gopass git reset --hard origin/main":                  {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", ""); err != nil {
		t.Fatalf("pristine adopt without fpr failed: %v", err)
	}
	if keyStartsWith(r.calls, "gopass", "--yes", "recipients", "add") {
		t.Errorf("must not call recipients add without fingerprint: %+v", r.calls)
	}
}

func TestIsMountPristine(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"empty", "", true},
		{"fresh init", ".gitattributes\n.gpg-id\n.public-keys/abc.pub\n", true},
		{"with a gpg file", ".gpg-id\nzuhause/wifi.gpg\n", false},
		{"unknown top-level file", ".gpg-id\nREADME.md\n", false},
		{"extra top-level dir", ".gpg-id\nmisc/\n", false},
		{"whitespace only", "   \n\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runnerFor(map[string]scriptedResult{
				"gopass git ls-files": {out: []byte(tc.output)},
			})
			got, err := isMountPristine(context.Background(), r, "root")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGopassGitPull_ExplicitOriginBranch covers the missing-upstream bug:
// a bare `git pull` fails when the current branch has no tracking info,
// so GopassGitPull must resolve the branch and pull explicitly from
// `origin <branch>`.
// Uses a non-default mount ("work") so the `--store work` forwarding
// path is actually exercised: with mount == DefaultStoreMount the flag
// is omitted and the test would pass incidentally.
func TestGopassGitPull_ExplicitOriginBranch(t *testing.T) {
	// rev-parse output includes the real gopass „⚠ Running '...' in
	// <path>..." banner that gopass prefixes onto git subcommand
	// stdout. currentGitBranch must strip it; otherwise the banner
	// leaks into the refspec (regression seen in production after #51).
	r := runnerFor(map[string]scriptedResult{
		"gopass git --store work rev-parse --abbrev-ref HEAD": {out: []byte("⚠ Running 'git rev-parse --abbrev-ref HEAD' in /home/sascha/.local/share/gopass/stores/work...\nfeature/x\n")},
		"gopass git --store work pull origin feature/x":       {out: []byte("Already up to date.\n")},
	})
	if _, err := GopassGitPull(context.Background(), r, "work"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "--store", "work", "pull", "origin", "feature/x") {
		t.Fatalf("expected explicit `gopass git --store work pull origin feature/x`, got calls: %v", r.calls)
	}
	if keyStartsWith(r.calls, "gopass", "git", "--store", "work", "pull") &&
		!keyStartsWith(r.calls, "gopass", "git", "--store", "work", "pull", "origin") {
		t.Errorf("must not issue a bare `git pull` when the branch is known")
	}
}

// TestGopassGitPull_DetachedHeadError ensures a detached HEAD yields a
// descriptive error instead of a bare `git pull` (which would reproduce
// the very „exit status 1" this function exists to eliminate).
func TestGopassGitPull_DetachedHeadError(t *testing.T) {
	r := runnerFor(map[string]scriptedResult{
		"gopass git rev-parse --abbrev-ref HEAD": {out: []byte("HEAD\n")},
	})
	_, err := GopassGitPull(context.Background(), r, "root")
	if err == nil {
		t.Fatalf("expected an error on detached HEAD, got nil")
	}
	if !strings.Contains(err.Error(), "detached HEAD") {
		t.Errorf("error should mention detached HEAD, got: %v", err)
	}
	for _, c := range r.calls {
		if len(c) >= 4 && c[2] == "git" && c[3] == "pull" {
			t.Errorf("must not issue any `git pull` on detached HEAD: %v", c)
		}
	}
}

func TestGopassRecipientMutationArgs(t *testing.T) {
	tests := []struct {
		name  string
		mount string
		call  func(context.Context, Runner, string, string) ([]byte, error)
		want  string
	}{
		{"add default empty", "", GopassRecipientsAdd, "gopass recipients add ABCD"},
		{"add default root", DefaultStoreMount, GopassRecipientsAdd, "gopass recipients add ABCD"},
		{"add shared", "jasp", GopassRecipientsAdd, "gopass recipients add --store jasp ABCD"},
		{"remove default", DefaultStoreMount, GopassRecipientsRemove, "gopass recipients remove ABCD"},
		{"remove shared", "jasp", GopassRecipientsRemove, "gopass recipients remove --store jasp ABCD"},
		{"confirmed add shared", "jasp", GopassRecipientsAddConfirmed, "gopass --yes recipients add --store jasp ABCD"},
		{"confirmed remove shared", "jasp", GopassRecipientsRemoveConfirmed, "gopass --yes recipients remove --store jasp ABCD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &scriptedRunner{}
			if _, err := tc.call(context.Background(), r, tc.mount, "ABCD"); err != nil {
				t.Fatalf("mutation: %v", err)
			}
			if len(r.calls) != 1 || strings.Join(r.calls[0], " ") != tc.want {
				t.Fatalf("calls = %v, want %q", r.calls, tc.want)
			}
		})
	}
}

func TestGopassMountPath(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name  string
		mount string
		key   string
	}{
		{"root empty", "", "gopass config mounts.path"},
		{"root explicit", DefaultStoreMount, "gopass config mounts.path"},
		{"shared", "jasp", "gopass config mounts.jasp.path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runnerFor(map[string]scriptedResult{
				tc.key: {out: []byte(dir + "\n")},
			})
			got, err := GopassMountPath(context.Background(), r, tc.mount)
			if err != nil {
				t.Fatalf("GopassMountPath: %v", err)
			}
			want, err := filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("path = %q, want %q", got, want)
			}
		})
	}
}

func TestGopassMountPathRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "mount-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	r := runnerFor(map[string]scriptedResult{
		"gopass config mounts.jasp.path": {out: []byte(link)},
	})
	_, err := GopassMountPath(context.Background(), r, "jasp")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v, want symlink rejection", err)
	}
}
