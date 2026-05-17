package sync

import (
	"context"
	"errors"
	"path/filepath"
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
			{Mount: "jasp", URL: "git@github.com:alice/jasp-secrets.git", LastSync: now},
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
		"gopass git fetch origin":                                      {},
		"gopass git rev-parse --quiet --verify origin/main":            {},
		"gopass git merge-base --is-ancestor origin/main HEAD":         {},
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
		"gopass recipients add ABCD":                           {},
	})
	if err := ReconcileWithRemote(context.Background(), r, "root", "ABCD"); err != nil {
		t.Fatalf("pristine adopt path failed: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "reset", "--hard", "origin/main") {
		t.Errorf("expected reset --hard on adopt path: %+v", r.calls)
	}
	if !keyStartsWith(r.calls, "gopass", "recipients", "add", "ABCD") {
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
	if keyStartsWith(r.calls, "gopass", "recipients", "add") {
		t.Errorf("must not call recipients add without fingerprint: %+v", r.calls)
	}
}

func TestIsMountPristine(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		want    bool
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
func TestGopassGitPull_ExplicitOriginBranch(t *testing.T) {
	r := runnerFor(map[string]scriptedResult{
		"gopass git rev-parse --abbrev-ref HEAD": {out: []byte("main\n")},
		"gopass git pull origin main":            {out: []byte("Already up to date.\n")},
	})
	if _, err := GopassGitPull(context.Background(), r, "root"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "pull", "origin", "main") {
		t.Fatalf("expected explicit `gopass git pull origin main`, got calls: %v", r.calls)
	}
	if keyStartsWith(r.calls, "gopass", "git", "pull") &&
		!keyStartsWith(r.calls, "gopass", "git", "pull", "origin") {
		t.Errorf("must not issue a bare `git pull` when the branch is known")
	}
}

// TestGopassGitPull_DetachedHeadFallback ensures we fall back to the
// historical bare-pull behaviour rather than guessing a branch name
// when HEAD is detached.
func TestGopassGitPull_DetachedHeadFallback(t *testing.T) {
	r := runnerFor(map[string]scriptedResult{
		"gopass git rev-parse --abbrev-ref HEAD": {out: []byte("HEAD\n")},
		"gopass git pull":                        {out: []byte("ok")},
	})
	if _, err := GopassGitPull(context.Background(), r, "root"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !keyStartsWith(r.calls, "gopass", "git", "pull") {
		t.Fatalf("expected fallback `gopass git pull`, got calls: %v", r.calls)
	}
	for _, c := range r.calls {
		if len(c) >= 5 && c[2] == "git" && c[3] == "pull" && c[4] == "origin" {
			t.Errorf("must not guess origin/<branch> on detached HEAD: %v", c)
		}
	}
}
