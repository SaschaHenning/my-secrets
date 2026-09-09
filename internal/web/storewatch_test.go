package web

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// writeSecretFile creates <root>/<path>.gpg with the given contents,
// standing in for a gopass-encrypted secret. Only its mtime and size ever
// matter to the watcher.
func writeSecretFile(t *testing.T, root, path, contents string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path)+".gpg")
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeSecretFile(t *testing.T, root, path string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(path)+".gpg")); err != nil {
		t.Fatal(err)
	}
}

func fingerprintOrFail(t *testing.T, root string) storeFingerprint {
	t.Helper()
	fp, err := fingerprintStore(root)
	if err != nil {
		t.Fatalf("fingerprintStore(%q): %v", root, err)
	}
	return fp
}

// TestFingerprintStore_OnlyEncryptedSecrets: the fingerprint is keyed by
// secret path (no .gpg suffix, slash-separated) and ignores everything
// that is not an encrypted secret — above all .git, which gopass rewrites
// on every single commit and which would otherwise make every write look
// like a store change forever.
func TestFingerprintStore_OnlyEncryptedSecrets(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, root, "jasp/github", "a")
	writeSecretFile(t, root, "zuhause/router", "b")
	if err := os.WriteFile(filepath.Join(root, ".gpg-id"), []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSecretFile(t, root, ".git/objects/deadbeef", "commit")

	got := fingerprintOrFail(t, root)
	want := []string{"jasp/github", "zuhause/router"}
	if len(got) != len(want) {
		t.Fatalf("fingerprint = %v, want exactly %v", got, want)
	}
	for _, p := range want {
		if _, ok := got[p]; !ok {
			t.Errorf("fingerprint missing %q: %v", p, got)
		}
	}
}

// TestDiffFingerprints_AddChangeRemove covers all three signals the
// incremental update depends on. A rewrite is detected by size here and
// by mtime in the watcher test below — either alone is enough.
func TestDiffFingerprints_AddChangeRemove(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, root, "jasp/github", "a")
	writeSecretFile(t, root, "jasp/aws", "b")
	before := fingerprintOrFail(t, root)

	writeSecretFile(t, root, "jasp/new", "c")
	writeSecretFile(t, root, "jasp/github", "aa")
	removeSecretFile(t, root, "jasp/aws")

	change := diffFingerprints(before, fingerprintOrFail(t, root))
	if want := []string{"jasp/github", "jasp/new"}; !reflect.DeepEqual(change.Changed, want) {
		t.Errorf("Changed = %v, want %v", change.Changed, want)
	}
	if want := []string{"jasp/aws"}; !reflect.DeepEqual(change.Removed, want) {
		t.Errorf("Removed = %v, want %v", change.Removed, want)
	}

	unchanged := fingerprintOrFail(t, root)
	if got := diffFingerprints(unchanged, unchanged); !got.empty() {
		t.Errorf("a store that did not change must diff empty, got %+v", got)
	}
}

// TestStoreChange_MergeLetsTheNewerObservationWin: within one burst a
// path can be written and then deleted (or the reverse). The queued
// change must end up in exactly one of the two lists — a path queued for
// decryption that no longer exists would fail the whole batch.
func TestStoreChange_MergeLetsTheNewerObservationWin(t *testing.T) {
	pending := storeChange{Changed: []string{"jasp/a", "jasp/b"}, Removed: []string{"jasp/gone"}}
	merged := pending.merge(storeChange{Changed: []string{"jasp/gone"}, Removed: []string{"jasp/a"}})

	if want := []string{"jasp/b", "jasp/gone"}; !reflect.DeepEqual(merged.Changed, want) {
		t.Errorf("Changed = %v, want %v", merged.Changed, want)
	}
	if want := []string{"jasp/a"}; !reflect.DeepEqual(merged.Removed, want) {
		t.Errorf("Removed = %v, want %v", merged.Removed, want)
	}
}

// recordingApply captures what a watcher hands over.
type recordingApply struct {
	mu      sync.Mutex
	calls   []storeChange
	failNow bool
}

func (r *recordingApply) apply(change storeChange) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, change)
	return !r.failNow
}

func (r *recordingApply) snapshot() []storeChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]storeChange(nil), r.calls...)
}

// TestStoreWatcher_CoalescesBurstAndIgnoresBaseline: a store that already
// has entries at startup must not report them as changes, and a burst of
// writes (one `mys add` is several file operations) must arrive as ONE
// coalesced change, not one per file.
func TestStoreWatcher_CoalescesBurstAndIgnoresBaseline(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, root, "jasp/existing", "a")

	recorder := &recordingApply{}
	watcher := &storeWatcher{
		root:     root,
		poll:     10 * time.Millisecond,
		debounce: 30 * time.Millisecond,
		apply:    recorder.apply,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.run(ctx)

	// Let the baseline settle, then assert it produced nothing.
	time.Sleep(100 * time.Millisecond)
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("pre-existing entries must not count as a change, got %+v", calls)
	}

	// A burst: what one `mys add` plus its git commit looks like on disk.
	writeSecretFile(t, root, "jasp/one", "1")
	writeSecretFile(t, root, "jasp/two", "2")
	writeSecretFile(t, root, "jasp/existing", "rewritten")

	waitFor(t, "watcher to report the burst", func() bool {
		return len(recorder.snapshot()) > 0
	})
	// Nothing more may follow once the store is quiet again.
	time.Sleep(100 * time.Millisecond)

	calls := recorder.snapshot()
	if len(calls) != 1 {
		t.Fatalf("burst must coalesce into 1 change, got %d: %+v", len(calls), calls)
	}
	want := []string{"jasp/existing", "jasp/one", "jasp/two"}
	if !reflect.DeepEqual(calls[0].Changed, want) {
		t.Errorf("Changed = %v, want %v", calls[0].Changed, want)
	}
	if len(calls[0].Removed) != 0 {
		t.Errorf("Removed = %v, want none", calls[0].Removed)
	}
}

// TestStoreWatcher_RetriesWhenApplyFails: a change that cannot be applied
// yet (cache busy, decrypt failed) must stay pending and be retried, not
// be dropped — otherwise a write landing during a refresh would only
// surface at the next TTL expiry, which is the bug this whole watcher
// exists to fix.
func TestStoreWatcher_RetriesWhenApplyFails(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, root, "jasp/existing", "a")

	recorder := &recordingApply{failNow: true}
	watcher := &storeWatcher{
		root:     root,
		poll:     10 * time.Millisecond,
		debounce: 10 * time.Millisecond,
		retryCap: 20 * time.Millisecond,
		apply:    recorder.apply,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.run(ctx)

	time.Sleep(50 * time.Millisecond)
	writeSecretFile(t, root, "jasp/new", "1")

	waitFor(t, "watcher to retry a failed apply", func() bool {
		return len(recorder.snapshot()) >= 2
	})
	for i, call := range recorder.snapshot() {
		if want := []string{"jasp/new"}; !reflect.DeepEqual(call.Changed, want) {
			t.Fatalf("retry %d: Changed = %v, want %v", i, call.Changed, want)
		}
	}

	recorder.mu.Lock()
	recorder.failNow = false
	recorder.mu.Unlock()

	// Once it succeeds the change is consumed: the call count stops rising.
	waitFor(t, "apply to stop being retried", func() bool {
		before := len(recorder.snapshot())
		time.Sleep(60 * time.Millisecond)
		return len(recorder.snapshot()) == before
	})
}

// TestStoreWatcher_BacksOffWhileApplyFails: a change that cannot be
// applied must not be retried once per debounce window forever — every
// failed attempt writes an audit error row. The delay doubles up to the
// cap and drops back to normal polling as soon as one attempt succeeds.
// Driven step by step so the assertions are on the returned delays, not
// on wall-clock timing.
func TestStoreWatcher_BacksOffWhileApplyFails(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, root, "jasp/existing", "a")

	recorder := &recordingApply{failNow: true}
	watcher := &storeWatcher{
		root:     root,
		poll:     5 * time.Second,
		debounce: 100 * time.Millisecond,
		retryCap: 400 * time.Millisecond,
		apply:    recorder.apply,
	}

	state := &pollState{}
	if got := watcher.step(state); got != watcher.poll {
		t.Fatalf("baseline round = %v, want the poll interval %v", got, watcher.poll)
	}
	writeSecretFile(t, root, "jasp/new", "1")
	if got := watcher.step(state); got != watcher.debounce {
		t.Fatalf("round that saw the change = %v, want the debounce %v", got, watcher.debounce)
	}

	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond, // capped
	}
	for i, wantDelay := range want {
		if got := watcher.step(state); got != wantDelay {
			t.Errorf("retry %d delay = %v, want %v", i+1, got, wantDelay)
		}
	}

	recorder.mu.Lock()
	recorder.failNow = false
	recorder.mu.Unlock()

	if got := watcher.step(state); got != watcher.poll {
		t.Errorf("after a successful apply = %v, want the poll interval %v", got, watcher.poll)
	}
	if !state.pending.empty() {
		t.Errorf("a successful apply must consume the change, still pending: %+v", state.pending)
	}
	if state.backoff != 0 {
		t.Errorf("backoff = %v after success, want reset to 0", state.backoff)
	}
}

// TestEntriesCache_ApplyChangeMergesIncrementally is the payoff test:
// after a store change the cache reflects the new set while decrypting
// ONLY the changed path, and the incremental refresh costs exactly one
// aggregated list_detail row — never a per-path `get` row, which would
// corrupt the "last read" column on the entries page.
func TestEntriesCache_ApplyChangeMergesIncrementally(t *testing.T) {
	a, f := cacheTestApp(t,
		&store.Entry{Path: "jasp/a", Org: "jasp"},
		&store.Entry{Path: "jasp/b", Org: "jasp"},
		&store.Entry{Path: "zuhause/router", Org: "zuhause"},
	)
	cache := newEntriesCache()
	if got, _ := cache.get(context.Background(), a); len(got) != 3 {
		t.Fatalf("initial load: want 3 entries, got %d", len(got))
	}
	decryptsAfterLoad := f.GetCallCount()

	// Out-of-band: one entry added, one removed.
	if err := f.Set(context.Background(), &store.Entry{Path: "jasp/new", Org: "jasp", Username: "fresh"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(context.Background(), "jasp/b"); err != nil {
		t.Fatal(err)
	}
	change := storeChange{Changed: []string{"jasp/new"}, Removed: []string{"jasp/b"}}
	if !cache.applyChange(context.Background(), a, change) {
		t.Fatal("applyChange reported not-applied on an idle, warm cache")
	}

	got, err := cache.get(context.Background(), a)
	if err != nil {
		t.Fatalf("get after merge: %v", err)
	}
	paths := make([]string, 0, len(got))
	for _, e := range got {
		paths = append(paths, e.Path)
	}
	if want := []string{"jasp/a", "jasp/new", "zuhause/router"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("merged cache = %v, want %v (sorted, like a full load)", paths, want)
	}
	for _, e := range got {
		if e.Path == "jasp/new" && e.Username != "fresh" {
			t.Errorf("merged entry carries stale metadata: %+v", e)
		}
	}

	if decrypts := f.GetCallCount() - decryptsAfterLoad; decrypts != 1 {
		t.Errorf("incremental update decrypted %d entries, want exactly 1 (the changed path)", decrypts)
	}

	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionListDetail, Limit: 10})
	if len(rows) != 2 {
		t.Errorf("want 2 list_detail rows (initial load + incremental), got %d", len(rows))
	}
	gets, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 10})
	if len(gets) != 0 {
		t.Errorf("a background refresh must never write `get` rows, got %d", len(gets))
	}
}

// TestServeWith_WaitsForBackgroundDecrypt guards the shutdown race: the
// warm and watcher goroutines read the store and write audit rows, and
// cmd/mys closes both the moment Serve returns. serveWith must cancel
// them and wait for them to finish, never return mid-decrypt.
func TestServeWith_WaitsForBackgroundDecrypt(t *testing.T) {
	// Point the watcher at an empty temp store: no `gopass config`
	// subprocess, and no polling of the developer's real store.
	t.Setenv("PASSWORD_STORE_DIR", t.TempDir())
	a, f := newFakeApp(t, "human", sampleWebEntries()...)
	f.GetDelay = 150 * time.Millisecond // 4 fixtures ≈ 600ms of warm

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, a, port, &stdout, time.Minute, time.Second) }()

	time.Sleep(200 * time.Millisecond) // warm is now mid-decrypt
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveWith: %v", err)
	}

	// Any further Store.Get after the return would, in production, hit a
	// store App.Close has already shut down.
	settled := f.GetCallCount()
	time.Sleep(300 * time.Millisecond)
	if got := f.GetCallCount(); got != settled {
		t.Errorf("store still being read after serveWith returned: %d → %d Get calls", settled, got)
	}
}

// TestEntriesCache_ApplyChangeSkipsWhileRefreshing: the incremental merge
// must never run alongside a full refresh — its result would be
// overwritten by the in-flight full load anyway. It reports false so the
// watcher retries instead of dropping the change.
func TestEntriesCache_ApplyChangeSkipsWhileRefreshing(t *testing.T) {
	a, f := cacheTestApp(t, &store.Entry{Path: "jasp/a", Org: "jasp"})
	cache := newEntriesCache()
	if _, err := cache.get(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	decryptsBefore := f.GetCallCount()

	cache.mu.Lock()
	cache.refreshing = true
	cache.mu.Unlock()

	if cache.applyChange(context.Background(), a, storeChange{Changed: []string{"jasp/a"}}) {
		t.Error("applyChange must report false while a refresh is in flight")
	}
	if f.GetCallCount() != decryptsBefore {
		t.Error("applyChange decrypted despite an in-flight refresh")
	}
}

// TestEntriesCache_ApplyChangeOnColdCache: with no cached set and no load
// running there is nothing to merge into, and the next load reads the
// store as it is now — so the change is consumed rather than retried
// forever, and nothing is decrypted.
func TestEntriesCache_ApplyChangeOnColdCache(t *testing.T) {
	a, f := cacheTestApp(t, &store.Entry{Path: "jasp/a", Org: "jasp"})
	cache := newEntriesCache()

	if !cache.applyChange(context.Background(), a, storeChange{Changed: []string{"jasp/a"}}) {
		t.Error("a cold, idle cache should consume the change, not queue it")
	}
	if f.GetCallCount() != 0 {
		t.Errorf("cold cache must not decrypt, got %d Get calls", f.GetCallCount())
	}
}
