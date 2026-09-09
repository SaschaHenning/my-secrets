package web

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// storePollInterval is how often the watcher stats the store directory —
// far below entriesCacheTTL, since the point is that a `mys add` shows up
// in seconds. One poll is a stat walk: no decrypt, no GPG, no git.
const storePollInterval = 2 * time.Second

// storeDebounce is how long the store must sit still before a change is
// acted on. One `mys add` is several filesystem events and `mys sync
// pull` rewrites many files in a row; one quiet interval turns that
// burst into a single decrypt.
const storeDebounce = 1 * time.Second

// fileStamp is the change signal for one encrypted secret. Content is
// never read: a re-encrypt always moves mtime or size, and anything that
// evades both is still caught by the entriesCacheTTL safety net.
type fileStamp struct {
	modNano int64
	size    int64
}

// storeFingerprint maps a secret path (store-relative, no .gpg suffix) to
// its stamp.
type storeFingerprint map[string]fileStamp

// storeChange is what one or more poll rounds observed: paths that are
// new or rewritten, and paths that are gone.
type storeChange struct {
	Changed []string
	Removed []string
}

func (c storeChange) empty() bool {
	return len(c.Changed) == 0 && len(c.Removed) == 0
}

// merge folds a newer diff into a still-pending one so a write burst
// collapses into one update. The newer observation wins: a path removed
// after it was changed must not stay queued for a decrypt that then
// fails the whole batch.
func (c storeChange) merge(next storeChange) storeChange {
	changed := pathSet(c.Changed)
	removed := pathSet(c.Removed)
	for _, p := range next.Changed {
		delete(removed, p)
		changed[p] = struct{}{}
	}
	for _, p := range next.Removed {
		delete(changed, p)
		removed[p] = struct{}{}
	}
	return storeChange{Changed: sortedPaths(changed), Removed: sortedPaths(removed)}
}

func pathSet(paths []string) map[string]struct{} {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	return set
}

func sortedPaths(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// fingerprintStore stats every *.gpg file under root and returns one
// stamp per secret path. Any walk error aborts the whole fingerprint: a
// partial one would diff as "half the store was deleted" and evict live
// entries from the cache, while skipping the round costs nothing.
func fingerprintStore(root string) (storeFingerprint, error) {
	// WalkDir does not follow symlinks, so a symlinked store root would
	// walk as one non-directory entry: zero .gpg files, i.e. "the whole
	// store just disappeared".
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	fingerprint := make(storeFingerprint)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			// .git churns on every gopass commit and holds no secrets;
			// walking it would make every commit look like a store change.
			if path != root && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".gpg") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		secretPath := filepath.ToSlash(strings.TrimSuffix(relative, ".gpg"))
		fingerprint[secretPath] = fileStamp{
			modNano: info.ModTime().UnixNano(),
			size:    info.Size(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fingerprint, nil
}

func diffFingerprints(before, after storeFingerprint) storeChange {
	var change storeChange
	for path, stamp := range after {
		if old, ok := before[path]; !ok || old != stamp {
			change.Changed = append(change.Changed, path)
		}
	}
	for path := range before {
		if _, ok := after[path]; !ok {
			change.Removed = append(change.Removed, path)
		}
	}
	sort.Strings(change.Changed)
	sort.Strings(change.Removed)
	return change
}

// storeRetryCap is the ceiling for the retry delay after a failed apply.
// Every failure costs an audit error row, so a change that cannot be
// applied at all must not hammer the log once a second forever.
const storeRetryCap = 60 * time.Second

// storeWatcher polls a gopass store directory and hands coalesced changes
// to apply.
type storeWatcher struct {
	root     string
	poll     time.Duration
	debounce time.Duration
	retryCap time.Duration
	// apply reports false when the change could not be taken yet. The
	// watcher keeps it pending and retries, so a write landing during a
	// refresh is never silently dropped.
	apply func(storeChange) bool
}

// pollState is the watcher loop's state, split out so a single round can
// be driven from a test without timing. backoff doubles per failed apply
// and resets once one succeeds.
type pollState struct {
	last    storeFingerprint
	pending storeChange
	backoff time.Duration
}

// run polls until ctx is cancelled. The first successful fingerprint is
// only a baseline — a store that exists at startup must not look like one
// where every entry was just added.
func (w *storeWatcher) run(ctx context.Context) {
	var state pollState
	timer := time.NewTimer(w.poll)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(w.step(&state))
	}
}

// step runs one poll round and returns how long to wait before the next:
// the debounce window while a change is settling, the current backoff
// while an apply keeps failing, the poll interval otherwise.
func (w *storeWatcher) step(state *pollState) time.Duration {
	current, err := fingerprintStore(w.root)
	if err != nil {
		return w.poll
	}
	if state.last == nil {
		state.last = current
		return w.poll
	}
	if change := diffFingerprints(state.last, current); !change.empty() {
		state.pending = state.pending.merge(change)
		state.last = current
		return w.debounce // let the rest of the write burst land first
	}
	if state.pending.empty() {
		return w.poll
	}
	if !w.apply(state.pending) {
		state.backoff = w.nextBackoff(state.backoff)
		return state.backoff
	}
	state.pending = storeChange{}
	state.backoff = 0
	return w.poll
}

// nextBackoff doubles the retry delay from one debounce window to retryCap.
func (w *storeWatcher) nextBackoff(current time.Duration) time.Duration {
	ceiling := w.retryCap
	if ceiling <= 0 {
		ceiling = storeRetryCap
	}
	next := current * 2
	if current <= 0 {
		next = w.debounce
	}
	if next > ceiling {
		return ceiling
	}
	return next
}
