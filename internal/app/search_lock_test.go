package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// Regression for #124: a search that decrypts the whole store must not hold
// the cross-process lock against get. Both apps use the real lock anchor;
// separate App instances stand in for separate mys processes (flock locks
// per open file description, so the kernel treats them independently).
func TestGetCompletesWhileSearchDecrypts(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	entries := make([]*store.Entry, 0, 20)
	for index := 0; index < 20; index++ {
		entries = append(entries, &store.Entry{
			Path: fmt.Sprintf("jasp/service-%02d", index),
			URL:  "https://example.test",
		})
	}
	searchApp, searchStore, _, _ := gatedApp(t, aiActor(), entries...)
	getApp, _, _, _ := gatedApp(t, aiActor(), entries...)
	for _, candidate := range []*App{searchApp, getApp} {
		candidate.teamReads.acquireAnchor = lockanchor.AcquireContext
		candidate.teamReads.acquireReadAnchor = lockanchor.AcquireSharedContext
	}
	// 20 metadata decrypts at 500 ms keep the search busy for ~10 s.
	searchStore.GetDelay = 500 * time.Millisecond

	searchCtx, cancelSearch := context.WithCancel(context.Background())
	defer cancelSearch()
	searchDone := make(chan error, 1)
	go func() {
		_, err := searchApp.Search(searchCtx, "no-path-matches-this")
		searchDone <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for searchStore.GetCallCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("search never started decrypting")
		}
		time.Sleep(10 * time.Millisecond)
	}

	getCtx, cancelGet := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelGet()
	entry, err := getApp.Get(getCtx, "jasp/service-03")
	if err != nil {
		t.Fatalf("get while search runs: %v", err)
	}
	if entry.Path != "jasp/service-03" {
		t.Fatalf("get returned %q", entry.Path)
	}
	select {
	case err := <-searchDone:
		t.Fatalf("search finished before get, test proves nothing: %v", err)
	default:
	}
	cancelSearch()
	select {
	case <-searchDone:
	case <-time.After(5 * time.Second):
		t.Fatal("search ignored cancellation")
	}
}

func TestLockTimeoutHidesHolderDetailsFromAI(t *testing.T) {
	timeout := func(context.Context) (context.Context, func() error, error) {
		return nil, nil, fmt.Errorf("%w after 2m0s (held by PID 4242)", lockanchor.ErrWaitTimeout)
	}
	aiApp, _, _, _ := gatedApp(t, aiActor(), &store.Entry{Path: "jasp/a"})
	aiApp.teamReads.acquireReadAnchor = timeout
	_, err := aiApp.Get(context.Background(), "jasp/a")
	if !errors.Is(err, ErrAccessLockBusy) || strings.Contains(err.Error(), "4242") {
		t.Fatalf("AI lock timeout error = %v, want ErrAccessLockBusy without PID", err)
	}

	humanApp, _, _, _ := gatedApp(t, caller.Detail{Kind: caller.KindHuman}, &store.Entry{Path: "jasp/a"})
	humanApp.teamReads.acquireReadAnchor = timeout
	_, err = humanApp.Get(context.Background(), "jasp/a")
	if !errors.Is(err, lockanchor.ErrWaitTimeout) || !strings.Contains(err.Error(), "PID 4242") {
		t.Fatalf("human lock timeout error = %v, want holder PID", err)
	}
}
