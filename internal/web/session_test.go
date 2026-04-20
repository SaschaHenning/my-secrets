package web

import (
	"sync"
	"testing"
	"time"
)

func TestSessionIssueAndValidate(t *testing.T) {
	s := newSessionStore(time.Minute)
	id := s.Issue()
	if len(id) != 64 {
		t.Fatalf("expected 64-char hex id, got len=%d", len(id))
	}
	if !s.Validate(id) {
		t.Fatal("fresh session should validate")
	}
	if s.Validate("") {
		t.Fatal("empty id must not validate")
	}
	if s.Validate("not-a-real-id") {
		t.Fatal("unknown id must not validate")
	}
}

func TestSessionIssueReturnsUniqueIDs(t *testing.T) {
	s := newSessionStore(time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		id := s.Issue()
		if seen[id] {
			t.Fatalf("duplicate session id %s", id)
		}
		seen[id] = true
	}
}

func TestSessionValidateBumpsLastSeen(t *testing.T) {
	s := newSessionStore(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	now := base
	s.now = func() time.Time { return now }

	id := s.Issue()
	now = base.Add(30 * time.Second)
	if !s.Validate(id) {
		t.Fatal("session should still be valid after 30s with 60s ttl")
	}
	// lastSeen is now base+30s. Push now forward by 45s → still within
	// ttl because lastSeen was bumped.
	now = base.Add(75 * time.Second)
	if !s.Validate(id) {
		t.Fatal("session should survive when activity keeps bumping lastSeen")
	}
}

func TestSessionExpiryRemovesEntry(t *testing.T) {
	s := newSessionStore(50 * time.Millisecond)
	id := s.Issue()

	time.Sleep(80 * time.Millisecond)
	if s.Validate(id) {
		t.Fatal("session should have expired")
	}
	if len(s.sessions) != 0 {
		t.Fatalf("expired session should be dropped, got %d", len(s.sessions))
	}
}

func TestSessionSweepDropsExpired(t *testing.T) {
	s := newSessionStore(20 * time.Millisecond)
	_ = s.Issue()
	_ = s.Issue()

	time.Sleep(50 * time.Millisecond)
	n := s.Sweep()
	if n != 2 {
		t.Fatalf("expected sweep to drop 2 sessions, dropped %d", n)
	}
}

// TestIdleWatcherFiresAfterTTL verifies the core idle-shutdown contract:
// once a session has been issued and the store has been silent for
// longer than ttl, idleCh closes.
func TestIdleWatcherFiresAfterTTL(t *testing.T) {
	s := newSessionStore(50 * time.Millisecond)
	_ = s.Issue()

	stop := make(chan struct{})
	defer close(stop)
	go s.runWatcher(stop, 10*time.Millisecond)

	select {
	case <-s.IdleC():
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("idle channel should have closed")
	}
}

// TestIdleWatcherSilentWithoutSessions verifies the "no session ever
// issued" guard. A fresh store must wait for the first login before
// considering auto-shutdown.
func TestIdleWatcherSilentWithoutSessions(t *testing.T) {
	s := newSessionStore(20 * time.Millisecond)

	stop := make(chan struct{})
	defer close(stop)
	go s.runWatcher(stop, 5*time.Millisecond)

	select {
	case <-s.IdleC():
		t.Fatal("idle channel must not fire when no session was ever issued")
	case <-time.After(100 * time.Millisecond):
		// expected
	}
}

// TestIdleWatcherResetByActivity verifies that ongoing activity keeps
// the watcher quiet.
func TestIdleWatcherResetByActivity(t *testing.T) {
	s := newSessionStore(60 * time.Millisecond)
	id := s.Issue()

	stop := make(chan struct{})
	defer close(stop)
	go s.runWatcher(stop, 10*time.Millisecond)

	// Hammer Validate for 150ms. With ttl=60ms the watcher must stay
	// quiet because lastSeen keeps getting bumped.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(150 * time.Millisecond)
		for time.Now().Before(deadline) {
			_ = s.Validate(id)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	select {
	case <-s.IdleC():
		t.Fatal("idle channel must not fire while session stays active")
	case <-time.After(120 * time.Millisecond):
		// expected — still within the activity window
	}
	wg.Wait()
}
