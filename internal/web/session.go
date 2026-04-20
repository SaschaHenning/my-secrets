package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// session represents a single authenticated browser session.
//
// A session is bound to a random 32-byte ID stored in the client as an
// HttpOnly cookie. issuedAt never changes; lastSeen is bumped every time
// the middleware sees a valid request for this session. The idle watcher
// compares the most-recent lastSeen across all sessions against ttl to
// decide when the server should shut itself down.
type session struct {
	id       string
	issuedAt time.Time
	lastSeen time.Time
}

// sessionStore is the in-memory registry of active sessions. All access
// must go through the mutex. Sessions that exceed ttl are removed by
// Sweep(); the idle watcher goroutine calls Sweep periodically and also
// emits the single idle signal on idleCh once the store falls quiet.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
	ttl      time.Duration

	// ever is true once Issue() has been called at least once. Until
	// then the idle watcher stays silent — a freshly started server
	// should wait for the first login, not auto-shutdown.
	ever bool

	// idleCh is closed exactly once when the store has gone idle
	// beyond ttl. Callers select on this channel to trigger graceful
	// shutdown of the HTTP server.
	idleCh   chan struct{}
	idleOnce sync.Once

	// now lets tests replace time.Now for deterministic timing.
	now func() time.Time
}

// newSessionStore constructs a store with the given ttl. Callers are
// expected to Start() the idle watcher after construction.
func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*session),
		ttl:      ttl,
		idleCh:   make(chan struct{}),
		now:      time.Now,
	}
}

// Issue creates a new session and returns its ID. The ID is a 32-byte
// cryptographically random value encoded as lowercase hex.
func (s *sessionStore) Issue() string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand should never fail on a sane system; if it does,
		// refuse to issue a session rather than falling back to a weak
		// source.
		return ""
	}
	id := hex.EncodeToString(buf[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sessions[id] = &session{id: id, issuedAt: now, lastSeen: now}
	s.ever = true
	return id
}

// Validate checks whether the given ID belongs to an active, non-expired
// session. On success it bumps lastSeen and returns true.
func (s *sessionStore) Validate(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	now := s.now()
	if now.Sub(sess.lastSeen) > s.ttl {
		delete(s.sessions, id)
		return false
	}
	sess.lastSeen = now
	return true
}

// Sweep drops every session whose lastSeen is older than ttl. It returns
// the number of sessions removed.
func (s *sessionStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for id, sess := range s.sessions {
		if now.Sub(sess.lastSeen) > s.ttl {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// IdleC returns a channel that is closed once the store decides it has
// been idle for longer than ttl. Never returns a nil channel.
func (s *sessionStore) IdleC() <-chan struct{} { return s.idleCh }

// signalIdle closes idleCh exactly once.
func (s *sessionStore) signalIdle() {
	s.idleOnce.Do(func() { close(s.idleCh) })
}

// checkIdle is the single-shot body of the watcher loop, exposed for
// tests. It returns true if the watcher should stop (idle fired).
func (s *sessionStore) checkIdle() bool {
	s.Sweep()

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ever {
		// No session ever issued → server is still waiting for the
		// first login. Do not auto-shutdown.
		return false
	}
	if len(s.sessions) == 0 {
		// At least one session existed at some point, and now they
		// are all gone (either expired and swept, or explicitly
		// logged out). Treat that as idle.
		s.signalIdle()
		return true
	}
	// Find the youngest lastSeen across all sessions.
	var youngest time.Time
	for _, sess := range s.sessions {
		if sess.lastSeen.After(youngest) {
			youngest = sess.lastSeen
		}
	}
	if s.now().Sub(youngest) > s.ttl {
		s.signalIdle()
		return true
	}
	return false
}

// runWatcher is the background goroutine that calls checkIdle on a
// fixed tick. It exits once idle has fired or when stop is closed.
func (s *sessionStore) runWatcher(stop <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if s.checkIdle() {
				return
			}
		}
	}
}
