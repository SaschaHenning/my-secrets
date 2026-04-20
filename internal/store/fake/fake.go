// Package fake provides an in-memory implementation of store.Interface for
// unit tests that need to exercise the app, mcp, or web layers without a
// live gopass/GPG setup.
//
// Semantics chosen for convenience in tests:
//
//   - Get/Set return/store deep clones so callers cannot mutate internal state.
//   - Remove on an unknown key returns an error (mirrors gopass behaviour
//     closely enough for test assertions).
//   - Search is case-insensitive and matches against path + metadata (username,
//     url, kind, github_project, notes, tags) but NEVER against password
//     values — matches the real store's "metadata only" search semantics.
package fake

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// Store is an in-memory fake implementing store.Interface.
type Store struct {
	mu      sync.RWMutex
	entries map[string]*store.Entry
	// ListErr/SearchErr/GetErr/SetErr/RemoveErr/OrgsErr/CloseErr allow tests
	// to force specific operations to fail. Zero value means no forced error.
	ListErr   error
	SearchErr error
	GetErr    error
	SetErr    error
	RemoveErr error
	OrgsErr   error
	CloseErr  error
}

// Compile-time assertion: *Store satisfies store.Interface.
var _ store.Interface = (*Store)(nil)

// New returns an empty fake store.
func New() *Store {
	return &Store{entries: map[string]*store.Entry{}}
}

// NewWithEntries returns a fake store pre-populated with the given entries
// (deep-cloned into the internal map).
func NewWithEntries(entries ...*store.Entry) *Store {
	s := New()
	for _, e := range entries {
		if e == nil || e.Path == "" {
			continue
		}
		s.entries[e.Path] = cloneEntry(e)
	}
	return s
}

func (s *Store) Close(_ context.Context) error {
	return s.CloseErr
}

func (s *Store) List(_ context.Context, org string) ([]string, error) {
	if s.ListErr != nil {
		return nil, s.ListErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	if org == "" {
		for p := range s.entries {
			out = append(out, p)
		}
	} else {
		prefix := strings.TrimSuffix(org, "/") + "/"
		for p := range s.entries {
			if strings.HasPrefix(p, prefix) {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Search matches entries against the query. When allow != nil, each matched
// path is classified into allowed or denied (policy pre-filter) — denied
// paths never participate in a "decrypt" step in the real store, so the
// fake simply surfaces them separately for assertion. When allow is nil,
// all matches go into allowed and denied stays empty.
func (s *Store) Search(_ context.Context, query string, allow func(path string) bool) (allowed, denied []string, err error) {
	if s.SearchErr != nil {
		return nil, nil, s.SearchErr
	}
	if strings.TrimSpace(query) == "" {
		return nil, nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := strings.ToLower(query)
	allowed = make([]string, 0)
	denied = make([]string, 0)
	for p, e := range s.entries {
		if !entryMatches(p, e, q) {
			continue
		}
		if allow != nil && !allow(p) {
			denied = append(denied, p)
			continue
		}
		allowed = append(allowed, p)
	}
	sort.Strings(allowed)
	sort.Strings(denied)
	return allowed, denied, nil
}

// entryMatches returns true if the query substring appears in the path or any
// metadata field. Password VALUES are intentionally excluded from matching.
func entryMatches(path string, e *store.Entry, q string) bool {
	if strings.Contains(strings.ToLower(path), q) {
		return true
	}
	if e == nil {
		return false
	}
	fields := []string{
		e.Username, e.URL, e.Kind, e.GitHubProject, e.Notes,
	}
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	for _, t := range e.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	// Match on the word "password" (the key) but NOT the password value.
	if strings.Contains("password", q) {
		return true
	}
	return false
}

func (s *Store) Get(_ context.Context, path string) (*store.Entry, error) {
	if s.GetErr != nil {
		return nil, s.GetErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[path]
	if !ok {
		return nil, fmt.Errorf("fake: entry %q not found", path)
	}
	return cloneEntry(e), nil
}

func (s *Store) Set(_ context.Context, e *store.Entry) error {
	if s.SetErr != nil {
		return s.SetErr
	}
	if e == nil || e.Path == "" {
		return fmt.Errorf("fake: entry path required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := cloneEntry(e)
	clone.Org = store.OrgOf(clone.Path)
	s.entries[clone.Path] = clone
	return nil
}

func (s *Store) Remove(_ context.Context, path string) error {
	if s.RemoveErr != nil {
		return s.RemoveErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[path]; !ok {
		return fmt.Errorf("fake: entry %q not found", path)
	}
	delete(s.entries, path)
	return nil
}

func (s *Store) Rotate(ctx context.Context, path, newPassword string) error {
	e, err := s.Get(ctx, path)
	if err != nil {
		return err
	}
	e.Password = newPassword
	return s.Set(ctx, e)
}

func (s *Store) Orgs(_ context.Context) ([]string, error) {
	if s.OrgsErr != nil {
		return nil, s.OrgsErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	for p := range s.entries {
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

// Len returns the number of entries — handy for tests.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func cloneEntry(e *store.Entry) *store.Entry {
	if e == nil {
		return nil
	}
	c := *e // copies RotateAfter (string) and RotatedAt (time.Time) by value.
	if len(e.Tags) > 0 {
		c.Tags = append([]string(nil), e.Tags...)
	}
	return &c
}
