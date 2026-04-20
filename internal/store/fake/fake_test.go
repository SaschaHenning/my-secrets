package fake

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

func ctx() context.Context { return context.Background() }

func sample() []*store.Entry {
	return []*store.Entry{
		{Path: "jasp/github", Username: "alice", URL: "https://github.com", Kind: "password", Tags: []string{"work", "vcs"}, Notes: "primary", Password: "p1"},
		{Path: "jasp/aws/prod", Username: "bob", Kind: "api_key", Password: "secret-AWS"},
		{Path: "zuhause/router", Username: "admin", URL: "https://192.168.1.1", Password: "z-router"},
		{Path: "private/bank", Username: "me", Password: "bank-pass"},
		{Path: "toplevel", Password: "nomatter"},
	}
}

func TestNewEmpty(t *testing.T) {
	s := New()
	if s.Len() != 0 {
		t.Fatalf("fresh store should be empty, got %d", s.Len())
	}
	if err := s.Close(ctx()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestNewWithEntries_SkipsNilAndEmptyPath(t *testing.T) {
	s := NewWithEntries(nil, &store.Entry{Path: ""}, &store.Entry{Path: "jasp/x", Password: "p"})
	if s.Len() != 1 {
		t.Fatalf("want 1 entry, got %d", s.Len())
	}
}

func TestList(t *testing.T) {
	s := NewWithEntries(sample()...)
	all, err := s.List(ctx(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"jasp/aws/prod", "jasp/github", "private/bank", "toplevel", "zuhause/router"}
	if !reflect.DeepEqual(all, want) {
		t.Errorf("List(\"\") = %v, want %v", all, want)
	}

	jasp, _ := s.List(ctx(), "jasp")
	if !reflect.DeepEqual(jasp, []string{"jasp/aws/prod", "jasp/github"}) {
		t.Errorf("List(jasp) = %v", jasp)
	}

	// Trailing slash handling
	jasp2, _ := s.List(ctx(), "jasp/")
	if !reflect.DeepEqual(jasp, jasp2) {
		t.Errorf("List with and without trailing slash must be equal: %v vs %v", jasp, jasp2)
	}

	// Filter for nonexistent org
	none, _ := s.List(ctx(), "nope")
	if len(none) != 0 {
		t.Errorf("expected empty, got %v", none)
	}
}

func TestList_ErrorForced(t *testing.T) {
	s := NewWithEntries(sample()...)
	s.ListErr = errors.New("boom")
	_, err := s.List(ctx(), "")
	if err == nil || err.Error() != "boom" {
		t.Errorf("want forced error, got %v", err)
	}
}

func TestSearch(t *testing.T) {
	s := NewWithEntries(sample()...)

	// Empty query returns nil/empty, not an error.
	got, _, err := s.Search(ctx(), "", nil)
	if err != nil || got != nil {
		t.Errorf("empty query: got %v, %v", got, err)
	}
	got, _, err = s.Search(ctx(), "   ", nil)
	if err != nil || got != nil {
		t.Errorf("whitespace query: got %v, %v", got, err)
	}

	// Path match
	got, _, _ = s.Search(ctx(), "github", nil)
	if !reflect.DeepEqual(got, []string{"jasp/github"}) {
		t.Errorf("search github = %v", got)
	}

	// Username match (case-insensitive)
	got, _, _ = s.Search(ctx(), "BOB", nil)
	if !reflect.DeepEqual(got, []string{"jasp/aws/prod"}) {
		t.Errorf("search BOB = %v", got)
	}

	// URL match
	got, _, _ = s.Search(ctx(), "192.168", nil)
	if !reflect.DeepEqual(got, []string{"zuhause/router"}) {
		t.Errorf("search 192.168 = %v", got)
	}

	// Kind match
	got, _, _ = s.Search(ctx(), "api_key", nil)
	if !reflect.DeepEqual(got, []string{"jasp/aws/prod"}) {
		t.Errorf("search api_key = %v", got)
	}

	// Notes match
	got, _, _ = s.Search(ctx(), "primary", nil)
	if !reflect.DeepEqual(got, []string{"jasp/github"}) {
		t.Errorf("search primary = %v", got)
	}

	// Tag match
	got, _, _ = s.Search(ctx(), "vcs", nil)
	if !reflect.DeepEqual(got, []string{"jasp/github"}) {
		t.Errorf("search vcs = %v", got)
	}

	// Password VALUE must NOT match.
	got, _, _ = s.Search(ctx(), "secret-AWS", nil)
	if len(got) != 0 {
		t.Errorf("password value must not match; got %v", got)
	}
	got, _, _ = s.Search(ctx(), "bank-pass", nil)
	if len(got) != 0 {
		t.Errorf("password value must not match; got %v", got)
	}
}

func TestSearch_PasswordKey(t *testing.T) {
	s := NewWithEntries(sample()...)
	// The literal word "password" is permitted to match (it is a metadata key
	// name, not a secret value).
	got, _, err := s.Search(ctx(), "password", nil)
	if err != nil {
		t.Fatal(err)
	}
	// All entries match because the key "password" matches every entry.
	if len(got) != len(sample()) {
		t.Errorf("want %d matches, got %d", len(sample()), len(got))
	}
}

func TestSearch_GitHubProjectField(t *testing.T) {
	s := NewWithEntries(&store.Entry{Path: "jasp/repo", GitHubProject: "SaschaHenning/my-secrets", Password: "x"})
	got, _, _ := s.Search(ctx(), "my-secrets", nil)
	if !reflect.DeepEqual(got, []string{"jasp/repo"}) {
		t.Errorf("github_project match failed: %v", got)
	}
}

func TestSearch_ErrorForced(t *testing.T) {
	s := NewWithEntries(sample()...)
	s.SearchErr = errors.New("search failed")
	_, _, err := s.Search(ctx(), "anything", nil)
	if err == nil {
		t.Error("want forced search error")
	}
}

func TestGetReturnsClone(t *testing.T) {
	s := NewWithEntries(sample()...)
	e, err := s.Get(ctx(), "jasp/github")
	if err != nil {
		t.Fatal(err)
	}
	if e.Username != "alice" {
		t.Errorf("username = %q", e.Username)
	}
	// Mutate the returned clone; the internal entry must not change.
	e.Username = "mallory"
	e.Tags[0] = "MUTATED"
	e2, _ := s.Get(ctx(), "jasp/github")
	if e2.Username != "alice" {
		t.Error("mutation through returned clone affected internal state")
	}
	if e2.Tags[0] != "work" {
		t.Errorf("tags mutation leaked: %v", e2.Tags)
	}
}

func TestGet_Missing(t *testing.T) {
	s := New()
	_, err := s.Get(ctx(), "nope")
	if err == nil {
		t.Error("want error for missing entry")
	}
}

func TestGet_ErrorForced(t *testing.T) {
	s := NewWithEntries(sample()...)
	s.GetErr = errors.New("bang")
	_, err := s.Get(ctx(), "jasp/github")
	if err == nil {
		t.Error("want forced error")
	}
}

func TestSet(t *testing.T) {
	s := New()
	if err := s.Set(ctx(), &store.Entry{Path: "jasp/new", Password: "p", Tags: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(ctx(), "jasp/new")
	if err != nil {
		t.Fatal(err)
	}
	// Org must be derived from path.
	if e.Org != "jasp" {
		t.Errorf("org = %q, want jasp", e.Org)
	}
	// Mutating the original must not affect the stored value.
	original := &store.Entry{Path: "jasp/two", Password: "p", Tags: []string{"keep"}}
	_ = s.Set(ctx(), original)
	original.Tags[0] = "MUTATED"
	back, _ := s.Get(ctx(), "jasp/two")
	if back.Tags[0] != "keep" {
		t.Errorf("stored value affected by caller mutation: %v", back.Tags)
	}
}

func TestSet_EmptyPath(t *testing.T) {
	s := New()
	if err := s.Set(ctx(), &store.Entry{Path: ""}); err == nil {
		t.Error("want error for empty path")
	}
	if err := s.Set(ctx(), nil); err == nil {
		t.Error("want error for nil entry")
	}
}

func TestSet_ErrorForced(t *testing.T) {
	s := New()
	s.SetErr = errors.New("nope")
	if err := s.Set(ctx(), &store.Entry{Path: "a/b"}); err == nil {
		t.Error("want forced error")
	}
}

func TestRemove(t *testing.T) {
	s := NewWithEntries(sample()...)
	if err := s.Remove(ctx(), "jasp/github"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx(), "jasp/github"); err == nil {
		t.Error("entry still present after remove")
	}
	// Removing nonexistent → error.
	if err := s.Remove(ctx(), "not/here"); err == nil {
		t.Error("want error for missing key")
	}
}

func TestRemove_ErrorForced(t *testing.T) {
	s := NewWithEntries(sample()...)
	s.RemoveErr = errors.New("block")
	if err := s.Remove(ctx(), "jasp/github"); err == nil {
		t.Error("want forced error")
	}
}

func TestRotate(t *testing.T) {
	s := NewWithEntries(sample()...)
	if err := s.Rotate(ctx(), "jasp/github", "new-pass"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get(ctx(), "jasp/github")
	if e.Password != "new-pass" {
		t.Errorf("password = %q, want new-pass", e.Password)
	}
	// Metadata preserved.
	if e.Username != "alice" {
		t.Errorf("username changed during rotate: %q", e.Username)
	}
	// Rotate on missing key → error propagates.
	if err := s.Rotate(ctx(), "missing", "x"); err == nil {
		t.Error("want error rotating missing entry")
	}
}

func TestOrgs(t *testing.T) {
	s := NewWithEntries(sample()...)
	orgs, err := s.Orgs(ctx())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"jasp", "private", "zuhause"}
	if !reflect.DeepEqual(orgs, want) {
		t.Errorf("orgs = %v, want %v", orgs, want)
	}
}

func TestOrgs_ErrorForced(t *testing.T) {
	s := NewWithEntries(sample()...)
	s.OrgsErr = errors.New("x")
	_, err := s.Orgs(ctx())
	if err == nil {
		t.Error("want forced error")
	}
}

func TestClose_ErrorForced(t *testing.T) {
	s := New()
	s.CloseErr = errors.New("c")
	if err := s.Close(ctx()); err == nil {
		t.Error("want forced close error")
	}
}

func TestCloneEntry_Nil(t *testing.T) {
	if got := cloneEntry(nil); got != nil {
		t.Errorf("cloneEntry(nil) = %v, want nil", got)
	}
}
