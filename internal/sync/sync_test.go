package sync

import (
	"path/filepath"
	"testing"
	"time"
)

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
