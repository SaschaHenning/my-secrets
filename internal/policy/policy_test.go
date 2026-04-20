package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEvaluate(t *testing.T) {
	pol := Default()
	cases := []struct {
		kind, agent, path string
		wantAllow         bool
	}{
		{"human", "", "jasp/github-test", true},
		{"human", "", "private/bank", true},
		{"ai", "claude-code", "jasp/github-test", true},
		{"ai", "claude-code", "zuhause/proxmox-root", true},
		{"ai", "claude-code", "private/bank", false},
		{"ai", "claude-code", "some-other/path", false},
		{"script", "", "private/bank", true},
	}
	for _, tc := range cases {
		d := pol.Evaluate(tc.kind, tc.agent, tc.path)
		if d.Allowed != tc.wantAllow {
			t.Errorf("Evaluate(%q,%q,%q) = %v, want %v (reason: %s)",
				tc.kind, tc.agent, tc.path, d.Allowed, tc.wantAllow, d.Reason)
		}
	}
}

func TestLoadMissingReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nope.yaml")
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Actors) == 0 {
		t.Fatal("expected default actors")
	}
}

func TestUnknownActorDeniedByDefault(t *testing.T) {
	pol := &Policy{Actors: map[string]Rules{
		"human": {Allow: []string{"**"}},
	}}
	d := pol.Evaluate("robot", "", "anything")
	if d.Allowed {
		t.Errorf("unknown actor should default-deny, got %v", d)
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	pol := &Policy{Actors: map[string]Rules{
		"ai": {
			Allow: []string{"jasp/**"},
			Deny:  []string{"jasp/private/**"},
		},
	}}
	if d := pol.Evaluate("ai", "", "jasp/ok"); !d.Allowed {
		t.Errorf("expected allow jasp/ok, got %v", d)
	}
	if d := pol.Evaluate("ai", "", "jasp/private/bank"); d.Allowed {
		t.Errorf("expected deny jasp/private/bank (deny overrides allow), got %v", d)
	}
}

func TestLoadCustom(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.yaml")
	body := `actors:
  ai:
    allow: ["ok/**"]
    deny:  ["nope/**"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := pol.Evaluate("ai", "", "ok/a"); !d.Allowed {
		t.Errorf("expected allow, got %v", d)
	}
	if d := pol.Evaluate("ai", "", "nope/a"); d.Allowed {
		t.Errorf("expected deny, got %v", d)
	}
	if d := pol.Evaluate("ai", "", "other"); d.Allowed {
		t.Errorf("expected deny-by-default, got %v", d)
	}
}

func TestMatchGlobs(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"**", "anything/goes", true},
		{"jasp/**", "jasp/github", true},
		{"jasp/**", "other/github", false},
		{"jasp/**", "jasp", false},
		{"*.env", "dev.env", true},
		{"**.env", "any/path/dev.env", true},
	}
	for _, tc := range cases {
		got := match(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("match(%q,%q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}
