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

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(p, []byte("not: valid: yaml: [["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("want error for invalid YAML")
	}
}

func TestLoadEmptyActors(t *testing.T) {
	// A YAML without any `actors` key produces an empty (non-nil) map.
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(p, []byte("# no actors\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Actors == nil {
		t.Fatal("actors must be non-nil after Load")
	}
	// With no actors defined, every decision is default-deny.
	if d := pol.Evaluate("human", "", "anything"); d.Allowed {
		t.Errorf("empty policy must deny, got %v", d)
	}
}

func TestEvaluateNoAllowRules(t *testing.T) {
	pol := &Policy{Actors: map[string]Rules{
		"ai": {Deny: []string{"private/**"}},
	}}
	d := pol.Evaluate("ai", "", "jasp/github")
	if d.Allowed {
		t.Errorf("actor without any allow rules must be denied, got %v", d)
	}
	if d.MatchedRule != "no-allow" {
		t.Errorf("MatchedRule = %q, want no-allow", d.MatchedRule)
	}
}

func TestEvaluateAgentLabelWins(t *testing.T) {
	pol := &Policy{Actors: map[string]Rules{
		"ai":          {Allow: []string{"**"}},
		"claude-code": {Allow: []string{"jasp/**"}},
	}}
	// agentLabel=claude-code must pick the narrower rule, not the generic
	// ai fallback.
	if d := pol.Evaluate("ai", "claude-code", "other/path"); d.Allowed {
		t.Errorf("agent-label should override, got %v", d)
	}
}

func TestEvaluateNilPolicy(t *testing.T) {
	var pol *Policy
	if d := pol.Evaluate("ai", "", "x"); d.Allowed {
		t.Errorf("nil policy must deny, got %v", d)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) || filepath.Base(p) != "scope-policy.yaml" {
		t.Errorf("unexpected default path: %q", p)
	}
}

func TestWriteDefault(t *testing.T) {
	// Redirect HOME so we don't touch the real config dir.
	t.Setenv("HOME", t.TempDir())
	p, err := WriteDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("policy file not created: %v", err)
	}
	// Calling it again should be a no-op (file exists).
	p2, err := WriteDefault()
	if err != nil {
		t.Fatal(err)
	}
	if p != p2 {
		t.Errorf("paths differ: %q vs %q", p, p2)
	}
}

func TestLoadDefaultPath(t *testing.T) {
	// Load("") should use DefaultPath(). Redirect HOME to avoid depending
	// on the real user's config file.
	t.Setenv("HOME", t.TempDir())
	pol, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil || len(pol.Actors) == 0 {
		t.Error("expected non-empty default policy")
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
