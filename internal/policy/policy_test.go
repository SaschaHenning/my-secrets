package policy

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsNonStrictYAML(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown root field",
			body: "actors: {}\nunexpected: true\n",
		},
		{
			name: "unknown rule field",
			body: "actors:\n  ai:\n    allow: [\"jasp/**\"]\n    unexpected: true\n",
		},
		{
			name: "duplicate root key",
			body: "actors: {}\nactors: {}\n",
		},
		{
			name: "duplicate nested key",
			body: "actors:\n  ai:\n    allow: [\"jasp/**\"]\n    allow: [\"private/**\"]\n",
		},
		{
			name: "multiple documents",
			body: "actors: {}\n---\nactors: {}\n",
		},
		{
			name: "null actors",
			body: "actors: null\n",
		},
		{
			name: "null rules",
			body: "actors:\n  ai: null\n",
		},
		{
			name: "non string actor",
			body: "actors:\n  1:\n    allow: [\"jasp/**\"]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatal("expected strict policy parsing to fail")
			}
		})
	}
}

func TestLoadRejectsUnsafePolicyFile(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.yaml")
		link := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(target, []byte("actors: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link); err == nil {
			t.Fatal("expected symbolic-link policy to be rejected")
		}
	})

	t.Run("non regular", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("expected directory policy to be rejected")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		body := strings.Repeat("#", policyFileSizeLimit+1)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("expected oversized policy to be rejected")
		}
	})
}

func TestLoadValidatesActorNamesAndGlobs(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unicode actor",
			body: "actors:\n  über-agent:\n    allow: [\"jasp/**\"]\n",
		},
		{
			name: "control character actor",
			body: "actors:\n  \"ai\\tbot\":\n    allow: [\"jasp/**\"]\n",
		},
		{
			name: "control character glob",
			body: "actors:\n  ai:\n    allow: [\"jasp/ok\\n/**\"]\n",
		},
		{
			name: "invalid glob",
			body: "actors:\n  ai:\n    allow: [\"jasp/[broken\"]\n",
		},
		{
			name: "unsupported composite globstar",
			body: "actors:\n  ai:\n    allow: [\"jasp/*/**\"]\n",
		},
		{
			name: "traversing glob",
			body: "actors:\n  ai:\n    allow: [\"../jasp/**\"]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatal("expected invalid policy to be rejected")
			}
		})
	}
}

func TestLoadAllowsPrintableUnicodeGlob(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	body := "actors:\n  human:\n    allow: [\"jasp/über/**\"]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if decision := pol.Evaluate("human", "", "jasp/über/passwort"); !decision.Allowed {
		t.Fatalf("printable Unicode glob should be supported: %v", decision)
	}
}

func TestEvaluateRejectsUnsafeSecretPaths(t *testing.T) {
	pol := &Policy{Actors: map[string]Rules{
		"human": {Allow: []string{"**"}},
	}}
	paths := []string{
		"",
		"/absolute",
		"jasp/../private",
		"jasp/./secret",
		"jasp//secret",
		`jasp\secret`,
		"jasp/secret\n",
		" jasp/secret",
		"jasp/\u2028secret",
	}
	for _, secretPath := range paths {
		t.Run(secretPath, func(t *testing.T) {
			if decision := pol.Evaluate(
				"human",
				"",
				secretPath,
			); decision.Allowed {
				t.Fatalf("unsafe path %q was allowed: %v", secretPath, decision)
			}
		})
	}
}

func TestLoadEmptyActors(t *testing.T) {
	// An explicit empty actors mapping produces an empty (non-nil) map.
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(p, []byte("actors: {}\n"), 0o600); err != nil {
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
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("policy mode = %#o, want 0600", got)
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
