// Package policy enforces org-scoped access rules. A policy is a YAML file
// mapping actor kinds to allow/deny path globs.
package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy maps an actor identifier (e.g. "claude-code", "human", "script",
// "ai") to its allow/deny rule set.
type Policy struct {
	Actors map[string]Rules `yaml:"actors"`
}

// Rules define which secret paths an actor may or may not touch.
// Allow is evaluated first; a path must match at least one allow pattern.
// A matching deny pattern overrides an allow.
type Rules struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

// Decision is the outcome of evaluating a path against a policy.
type Decision struct {
	Allowed     bool
	MatchedRule string
	Reason      string
}

// DefaultPath returns the standard config location:
// ~/.config/my-secrets/scope-policy.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "my-secrets", "scope-policy.yaml"), nil
}

// Default returns the baked-in policy used when no file is present.
// Humans and scripts get everything; AI callers are scoped to `jasp/**`
// and `zuhause/**` with `private/**` hard-denied.
//
// Important: the default policy is additive, but Evaluate fail-closes on
// unknown actors. If you spelt the actor key wrong in your YAML, nothing
// matches and every request is denied.
func Default() *Policy {
	return &Policy{
		Actors: map[string]Rules{
			"human": {
				Allow: []string{"**"},
			},
			"script": {
				Allow: []string{"**"},
			},
			"ai": {
				Allow: []string{"jasp/**", "zuhause/**"},
				Deny:  []string{"private/**"},
			},
			"claude-code": {
				Allow: []string{"jasp/**", "zuhause/**"},
				Deny:  []string{"private/**"},
			},
		},
	}
}

// Load reads policy from path. Missing file returns Default() and no error.
func Load(p string) (*Policy, error) {
	if p == "" {
		var err error
		p, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var pol Policy
	if err := yaml.Unmarshal(b, &pol); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if pol.Actors == nil {
		pol.Actors = map[string]Rules{}
	}
	return &pol, nil
}

// WriteDefault writes the default policy to DefaultPath() if it does not
// already exist. Returns the path written (or the existing path).
func WriteDefault() (string, error) {
	p, err := DefaultPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	b, err := yaml.Marshal(Default())
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o600)
}

// Evaluate decides whether an actor may touch a secret path.
// actor should be one of the kinds produced by the caller package
// (human, ai, script). The agentLabel (e.g. "claude-code") is checked
// first as a more specific key; if not present, the generic kind is used.
//
// If no rules exist for either the specific label or the generic kind,
// the decision is DENY. Fail-closed — a missing or misspelled actor
// entry must never silently open the store.
func (pol *Policy) Evaluate(actorKind, agentLabel, secretPath string) Decision {
	rules, label := pol.rulesFor(actorKind, agentLabel)
	if rules == nil {
		return Decision{Allowed: false, MatchedRule: "no-rules",
			Reason: "no rules for actor " + label + " — default deny"}
	}
	for _, d := range rules.Deny {
		if match(d, secretPath) {
			return Decision{Allowed: false, MatchedRule: "deny:" + d,
				Reason: fmt.Sprintf("%s denied by rule %q", label, d)}
		}
	}
	if len(rules.Allow) == 0 {
		return Decision{Allowed: false, MatchedRule: "no-allow",
			Reason: fmt.Sprintf("%s has no allow rules", label)}
	}
	for _, a := range rules.Allow {
		if match(a, secretPath) {
			return Decision{Allowed: true, MatchedRule: "allow:" + a,
				Reason: fmt.Sprintf("%s allowed by rule %q", label, a)}
		}
	}
	return Decision{Allowed: false, MatchedRule: "no-match",
		Reason: fmt.Sprintf("%s has no matching allow rule for %q", label, secretPath)}
}

func (pol *Policy) rulesFor(kind, agentLabel string) (*Rules, string) {
	if pol == nil || pol.Actors == nil {
		return nil, kind
	}
	if agentLabel != "" {
		if r, ok := pol.Actors[agentLabel]; ok {
			return &r, agentLabel
		}
	}
	if r, ok := pol.Actors[kind]; ok {
		return &r, kind
	}
	return nil, kind
}

// match checks whether a path matches a shell-style glob pattern. We use
// path.Match but also allow "**" for "any number of segments".
func match(pattern, p string) bool {
	pattern = strings.TrimSpace(pattern)
	p = strings.TrimSpace(p)
	if pattern == "**" {
		return true
	}
	// Expand "**" to match any subpath by splitting on the literal
	// and checking both prefix/suffix.
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		rawPrefix := parts[0]
		rawSuffix := parts[1]
		prefix := strings.TrimSuffix(rawPrefix, "/")
		suffix := strings.TrimPrefix(rawSuffix, "/")
		// Prefix ending in "/" requires at least one additional segment.
		if prefix != "" {
			if strings.HasSuffix(rawPrefix, "/") {
				if !strings.HasPrefix(p, prefix+"/") {
					return false
				}
			} else if !strings.HasPrefix(p, prefix) {
				return false
			}
		}
		if suffix != "" && !strings.HasSuffix(p, suffix) {
			return false
		}
		return true
	}
	ok, err := path.Match(pattern, p)
	return err == nil && ok
}
