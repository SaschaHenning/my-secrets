// Package policy enforces org-scoped access rules. A policy is a YAML file
// mapping actor kinds to allow/deny path globs.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	policyFileSizeLimit = 256 * 1024
	maxActorNameBytes   = 64
	maxGlobBytes        = 512
	maxActors           = 128
	maxRulesPerActor    = 512
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
	b, err := readPolicyFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	pol, err := decodePolicy(b)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return pol, nil
}

func decodePolicy(data []byte) (*Policy, error) {
	if _, err := validateYAMLDocument(data); err != nil {
		return nil, err
	}

	var pol Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&pol); err != nil {
		return nil, err
	}
	if pol.Actors == nil {
		pol.Actors = map[string]Rules{}
	}
	if err := validatePolicy(&pol); err != nil {
		return nil, err
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
	b, err := yaml.Marshal(Default())
	if err != nil {
		return "", err
	}
	if err := ensurePolicyFile(p, b); err != nil {
		return "", err
	}
	return p, nil
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
	if validateGlob(pattern) != nil || validateSecretPath(p) != nil {
		return false
	}
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

func validateYAMLDocument(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy is empty")
		}
		return nil, err
	}
	if document.Kind != yaml.DocumentNode ||
		len(document.Content) != 1 ||
		document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("policy root must be a mapping")
	}
	if err := rejectDuplicateYAMLKeys(document.Content[0]); err != nil {
		return nil, err
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("policy must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return document.Content[0], nil
}

func rejectDuplicateYAMLKeys(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML aliases and anchors are not allowed")
	}
	if node.Tag == "!!null" {
		return errors.New("YAML null values are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return errors.New("invalid YAML mapping")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return errors.New("policy mapping keys must be strings")
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := rejectDuplicateYAMLKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicy(pol *Policy) error {
	if pol == nil {
		return errors.New("policy is nil")
	}
	if len(pol.Actors) > maxActors {
		return fmt.Errorf("policy has more than %d actors", maxActors)
	}
	for actor, rules := range pol.Actors {
		if err := validateActorName(actor); err != nil {
			return fmt.Errorf("actor %q: %w", actor, err)
		}
		if len(rules.Allow)+len(rules.Deny) > maxRulesPerActor {
			return fmt.Errorf(
				"actor %q has more than %d rules",
				actor,
				maxRulesPerActor,
			)
		}
		for _, pattern := range rules.Allow {
			if err := validateGlob(pattern); err != nil {
				return fmt.Errorf("actor %q allow glob: %w", actor, err)
			}
		}
		for _, pattern := range rules.Deny {
			if err := validateGlob(pattern); err != nil {
				return fmt.Errorf("actor %q deny glob: %w", actor, err)
			}
		}
	}
	return nil
}

func validateActorName(actor string) error {
	if actor == "" {
		return errors.New("name is empty")
	}
	if len(actor) > maxActorNameBytes {
		return fmt.Errorf("name exceeds %d bytes", maxActorNameBytes)
	}
	for index, char := range actor {
		valid := char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' ||
			(index > 0 && (char == '-' || char == '_' || char == '.'))
		if !valid {
			return fmt.Errorf("name contains invalid character %q", char)
		}
	}
	return nil
}

func validateGlob(pattern string) error {
	if pattern == "" {
		return errors.New("glob is empty")
	}
	if len(pattern) > maxGlobBytes {
		return fmt.Errorf("glob exceeds %d bytes", maxGlobBytes)
	}
	if !utf8.ValidString(pattern) {
		return errors.New("glob is not valid UTF-8")
	}
	if strings.TrimSpace(pattern) != pattern {
		return errors.New("glob has leading or trailing whitespace")
	}
	if strings.HasPrefix(pattern, "/") || strings.Contains(pattern, `\`) {
		return errors.New("glob must be a relative slash-separated path")
	}
	for _, char := range pattern {
		if isUnsafeFormatCharacter(char) {
			return fmt.Errorf("glob contains control character %q", char)
		}
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" {
			return errors.New("glob contains an empty path segment")
		}
		if segment == "." || segment == ".." {
			return errors.New("glob contains a traversal segment")
		}
	}
	if _, err := path.Match(pattern, "policy-validation-probe"); err != nil {
		return fmt.Errorf("invalid glob: %w", err)
	}
	if globstar := strings.Index(pattern, "**"); globstar >= 0 {
		remainder := pattern[:globstar] + pattern[globstar+2:]
		if strings.ContainsAny(remainder, "*?[") {
			return errors.New(
				"glob cannot combine ** with other wildcard operators",
			)
		}
	}
	return nil
}

func validateSecretPath(secretPath string) error {
	if secretPath == "" {
		return errors.New("secret path is empty")
	}
	if !utf8.ValidString(secretPath) {
		return errors.New("secret path is not valid UTF-8")
	}
	if strings.TrimSpace(secretPath) != secretPath ||
		strings.HasPrefix(secretPath, "/") ||
		strings.Contains(secretPath, `\`) {
		return errors.New("secret path is not a safe relative path")
	}
	for _, char := range secretPath {
		if isUnsafeFormatCharacter(char) {
			return errors.New("secret path contains a control character")
		}
	}
	for _, segment := range strings.Split(secretPath, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("secret path contains an unsafe segment")
		}
	}
	return nil
}

func isUnsafeFormatCharacter(char rune) bool {
	return unicode.IsControl(char) ||
		unicode.In(char, unicode.Cf, unicode.Zl, unicode.Zp)
}

func readPolicyFile(policyPath string) ([]byte, error) {
	if policyPath == "" {
		return nil, errors.New("policy path is empty")
	}
	pathInfo, err := os.Lstat(policyPath)
	if err != nil {
		return nil, err
	}
	if err := validatePolicyFileInfo(pathInfo); err != nil {
		return nil, err
	}
	if pathInfo.Size() > policyFileSizeLimit {
		return nil, fmt.Errorf(
			"policy exceeds %d bytes",
			policyFileSizeLimit,
		)
	}

	file, err := os.Open(policyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validatePolicyFileInfo(openInfo); err != nil {
		return nil, err
	}
	if !os.SameFile(pathInfo, openInfo) {
		return nil, errors.New("policy file changed while opening")
	}
	if openInfo.Size() > policyFileSizeLimit {
		return nil, fmt.Errorf(
			"policy exceeds %d bytes",
			policyFileSizeLimit,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, policyFileSizeLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > policyFileSizeLimit {
		return nil, fmt.Errorf(
			"policy exceeds %d bytes",
			policyFileSizeLimit,
		)
	}
	return data, nil
}

func validatePolicyFileInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic-link policies are not allowed")
	}
	if !info.Mode().IsRegular() {
		return errors.New("policy is not a regular file")
	}
	permissions := info.Mode().Perm()
	if permissions&0o077 != 0 || permissions&0o400 == 0 {
		return fmt.Errorf(
			"policy permissions %#o are insecure",
			permissions,
		)
	}
	return nil
}

func ensurePolicyFile(policyPath string, data []byte) error {
	if policyPath == "" {
		return errors.New("policy path is empty")
	}
	if info, err := os.Lstat(policyPath); err == nil {
		return validatePolicyFileInfo(info)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	parent := filepath.Dir(policyPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, "."+filepath.Base(policyPath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary policy permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary policy: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary policy: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary policy: %w", err)
	}
	if err := os.Link(tempPath, policyPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			info, statErr := os.Lstat(policyPath)
			if statErr != nil {
				return fmt.Errorf("inspect concurrently created policy: %w", statErr)
			}
			return validatePolicyFileInfo(info)
		}
		return fmt.Errorf("install policy: %w", err)
	}
	return nil
}
