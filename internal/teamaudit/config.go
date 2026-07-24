package teamaudit

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
)

// Config identifies a shared mount, its independent audit remote, and the
// local paths required to bind each audit event to the current store state.
type Config struct {
	Mount              string
	URL                string
	SigningFingerprint string
	StorePath          string
	PolicyPath         string
	TeamKeysPath       string
	RecipientPath      string
	WorkDir            string
	StateDir           string
	DeviceIDPath       string
	GPGHome            string
}

// Validate rejects unsafe mount names, repository URLs, fingerprints, and
// filesystem layouts before any subprocess or file mutation occurs.
func (config Config) Validate() error {
	if err := validateMount(config.Mount); err != nil {
		return err
	}
	if err := ValidateURL(config.URL); err != nil {
		return err
	}
	fingerprint, err := normalizeFingerprint(config.SigningFingerprint)
	if err != nil {
		return fmt.Errorf("invalid audit signing fingerprint: %w", err)
	}
	if fingerprint != config.SigningFingerprint {
		return errors.New("audit signing fingerprint must be uppercase and canonical")
	}

	paths := []struct {
		label string
		value string
	}{
		{"store path", config.StorePath},
		{"policy path", config.PolicyPath},
		{"team key path", config.TeamKeysPath},
		{"recipient path", config.RecipientPath},
		{"work directory", config.WorkDir},
		{"state directory", config.StateDir},
		{"device ID path", config.DeviceIDPath},
	}
	for _, item := range paths {
		if err := validateAbsoluteCleanPath(item.label, item.value); err != nil {
			return err
		}
	}
	if config.GPGHome != "" {
		if err := validateAbsoluteCleanPath("GPG home", config.GPGHome); err != nil {
			return err
		}
	}
	for _, item := range paths[2:4] {
		if !pathWithin(config.StorePath, item.value) {
			return fmt.Errorf("%s must be inside the store path", item.label)
		}
	}
	if config.TeamKeysPath != filepath.Join(config.StorePath, teamkeys.Filename) {
		return errors.New("team key path must be store/team-keys.yaml")
	}
	if config.RecipientPath != filepath.Join(config.StorePath, ".gpg-id") {
		return errors.New("recipient path must be store/.gpg-id")
	}
	if pathsOverlap(config.StorePath, config.DeviceIDPath) ||
		pathsOverlap(config.WorkDir, config.DeviceIDPath) {
		return errors.New("device ID path must not overlap store or audit work paths")
	}
	if pathsOverlap(config.StorePath, config.WorkDir) {
		return errors.New("audit work directory and store path must not overlap")
	}
	if pathsOverlap(config.StorePath, config.StateDir) {
		return errors.New("audit state directory and store path must not overlap")
	}
	if pathsOverlap(config.WorkDir, config.StateDir) {
		return errors.New("audit work and state directories must not overlap")
	}
	if pathsOverlap(config.PolicyPath, config.WorkDir) ||
		pathsOverlap(config.PolicyPath, config.StateDir) ||
		filepath.Clean(config.PolicyPath) == filepath.Clean(config.DeviceIDPath) {
		return errors.New("shared policy path must not overlap audit runtime paths")
	}
	if localRemote, ok := validatedLocalAuditPath(config.URL); ok &&
		(pathsOverlap(config.StorePath, localRemote) ||
			pathsOverlap(config.WorkDir, localRemote) ||
			pathsOverlap(config.StateDir, localRemote) ||
			pathsOverlap(config.DeviceIDPath, localRemote) ||
			pathsOverlap(config.PolicyPath, localRemote)) {
		return errors.New(
			"local audit remote must not overlap store, policy, device, work, or state paths",
		)
	}
	if config.GPGHome != "" &&
		(pathsOverlap(config.GPGHome, config.WorkDir) ||
			pathsOverlap(config.GPGHome, config.StateDir) ||
			pathsOverlap(config.GPGHome, config.StorePath)) {
		return errors.New("GPG home must not overlap audit or store paths")
	}
	return nil
}

// DefaultConfig derives one canonical filesystem layout for both CLI and app
// callers. Policy and device identity live in config space, the clone in cache
// space, and rollback watermarks in XDG state space.
func DefaultConfig(
	mount string,
	rawURL string,
	fingerprint string,
	storePath string,
) (Config, error) {
	if err := validateMount(mount); err != nil {
		return Config{}, err
	}
	if err := ValidateURL(rawURL); err != nil {
		return Config{}, err
	}
	normalizedFingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return Config{}, err
	}
	if err := validateAbsoluteCleanPath("store path", storePath); err != nil {
		return Config{}, err
	}
	policyPath, err := policy.SharedPath(mount)
	if err != nil {
		return Config{}, fmt.Errorf("resolve shared policy path: %w", err)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve user config directory: %w", err)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve user cache directory: %w", err)
	}
	stateDir, err := userStateDirectory()
	if err != nil {
		return Config{}, err
	}
	baseConfig := filepath.Join(configDir, "my-secrets", "team-audit")
	config := Config{
		Mount:              mount,
		URL:                rawURL,
		SigningFingerprint: normalizedFingerprint,
		StorePath:          storePath,
		PolicyPath:         policyPath,
		TeamKeysPath:       filepath.Join(storePath, teamkeys.Filename),
		RecipientPath:      filepath.Join(storePath, ".gpg-id"),
		WorkDir: filepath.Join(
			cacheDir,
			"my-secrets",
			"team-audit",
			mount,
			"repository",
		),
		StateDir: filepath.Join(
			stateDir,
			"my-secrets",
			"team-audit",
			mount,
		),
		DeviceIDPath: filepath.Join(
			baseConfig,
			"device.id",
		),
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func userStateDirectory() (string, error) {
	if configured := os.Getenv("XDG_STATE_HOME"); configured != "" {
		if err := validateAbsoluteCleanPath(
			"XDG_STATE_HOME",
			configured,
		); err != nil {
			return "", errors.New("XDG_STATE_HOME must be a clean absolute path")
		}
		return configured, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state"), nil
}

// ValidateURL accepts local absolute paths for offline operation and
// credential-free HTTPS, SSH, file, or Git scp-style remotes.
func ValidateURL(raw string) error {
	if raw == "" {
		return errors.New("audit URL is required")
	}
	if strings.TrimSpace(raw) != raw || strings.HasPrefix(raw, "-") ||
		containsControl(raw) {
		return errors.New("audit URL contains unsafe characters")
	}
	if filepath.IsAbs(raw) {
		if filepath.Clean(raw) != raw || raw == string(filepath.Separator) {
			return errors.New("local audit URL must be a clean non-root path")
		}
		return nil
	}

	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("parse audit URL: %w", err)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("audit URL must not contain a query or fragment")
		}
		switch parsed.Scheme {
		case "https":
			if parsed.User != nil || parsed.Host == "" || parsed.Path == "" {
				return errors.New("HTTPS audit URL must not embed credentials")
			}
		case "ssh":
			if parsed.Host == "" || parsed.Path == "" {
				return errors.New("SSH audit URL requires a host and path")
			}
			if parsed.User != nil {
				if _, hasPassword := parsed.User.Password(); hasPassword ||
					parsed.User.Username() != "git" {
					return errors.New("SSH audit URL may only use the git username")
				}
			}
		case "file":
			localPath := filepath.FromSlash(parsed.Path)
			if parsed.User != nil || parsed.Host != "" ||
				!filepath.IsAbs(localPath) ||
				filepath.Clean(localPath) != localPath ||
				localPath == string(filepath.Separator) {
				return errors.New("file audit URL must be a local absolute path")
			}
		default:
			return fmt.Errorf("unsupported audit URL scheme %q", parsed.Scheme)
		}
		return nil
	}

	colon := strings.IndexByte(raw, ':')
	if colon < 1 || colon == len(raw)-1 {
		return errors.New("audit URL must be an absolute path or supported Git URL")
	}
	left, remotePath := raw[:colon], raw[colon+1:]
	if left == "" || remotePath == "" || strings.HasPrefix(remotePath, "/") ||
		strings.ContainsAny(left+remotePath, `\ `) {
		return errors.New("invalid Git scp-style audit URL")
	}
	if at := strings.IndexByte(left, '@'); at >= 0 {
		if left[:at] != "git" || at == len(left)-1 {
			return errors.New("Git scp-style audit URL may only use the git username")
		}
		left = left[at+1:]
	}
	if left == "" || strings.ContainsAny(left, "/:") ||
		strings.Contains(remotePath, "..") {
		return errors.New("invalid Git scp-style audit URL")
	}
	return nil
}

// ParseGitHubRemote maps every GitHub URL form accepted by ValidateURL to the
// owner/repository slug used by the GitHub CLI. A malformed target on a
// recognized GitHub host remains a GitHub target and fails closed.
func ParseGitHubRemote(
	raw string,
) (owner string, repo string, isGitHub bool, err error) {
	if err := ValidateURL(raw); err != nil {
		return "", "", false, err
	}
	if filepath.IsAbs(raw) {
		return "", "", false, nil
	}

	var host string
	var remotePath string
	if strings.Contains(raw, "://") {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", false, fmt.Errorf(
				"parse GitHub remote: %w",
				parseErr,
			)
		}
		if parsed.Scheme == "file" {
			return "", "", false, nil
		}
		host = parsed.Hostname()
		remotePath = parsed.Path
	} else {
		colon := strings.IndexByte(raw, ':')
		if colon < 1 {
			return "", "", false, nil
		}
		host = raw[:colon]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		remotePath = raw[colon+1:]
	}
	if !isGitHubRemoteHost(host) {
		return "", "", false, nil
	}

	segments := strings.Split(strings.Trim(remotePath, "/"), "/")
	if len(segments) != 2 {
		return "", "", true, errors.New(
			"GitHub remote must identify exactly one owner and repository",
		)
	}
	owner = segments[0]
	repo = strings.TrimSuffix(segments[1], ".git")
	if err := validateGitHubRemoteComponent("owner", owner, 39); err != nil {
		return "", "", true, err
	}
	if err := validateGitHubRemoteComponent(
		"repository",
		repo,
		100,
	); err != nil {
		return "", "", true, err
	}
	return owner, repo, true, nil
}

func isGitHubRemoteHost(host string) bool {
	return strings.EqualFold(host, "github.com") ||
		strings.EqualFold(host, "ssh.github.com")
}

func validateGitHubRemoteComponent(
	label string,
	value string,
	limit int,
) error {
	if value == "" || len(value) > limit ||
		strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") ||
		strings.HasPrefix(value, "-") ||
		strings.HasSuffix(value, "-") ||
		strings.Contains(value, "..") {
		return fmt.Errorf("GitHub %s is invalid", label)
	}
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' ||
			label == "repository" &&
				(character == '_' || character == '.')
		if !valid {
			return fmt.Errorf("GitHub %s is invalid", label)
		}
	}
	return nil
}

func validatedLocalAuditPath(raw string) (string, bool) {
	if filepath.IsAbs(raw) {
		return raw, true
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "file" {
		return "", false
	}
	return filepath.FromSlash(parsed.Path), true
}
