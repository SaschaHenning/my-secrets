package bw

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultMasterPasswordPath is the store path the Bitwarden master
// password is read from when the config file does not override it.
const DefaultMasterPasswordPath = "private/bitwarden/master-password"

// Config is the persisted Bitwarden mirror configuration,
// ~/.config/my-secrets/bw.yaml. Every key is optional.
type Config struct {
	Version int `yaml:"version"`
	// ServerURL pins the expected Bitwarden server. When set, push
	// refuses to run against a bw CLI that is configured for any other
	// server — a wrong-server mirror would leak the store to the wrong
	// vault.
	ServerURL string `yaml:"server_url,omitempty"`
	// MasterPasswordPath is the store path of the Bitwarden master
	// password. Empty means DefaultMasterPasswordPath.
	MasterPasswordPath string `yaml:"master_password_path,omitempty"`
	// Organizations maps a mys org (top-level store prefix) to the
	// Bitwarden organization and collections its mirror items belong
	// in. Orgs without an entry stay in the personal vault.
	Organizations map[string]OrgTarget `yaml:"organizations,omitempty"`
	// ExcludePaths are store paths that already live in Bitwarden as a
	// hand-made item; mirroring them would put a second copy next to it.
	ExcludePaths []string `yaml:"exclude_paths,omitempty"`
}

// Excluded reports whether path is listed in exclude_paths.
func (c *Config) Excluded(path string) bool {
	for _, p := range c.ExcludePaths {
		if p == path {
			return true
		}
	}
	return false
}

// OrgTarget is the Bitwarden organization placement for one mys org.
type OrgTarget struct {
	OrganizationID string   `yaml:"organization_id"`
	CollectionIDs  []string `yaml:"collection_ids"`
}

func (c *Config) validate() error {
	for org, t := range c.Organizations {
		if org == "" || strings.Contains(org, "/") {
			return fmt.Errorf("bw config: organizations key %q must be a top-level org name", org)
		}
		if t.OrganizationID == "" {
			return fmt.Errorf("bw config: organizations.%s.organization_id is empty", org)
		}
		// bw move rejects an empty collection list, and an org item in no
		// collection is invisible to every teammate without admin rights.
		if len(t.CollectionIDs) == 0 {
			return fmt.Errorf("bw config: organizations.%s.collection_ids needs at least one id", org)
		}
		for _, id := range t.CollectionIDs {
			if id == "" {
				return fmt.Errorf("bw config: organizations.%s.collection_ids contains an empty id", org)
			}
		}
	}
	return nil
}

// PasswordPath returns the configured master-password store path or the
// default.
func (c *Config) PasswordPath() string {
	if c.MasterPasswordPath != "" {
		return c.MasterPasswordPath
	}
	return DefaultMasterPasswordPath
}

// DefaultConfigPath returns ~/.config/my-secrets/bw.yaml.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "my-secrets", "bw.yaml"), nil
}

// LoadConfig reads the config file. A missing file yields the zero
// config (defaults apply) — the mirror works without any setup beyond
// `bw login` and the master-password store entry.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Version: 1}, nil
		}
		return nil, fmt.Errorf("read bw config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	// A typo like "organisations" would otherwise silently push a team
	// org into the personal vault.
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse bw config: %w", err)
	}
	if c.Version == 0 {
		c.Version = 1
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
