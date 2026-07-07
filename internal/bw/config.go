package bw

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultMasterPasswordPath is the store path the Bitwarden master
// password is read from when the config file does not override it.
const DefaultMasterPasswordPath = "private/bitwarden/master-password"

// Config is the persisted Bitwarden mirror configuration,
// ~/.config/my-secrets/bw.yaml. Both keys are optional.
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
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse bw config: %w", err)
	}
	if c.Version == 0 {
		c.Version = 1
	}
	return &c, nil
}
