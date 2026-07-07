package bw

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_MissingFileYieldsDefaults(t *testing.T) {
	c, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.Version != 1 || c.ServerURL != "" {
		t.Fatalf("config = %+v, want zero config with version 1", c)
	}
	if c.PasswordPath() != DefaultMasterPasswordPath {
		t.Errorf("PasswordPath = %q, want default", c.PasswordPath())
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bw.yaml")
	if err := os.WriteFile(p, []byte("server_url: https://vault.example\nmaster_password_path: zuhause/bw/master\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.ServerURL != "https://vault.example" {
		t.Errorf("ServerURL = %q", c.ServerURL)
	}
	if c.PasswordPath() != "zuhause/bw/master" {
		t.Errorf("PasswordPath = %q, want override", c.PasswordPath())
	}
	if c.Version != 1 {
		t.Errorf("Version = %d, want defaulted 1", c.Version)
	}
}

func TestLoadConfig_MalformedYAMLFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bw.yaml")
	if err := os.WriteFile(p, []byte(":\t not yaml ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("want parse error for malformed yaml")
	}
}
