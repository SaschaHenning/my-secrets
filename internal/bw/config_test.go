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

func TestLoadConfig_Organizations(t *testing.T) {
	load := func(body string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "bw.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(p)
	}
	c, err := load("organizations:\n  jasp: { organization_id: org-1, collection_ids: [col-1, col-2] }\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if tg, ok := c.Organizations["jasp"]; !ok || tg.OrganizationID != "org-1" || len(tg.CollectionIDs) != 2 {
		t.Errorf("Organizations[jasp] = %+v, %v", tg, ok)
	}
	for name, body := range map[string]string{
		"no collections":   "organizations:\n  jasp: { organization_id: org-1 }\n",
		"empty collection": "organizations:\n  jasp: { organization_id: org-1, collection_ids: [\"\"] }\n",
		"no organization":  "organizations:\n  jasp: { collection_ids: [col-1] }\n",
		"nested org key":   "organizations:\n  jasp/stage: { organization_id: org-1, collection_ids: [col-1] }\n",
		"misspelled key":   "organisations:\n  jasp: { organization_id: org-1, collection_ids: [col-1] }\n",
		"unknown sub key":  "organizations:\n  jasp: { organization_id: org-1, collection: [col-1] }\n",
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%s: want validation error", name)
		}
	}
}

func TestLoadConfig_EmptyFileYieldsDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bw.yaml")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadConfig(p); err != nil || c.Version != 1 {
		t.Fatalf("LoadConfig(empty) = %+v, %v", c, err)
	}
}
