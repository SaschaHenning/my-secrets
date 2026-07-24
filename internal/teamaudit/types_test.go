package teamaudit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testFingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"

func TestConfigValidateRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	valid := Config{
		Mount:              "jasp-shared",
		URL:                "/tmp/audit.git",
		SigningFingerprint: testFingerprint,
		StorePath:          "/tmp/store",
		PolicyPath:         "/tmp/store/policy.yaml",
		TeamKeysPath:       "/tmp/store/team-keys.yaml",
		RecipientPath:      "/tmp/store/.gpg-id",
		WorkDir:            "/tmp/audit-work",
		StateDir:           "/tmp/audit-state",
		DeviceIDPath:       "/tmp/audit-state/device-id",
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "mount traversal",
			mutate: func(config *Config) {
				config.Mount = "../jasp"
			},
		},
		{
			name: "remote option injection",
			mutate: func(config *Config) {
				config.URL = "--upload-pack=evil"
			},
		},
		{
			name: "remote credentials",
			mutate: func(config *Config) {
				config.URL = "https://token@example.test/audit.git"
			},
		},
		{
			name: "short fingerprint",
			mutate: func(config *Config) {
				config.SigningFingerprint = "DEADBEEF"
			},
		},
		{
			name: "relative work directory",
			mutate: func(config *Config) {
				config.WorkDir = "audit-work"
			},
		},
		{
			name: "team keys outside store",
			mutate: func(config *Config) {
				config.TeamKeysPath = "/tmp/other/team-keys.yaml"
			},
		},
		{
			name: "audit work inside store",
			mutate: func(config *Config) {
				config.WorkDir = "/tmp/store/audit-work"
			},
		},
		{
			name: "local remote inside state",
			mutate: func(config *Config) {
				config.URL = "/tmp/audit-state/remote.git"
			},
		},
		{
			name: "file remote inside store",
			mutate: func(config *Config) {
				config.URL = "file:///tmp/store/audit.git"
			},
		},
		{
			name: "file remote overlaps policy",
			mutate: func(config *Config) {
				config.PolicyPath = "/tmp/my-secrets-config/shared-policy.yaml"
				config.URL = "file:///tmp/my-secrets-config/shared-policy.yaml"
			},
		},
		{
			name: "file remote is filesystem root",
			mutate: func(config *Config) {
				config.URL = "file:///"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() succeeded for unsafe config")
			}
		})
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	valid.PolicyPath = "/tmp/my-secrets-config/shared-policies/jasp-shared.yaml"
	valid.DeviceIDPath = "/tmp/my-secrets-config/team-audit/device.id"
	if err := valid.Validate(); err != nil {
		t.Fatalf("separate policy and device config paths: %v", err)
	}
}

func TestDefaultConfigUsesSeparateConfigCacheAndStateBases(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configBase := filepath.Join(root, "config")
	cacheBase := filepath.Join(root, "cache")
	stateBase := filepath.Join(root, "state")
	for _, directory := range []string{home, configBase, cacheBase, stateBase} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configBase)
	t.Setenv("XDG_CACHE_HOME", cacheBase)
	t.Setenv("XDG_STATE_HOME", stateBase)

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("UserCacheDir: %v", err)
	}
	storePath := filepath.Join(root, "store")
	config, err := DefaultConfig(
		"jasp-shared",
		filepath.Join(root, "audit.git"),
		strings.ToLower(testFingerprint),
		storePath,
	)
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	if config.PolicyPath != filepath.Join(
		home,
		".config",
		"my-secrets",
		"shared-policies",
		"jasp-shared.yaml",
	) {
		t.Fatalf("policy path = %q", config.PolicyPath)
	}
	if config.WorkDir != filepath.Join(
		cacheDir,
		"my-secrets",
		"team-audit",
		"jasp-shared",
		"repository",
	) {
		t.Fatalf("work directory = %q", config.WorkDir)
	}
	if config.StateDir != filepath.Join(
		stateBase,
		"my-secrets",
		"team-audit",
		"jasp-shared",
	) {
		t.Fatalf("state directory = %q", config.StateDir)
	}
	if config.DeviceIDPath != filepath.Join(
		configDir,
		"my-secrets",
		"team-audit",
		"device.id",
	) {
		t.Fatalf("device ID path = %q", config.DeviceIDPath)
	}
	if config.SigningFingerprint != testFingerprint {
		t.Fatalf("signing fingerprint = %q", config.SigningFingerprint)
	}
}

func TestStrictEventParserRejectsUnknownAndDuplicateFields(t *testing.T) {
	t.Parallel()

	event := testEvent()
	event.RowHash = computeRowHash(event)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	parsed, err := parseEventLine(data)
	if err != nil {
		t.Fatalf("parse valid event: %v", err)
	}
	if parsed.EventID != event.EventID {
		t.Fatalf("event id = %q, want %q", parsed.EventID, event.EventID)
	}

	unknown := append([]byte(nil), data[:len(data)-1]...)
	unknown = append(unknown, []byte(`,"reason":"must-not-exist"}`)...)
	if _, err := parseEventLine(unknown); err == nil ||
		!strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown field error = %v", err)
	}

	duplicate := append([]byte(`{"schema_version":1,`), data[1:]...)
	if _, err := parseEventLine(duplicate); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate field error = %v", err)
	}

	nestedDuplicate := bytes.Replace(
		data,
		[]byte(`"actor":{"kind":"ai"`),
		[]byte(`"actor":{"kind":"ai","kind":"human"`),
		1,
	)
	if _, err := parseEventLine(nestedDuplicate); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("nested duplicate field error = %v", err)
	}
}

func TestCanonicalHashChangesWhenSignedFieldChanges(t *testing.T) {
	t.Parallel()

	event := testEvent()
	firstCanonical, err := canonicalBytes(event)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	firstHash := computeRowHash(event)
	if len(firstHash) != 64 {
		t.Fatalf("row hash length = %d, want 64", len(firstHash))
	}

	event.Path = "jasp-shared/prod/other"
	secondCanonical, err := canonicalBytes(event)
	if err != nil {
		t.Fatalf("changed canonical bytes: %v", err)
	}
	if bytes.Equal(firstCanonical, secondCanonical) {
		t.Fatal("canonical bytes did not change")
	}
	if secondHash := computeRowHash(event); secondHash == firstHash {
		t.Fatal("row hash did not change")
	}
}

func TestAppendInputsRequireCallerOwnedIdentifiersAndSnapshots(t *testing.T) {
	t.Parallel()

	input := Input{
		Path:      "jasp-shared/prod/api",
		Action:    "get",
		ActorKind: "human",
	}
	if err := input.validate("jasp-shared"); err == nil ||
		!strings.Contains(err.Error(), "event ID") {
		t.Fatalf("missing event ID error = %v", err)
	}
	input.EventID = "11111111-1111-4111-8111-111111111111"
	if err := input.validate("jasp-shared"); err != nil {
		t.Fatalf("valid input: %v", err)
	}

	snapshot := Snapshot{
		StoreCommit:      strings.Repeat("a", 40),
		PolicyHash:       strings.Repeat("b", 64),
		TeamKeysHash:     strings.Repeat("c", 64),
		RecipientSetHash: strings.Repeat("d", 64),
	}
	if err := snapshot.validate(); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	snapshot.StoreCommit = strings.ToUpper(snapshot.StoreCommit)
	if err := snapshot.validate(); err == nil {
		t.Fatal("uppercase snapshot store commit was accepted")
	}
}

func TestEventJSONContainsNoSecretMaterialOrProcessContext(t *testing.T) {
	t.Parallel()

	event := testEvent()
	event.RowHash = computeRowHash(event)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	for _, forbidden := range []string{
		"secret_value",
		"super-secret-sentinel",
		`"reason"`,
		`"pid"`,
		`"env"`,
	} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("event JSON contains forbidden material %q: %s", forbidden, data)
		}
	}
}

func testEvent() Event {
	return Event{
		SchemaVersion:     1,
		EventID:           "11111111-1111-4111-8111-111111111111",
		Seq:               1,
		Timestamp:         "2026-07-24T12:34:56.000000000Z",
		Mount:             "jasp-shared",
		Path:              "jasp-shared/prod/api",
		Action:            "get",
		Actor:             Actor{Kind: "ai", AgentLabel: "codex"},
		Host:              "workstation",
		DeviceID:          "22222222-2222-4222-8222-222222222222",
		Result:            "success",
		SignerFingerprint: testFingerprint,
		SignerName:        "Alice Example",
		SignerEmail:       "alice@example.test",
		StoreCommit:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyHash:        strings.Repeat("b", 64),
		TeamKeysHash:      strings.Repeat("c", 64),
		RecipientSetHash:  strings.Repeat("d", 64),
		PrevHash:          strings.Repeat("0", 64),
	}
}
