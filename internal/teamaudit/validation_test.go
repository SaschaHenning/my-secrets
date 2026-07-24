package teamaudit

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateURLCoversSupportedAndUnsafeForms(t *testing.T) {
	t.Parallel()

	valid := []string{
		"/tmp/audit.git",
		"https://example.test/team/audit.git",
		"ssh://git@example.test/team/audit.git",
		"ssh://example.test/team/audit.git",
		"file:///tmp/audit.git",
		"git@example.test:team/audit.git",
		"example.test:team/audit.git",
	}
	for _, raw := range valid {
		if err := ValidateURL(raw); err != nil {
			t.Errorf("ValidateURL(%q): %v", raw, err)
		}
	}

	invalid := []string{
		"",
		" https://example.test/audit.git",
		"--upload-pack=bad",
		"https://example.test/audit.git\nother",
		"/",
		"/tmp/../audit.git",
		"https://example.test/audit.git?token=bad",
		"https://example.test/audit.git#fragment",
		"https://user@example.test/audit.git",
		"https:///audit.git",
		"https://example.test",
		"ssh://git:password@example.test/audit.git",
		"ssh://user@example.test/audit.git",
		"ssh:///audit.git",
		"ssh://example.test",
		"file://host/tmp/audit.git",
		"file://user@/tmp/audit.git",
		"file:///",
		"http://example.test/audit.git",
		"example.test",
		":audit.git",
		"example.test:",
		"example.test:/audit.git",
		"example.test:team audit.git",
		"user@example.test:audit.git",
		"git@:audit.git",
		"bad/host:audit.git",
		"example.test:../audit.git",
	}
	for _, raw := range invalid {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("ValidateURL(%q) accepted unsafe URL", raw)
		}
	}
}

func TestParseGitHubRemoteCoversEveryValidatedForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		remote    string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "scp without username",
			remote:    "github.com:jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "scp with git username",
			remote:    "git@github.com:jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "HTTPS",
			remote:    "https://github.com/jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "SSH URL",
			remote:    "ssh://git@github.com/jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "GitHub SSH endpoint",
			remote:    "ssh://git@ssh.github.com:443/jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "HTTPS FQDN",
			remote:    "https://GITHUB.COM./jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "HTTPS www alias",
			remote:    "https://www.github.com/jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "scp www FQDN alias",
			remote:    "git@WWW.GITHUB.COM.:jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "scp www FQDN alias without username",
			remote:    "WWW.GITHUB.COM.:jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
		{
			name:      "SSH endpoint FQDN",
			remote:    "ssh://git@SSH.GITHUB.COM.:443/jasp/mys-audit.git",
			wantOwner: "jasp",
			wantRepo:  "mys-audit",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := Config{
				Mount:              "jasp-shared",
				URL:                test.remote,
				SigningFingerprint: testFingerprint,
				StorePath:          "/tmp/store",
				PolicyPath:         "/tmp/policy.yaml",
				TeamKeysPath:       "/tmp/store/team-keys.yaml",
				RecipientPath:      "/tmp/store/.gpg-id",
				WorkDir:            "/tmp/audit-work",
				StateDir:           "/tmp/audit-state",
				DeviceIDPath:       "/tmp/device/device.id",
			}
			if err := config.Validate(); err != nil {
				t.Fatalf("test remote is not accepted by Config.Validate: %v", err)
			}
			owner, repo, isGitHub, err := ParseGitHubRemote(test.remote)
			if err != nil {
				t.Fatalf("ParseGitHubRemote(%q): %v", test.remote, err)
			}
			if !isGitHub || owner != test.wantOwner || repo != test.wantRepo {
				t.Fatalf(
					"ParseGitHubRemote(%q) = %q, %q, %v; want %q, %q, true",
					test.remote,
					owner,
					repo,
					isGitHub,
					test.wantOwner,
					test.wantRepo,
				)
			}
		})
	}
}

func TestParseGitHubRemoteFailsClosedForMalformedGitHubTargets(t *testing.T) {
	t.Parallel()

	for _, remote := range []string{
		"https://github.com/jasp/team/mys-audit.git",
		"github.com:jasp/team/mys-audit.git",
		"ssh://git@ssh.github.com:443/jasp",
	} {
		remote := remote
		t.Run(remote, func(t *testing.T) {
			t.Parallel()
			_, _, isGitHub, err := ParseGitHubRemote(remote)
			if !isGitHub || err == nil {
				t.Fatalf(
					"ParseGitHubRemote(%q) = isGitHub %v, error %v; want GitHub error",
					remote,
					isGitHub,
					err,
				)
			}
		})
	}

	owner, repo, isGitHub, err := ParseGitHubRemote(
		"ssh://git@gitlab.example/jasp/mys-audit.git",
	)
	if err != nil || isGitHub || owner != "" || repo != "" {
		t.Fatalf(
			"non-GitHub remote = %q, %q, %v, %v; want empty, empty, false, nil",
			owner,
			repo,
			isGitHub,
			err,
		)
	}

	for _, remote := range []string{
		"https://github.com.evil/jasp/mys-audit.git",
		"https://evilgithub.com/jasp/mys-audit.git",
		"https://github.com../jasp/mys-audit.git",
		"git@github.com.evil:jasp/mys-audit.git",
		"git@evilgithub.com:jasp/mys-audit.git",
		"ssh://git@www.github.com.evil:443/jasp/mys-audit.git",
	} {
		owner, repo, isGitHub, err := ParseGitHubRemote(remote)
		if err != nil || isGitHub || owner != "" || repo != "" {
			t.Errorf(
				"lookalike %q = %q, %q, %v, %v; want empty, empty, false, nil",
				remote,
				owner,
				repo,
				isGitHub,
				err,
			)
		}
	}
}

func TestInputValidationRejectsEveryUnsafeField(t *testing.T) {
	t.Parallel()

	valid := Input{
		EventID:    "11111111-1111-4111-8111-111111111111",
		Path:       "jasp-shared/prod/api",
		Action:     "get",
		ActorKind:  "ai",
		AgentLabel: "codex",
	}
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{"identifier", func(input *Input) { input.EventID = "not-a-uuid" }},
		{"path", func(input *Input) { input.Path = "../outside" }},
		{"action", func(input *Input) { input.Action = "GET" }},
		{"actor", func(input *Input) { input.ActorKind = "unknown" }},
		{"agent label", func(input *Input) { input.AgentLabel = "bad\nlabel" }},
		{"AI label", func(input *Input) { input.AgentLabel = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if err := input.validate("jasp-shared"); err == nil {
				t.Fatal("unsafe input was accepted")
			}
		})
	}
	if err := valid.validate("jasp-shared"); err != nil {
		t.Fatalf("valid input: %v", err)
	}
	valid.ActorKind = "human"
	valid.AgentLabel = ""
	if err := valid.validate("jasp-shared"); err != nil {
		t.Fatalf("human input without label: %v", err)
	}
}

func TestEventValidationRejectsEveryInvalidSignedField(t *testing.T) {
	t.Parallel()

	valid := testEvent()
	valid.RowHash = computeRowHash(valid)
	valid.Signature = "c2lnbmF0dXJl"
	tests := []struct {
		name             string
		requireSignature bool
		mutate           func(*Event)
	}{
		{"schema", true, func(event *Event) { event.SchemaVersion = 2 }},
		{"identifier", true, func(event *Event) { event.EventID = "bad" }},
		{"sequence", true, func(event *Event) { event.Seq = 0 }},
		{"timestamp", true, func(event *Event) { event.Timestamp = "yesterday" }},
		{"mount", true, func(event *Event) { event.Mount = "../shared" }},
		{"path", true, func(event *Event) { event.Path = "outside/secret" }},
		{"action", true, func(event *Event) { event.Action = "GET" }},
		{"actor", true, func(event *Event) { event.Actor.Kind = "unknown" }},
		{"agent label", true, func(event *Event) {
			event.Actor.AgentLabel = "bad\nlabel"
		}},
		{"AI label", true, func(event *Event) { event.Actor.AgentLabel = "" }},
		{"host", true, func(event *Event) { event.Host = "" }},
		{"device", true, func(event *Event) { event.DeviceID = "bad" }},
		{"result", true, func(event *Event) { event.Result = "failure" }},
		{"fingerprint", true, func(event *Event) {
			event.SignerFingerprint = strings.ToLower(testFingerprint)
		}},
		{"signer name", true, func(event *Event) { event.SignerName = "" }},
		{"signer email", true, func(event *Event) { event.SignerEmail = "bad" }},
		{"store commit", true, func(event *Event) { event.StoreCommit = "bad" }},
		{"policy hash", true, func(event *Event) { event.PolicyHash = "bad" }},
		{"team key hash", true, func(event *Event) { event.TeamKeysHash = "bad" }},
		{"recipient hash", true, func(event *Event) {
			event.RecipientSetHash = "bad"
		}},
		{"previous hash", true, func(event *Event) { event.PrevHash = "bad" }},
		{"row hash", true, func(event *Event) { event.RowHash = "bad" }},
		{"missing signature", true, func(event *Event) { event.Signature = "" }},
		{"oversized signature", false, func(event *Event) {
			event.Signature = strings.Repeat("x", maxEventLineBytes/2+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := valid
			test.mutate(&event)
			if err := event.validate(test.requireSignature); err == nil {
				t.Fatal("invalid event was accepted")
			}
		})
	}
	if err := valid.validate(true); err != nil {
		t.Fatalf("valid signed event: %v", err)
	}
}

func TestAppendBatchRejectsInvalidContractsBeforeIO(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := filepath.Join(root, "store")
	config := Config{
		Mount:              "jasp-shared",
		URL:                filepath.Join(root, "audit.git"),
		SigningFingerprint: testFingerprint,
		StorePath:          store,
		PolicyPath:         filepath.Join(root, "policy.yaml"),
		TeamKeysPath:       filepath.Join(store, "team-keys.yaml"),
		RecipientPath:      filepath.Join(store, ".gpg-id"),
		WorkDir:            filepath.Join(root, "work"),
		StateDir:           filepath.Join(root, "state"),
		DeviceIDPath:       filepath.Join(root, "device", "device.id"),
	}
	manager, err := NewManager(config, nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	snapshot := Snapshot{
		StoreCommit:      strings.Repeat("a", 40),
		PolicyHash:       strings.Repeat("b", 64),
		TeamKeysHash:     strings.Repeat("c", 64),
		RecipientSetHash: strings.Repeat("d", 64),
	}
	validInput := Input{
		EventID:   "11111111-1111-4111-8111-111111111111",
		Path:      "jasp-shared/prod/api",
		Action:    "get",
		ActorKind: "human",
	}
	if _, err := manager.AppendBatch(context.Background(), snapshot, nil); err == nil {
		t.Fatal("empty batch was accepted")
	}
	if _, err := manager.AppendBatch(
		context.Background(),
		snapshot,
		make([]Input, 1_001),
	); err == nil {
		t.Fatal("oversized batch was accepted")
	}
	invalidSnapshot := snapshot
	invalidSnapshot.PolicyHash = "bad"
	if _, err := manager.AppendBatch(
		context.Background(),
		invalidSnapshot,
		[]Input{validInput},
	); err == nil {
		t.Fatal("invalid snapshot was accepted")
	}
	invalidInput := validInput
	invalidInput.EventID = ""
	if _, err := manager.AppendBatch(
		context.Background(),
		snapshot,
		[]Input{invalidInput},
	); err == nil {
		t.Fatal("invalid input was accepted")
	}
	if _, err := manager.AppendBatch(
		context.Background(),
		snapshot,
		[]Input{validInput, validInput},
	); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate event ID error = %v", err)
	}
}

func TestUserStateDirectoryUsesValidatedEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	state, err := userStateDirectory()
	if err != nil || state != root {
		t.Fatalf("configured state directory = %q, %v", state, err)
	}
	t.Setenv("XDG_STATE_HOME", "relative")
	if _, err := userStateDirectory(); err == nil {
		t.Fatal("relative XDG_STATE_HOME was accepted")
	}
	t.Setenv("XDG_STATE_HOME", "")
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	state, err = userStateDirectory()
	if err != nil || state != filepath.Join(home, ".local", "state") {
		t.Fatalf("fallback state directory = %q, %v", state, err)
	}
}

func TestExecRunnerUsesDirectCommandsAndSanitizesFailures(t *testing.T) {
	runner := ExecRunner{}
	output, err := runner.Run(context.Background(), "git", "--version")
	if err != nil || !strings.HasPrefix(string(output), "git version ") {
		t.Fatalf("git version output = %q, %v", output, err)
	}
	_, err = runner.Run(
		context.Background(),
		"definitely-not-a-real-team-audit-command",
	)
	if err == nil {
		t.Fatal("missing command succeeded")
	}
	if !strings.Contains(
		err.Error(),
		"definitely-not-a-real-team-audit-command failed",
	) {
		t.Fatalf("runner error = %v", err)
	}
}

func TestWireHelpersRejectSizeAndMarshalErrors(t *testing.T) {
	if _, err := parseEventLine(nil); err == nil {
		t.Fatal("empty event line was accepted")
	}
	if _, err := parseEventLine(make([]byte, maxEventLineBytes+1)); err == nil {
		t.Fatal("oversized event line was accepted")
	}

	event := testEvent()
	event.Host = strings.Repeat("x", maxEventLineBytes+1)
	if _, err := canonicalBytes(event); err == nil {
		t.Fatal("oversized canonical field was accepted")
	}
	if hash := computeRowHash(event); hash != "" {
		t.Fatalf("oversized event hash = %q", hash)
	}

	valid := testEvent()
	valid.RowHash = computeRowHash(valid)
	valid.Signature = "c2lnbmF0dXJl"
	data, err := marshalEventLog([]Event{valid})
	if err != nil || !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("marshal valid event = %q, %v", data, err)
	}
	valid.Action = "BAD"
	if _, err := marshalEventLog([]Event{valid}); err == nil {
		t.Fatal("invalid event log was marshaled")
	}
}
