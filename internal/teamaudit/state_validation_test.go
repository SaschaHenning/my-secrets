package teamaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateFileHelpersRejectUnsafeFilesystemObjects(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular.txt")
	if err := os.WriteFile(regular, []byte("value"), 0o644); err != nil {
		t.Fatalf("write regular fixture: %v", err)
	}
	data, err := readLimitedRegularFile(regular, 5)
	if err != nil || string(data) != "value" {
		t.Fatalf("read regular file = %q, %v", data, err)
	}
	if _, err := readLimitedRegularFile(regular, 4); err == nil {
		t.Fatal("oversized regular file was accepted")
	}
	if _, err := readLimitedRegularFile(root, 100); err == nil {
		t.Fatal("directory was accepted as a regular file")
	}
	if _, err := readLimitedRegularFile(
		filepath.Join(root, "missing"),
		100,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
	symlink := filepath.Join(root, "regular-link")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatalf("create symlink fixture: %v", err)
	}
	if _, err := readLimitedRegularFile(symlink, 100); err == nil {
		t.Fatal("symlink was accepted as a regular file")
	}

	privateDirectory := filepath.Join(root, "private", "nested")
	if err := ensurePrivateDirectory(privateDirectory); err != nil {
		t.Fatalf("ensure private directory: %v", err)
	}
	info, err := os.Stat(privateDirectory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory mode = %#o, %v", info.Mode().Perm(), err)
	}
	if err := ensurePrivateDirectory(regular); err == nil {
		t.Fatal("regular file was accepted as a private directory")
	}
	if err := ensurePrivateDirectory(symlink); err == nil {
		t.Fatal("symlink was accepted as a private directory")
	}
	if err := ensureDirectory(filepath.Join(root, "ordinary")); err != nil {
		t.Fatalf("ensure directory: %v", err)
	}
	if err := ensureDirectory(regular); err == nil {
		t.Fatal("regular file was accepted as a directory")
	}
	if err := ensureDirectory(symlink); err == nil {
		t.Fatal("symlink was accepted as a directory")
	}

	exclusive := filepath.Join(root, "exclusive.txt")
	if err := writeFileExclusive(exclusive, []byte("first"), 0o600); err != nil {
		t.Fatalf("write exclusive file: %v", err)
	}
	if err := writeFileExclusive(exclusive, []byte("second"), 0o600); err == nil {
		t.Fatal("exclusive write replaced an existing file")
	}
	atomic := filepath.Join(root, "atomic", "state.json")
	if err := atomicWriteFile(atomic, []byte("one"), 0o600); err != nil {
		t.Fatalf("first atomic write: %v", err)
	}
	if err := atomicWriteFile(atomic, []byte("two"), 0o600); err != nil {
		t.Fatalf("second atomic write: %v", err)
	}
	if data, err := os.ReadFile(atomic); err != nil || string(data) != "two" {
		t.Fatalf("atomic data = %q, %v", data, err)
	}
}

func TestWatermarkStateRejectsMalformedOrUnsafeData(t *testing.T) {
	root := t.TempDir()
	manager := &Manager{config: Config{StateDir: root}}
	state, err := manager.loadWatermarks()
	if err != nil || state.Version != schemaVersion || len(state.Branches) != 0 {
		t.Fatalf("missing watermark state = %#v, %v", state, err)
	}
	valid := watermarkFile{
		Version: schemaVersion,
		Branches: map[string]watermark{
			"audit/v1/shared/signer/device": {
				OID:     strings.Repeat("a", 40),
				Count:   1,
				RowHash: strings.Repeat("b", 64),
			},
		},
	}
	if err := manager.saveWatermarks(valid); err != nil {
		t.Fatalf("save watermarks: %v", err)
	}
	loaded, err := manager.loadWatermarks()
	if err != nil || loaded.Branches["audit/v1/shared/signer/device"].Count != 1 {
		t.Fatalf("loaded watermarks = %#v, %v", loaded, err)
	}

	path := filepath.Join(root, watermarkFilename)
	invalid := [][]byte{
		[]byte(`{"version":1,"version":1,"branches":{}}`),
		[]byte(`{"version":1,"branches":{},"unknown":true}`),
		[]byte(`{"version":2,"branches":{}}`),
		[]byte(`{"version":1,"branches":null}`),
		[]byte(`{"version":1,"branches":{"bad":{"oid":"x","count":0,"row_hash":"x"}}}`),
		[]byte(`not-json`),
	}
	for index, data := range invalid {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write invalid watermark %d: %v", index, err)
		}
		if _, err := manager.loadWatermarks(); err == nil {
			t.Errorf("invalid watermark %d was accepted", index)
		}
	}
}

func TestRecipientAndMetadataValidationErrorPaths(t *testing.T) {
	validData := []byte(
		"# team\n" +
			"9999999999999999999999999999999999999999\n" +
			testFingerprint + "\n",
	)
	recipients, err := parseRecipientSet(validData)
	if err != nil || len(recipients) != 2 || recipients[0] != testFingerprint {
		t.Fatalf("recipients = %#v, %v", recipients, err)
	}
	hash, err := hashRecipientData(validData)
	if err != nil || len(hash) != 64 {
		t.Fatalf("recipient hash = %q, %v", hash, err)
	}
	for name, data := range map[string][]byte{
		"empty":     []byte("# no recipients\n"),
		"invalid":   []byte("not-a-fingerprint\n"),
		"duplicate": []byte(testFingerprint + "\n" + testFingerprint + "\n"),
		"too long":  []byte(strings.Repeat("A", maxEventLineBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRecipientSet(data); err == nil {
				t.Fatal("invalid recipient data was accepted")
			}
		})
	}

	root := t.TempDir()
	store := filepath.Join(root, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	teamPath := filepath.Join(store, "team-keys.yaml")
	recipientPath := filepath.Join(store, ".gpg-id")
	for _, path := range []string{teamPath, recipientPath} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatalf("write metadata fixture: %v", err)
		}
	}
	if err := validateStoreMetadataPaths(
		store,
		teamPath,
		recipientPath,
	); err != nil {
		t.Fatalf("valid metadata paths: %v", err)
	}
	if err := validateStoreMetadataPaths(
		store,
		filepath.Join(root, "outside"),
	); err == nil {
		t.Fatal("outside metadata path was accepted")
	}
	linkPath := filepath.Join(store, "metadata-link")
	if err := os.Symlink(teamPath, linkPath); err != nil {
		t.Fatalf("create metadata symlink: %v", err)
	}
	if err := validateStoreMetadataPaths(store, linkPath); err == nil {
		t.Fatal("metadata symlink was accepted")
	}
	if err := validateStoreMetadataPaths(teamPath, recipientPath); err == nil {
		t.Fatal("regular file was accepted as a store directory")
	}
}

func TestOrderingAndJSONTrailerBranches(t *testing.T) {
	base := VerifiedEvent{Event: testEvent(), Branch: "branch-b"}
	base.Timestamp = "2026-07-24T12:34:56.000000000Z"
	tests := []VerifiedEvent{
		func() VerifiedEvent {
			event := base
			event.Timestamp = "2026-07-24T12:34:55.000000000Z"
			return event
		}(),
		func() VerifiedEvent {
			event := base
			event.SignerFingerprint = "0000000000000000000000000000000000000000"
			return event
		}(),
		func() VerifiedEvent {
			event := base
			event.DeviceID = "00000000-0000-4000-8000-000000000000"
			return event
		}(),
		func() VerifiedEvent {
			event := base
			event.Seq = 0
			return event
		}(),
		func() VerifiedEvent {
			event := base
			event.EventID = "00000000-0000-4000-8000-000000000000"
			return event
		}(),
		func() VerifiedEvent {
			event := base
			event.Branch = "branch-a"
			return event
		}(),
	}
	for index, candidate := range tests {
		if !verifiedEventLess(candidate, base) {
			t.Errorf("ordering candidate %d was not less than base", index)
		}
	}

	if err := rejectDuplicateJSONFields(
		[]byte(`[{"first":1},{"second":[true,false]}]`),
	); err != nil {
		t.Fatalf("valid nested JSON array: %v", err)
	}
	if err := rejectDuplicateJSONFields([]byte(`[1`)); err == nil {
		t.Fatal("unterminated JSON array was accepted")
	}
	decoder := json.NewDecoder(bytes.NewBufferString("1 2"))
	if _, err := decoder.Token(); err != nil {
		t.Fatalf("read first JSON token: %v", err)
	}
	if err := ensureJSONEOF(decoder); err == nil {
		t.Fatal("JSON trailer was accepted")
	}
}

func TestSmallValidationHelpers(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("non-fast-forward"),
		errors.New("fetch first"),
		errors.New("[rejected]"),
		errors.New("other"),
	} {
		got := isNonFastForward(err)
		want := err != nil && err.Error() != "other"
		if got != want {
			t.Errorf("isNonFastForward(%v) = %t, want %t", err, got, want)
		}
	}
	for _, value := range []string{"origin", "team_remote-1", "remote.example"} {
		if !validGitRemoteName(value) {
			t.Errorf("valid remote name %q rejected", value)
		}
	}
	for _, value := range []string{"", ".", "-bad", "bad/name", "bad:name", "bad name"} {
		if validGitRemoteName(value) {
			t.Errorf("invalid remote name %q accepted", value)
		}
	}
	if got := watermarkFor(remoteBranch{}, nil); got != (watermark{}) {
		t.Fatalf("empty watermark = %#v", got)
	}
}

func TestDefaultConfigAndBranchParsingRejectInvalidContracts(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	remote := filepath.Join(root, "audit.git")
	for name, arguments := range map[string][4]string{
		"mount":       {"../shared", remote, testFingerprint, store},
		"URL":         {"shared", "--bad", testFingerprint, store},
		"fingerprint": {"shared", remote, "bad", store},
		"store":       {"shared", remote, testFingerprint, "relative"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DefaultConfig(
				arguments[0],
				arguments[1],
				arguments[2],
				arguments[3],
			); err == nil {
				t.Fatal("invalid default config input was accepted")
			}
		})
	}

	manager := &Manager{config: Config{Mount: "shared"}}
	validOID := strings.Repeat("a", 40)
	validRef := "refs/heads/audit/v1/shared/" + testFingerprint +
		"/11111111-1111-4111-8111-111111111111"
	branch, err := manager.parseBranch(validRef, validOID)
	if err != nil || branch.Name != strings.TrimPrefix(validRef, "refs/heads/") {
		t.Fatalf("valid branch = %#v, %v", branch, err)
	}
	for _, ref := range []string{
		"refs/tags/audit/v1/shared/" + testFingerprint +
			"/11111111-1111-4111-8111-111111111111",
		"refs/heads/audit/v1/other/" + testFingerprint +
			"/11111111-1111-4111-8111-111111111111",
		"refs/heads/audit/v1/shared/BAD/" +
			"11111111-1111-4111-8111-111111111111",
		"refs/heads/audit/v1/shared/" + testFingerprint + "/bad",
	} {
		if _, err := manager.parseBranch(ref, validOID); err == nil {
			t.Errorf("invalid branch %q was accepted", ref)
		}
	}
}
