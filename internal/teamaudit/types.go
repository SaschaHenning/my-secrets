// Package teamaudit stores tamper-evident, per-device audit chains for reads
// from shared my-secrets mounts.
package teamaudit

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const (
	schemaVersion = 1
	zeroHash      = "0000000000000000000000000000000000000000000000000000000000000000"

	maxEventLineBytes = 1 << 20
	maxAuditLogBytes  = 32 << 20
	maxAuditEvents    = 100_000
)

var (
	fingerprintPattern = regexp.MustCompile(`^[0-9A-F]{40}$`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$`)
	actionPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	actorPattern       = regexp.MustCompile(`^(?:human|ai|script)$`)
)

// Actor records the caller category and optional stable agent label.
type Actor struct {
	Kind       string `json:"kind"`
	AgentLabel string `json:"agent_label,omitempty"`
}

// Input contains only the non-secret attribution needed to append a read.
// EventID is caller-generated so retries remain idempotent across processes.
type Input struct {
	EventID    string
	Path       string
	Action     string
	ActorKind  string
	AgentLabel string
}

// Event is the strict version-1 NDJSON wire record. SignerName and
// SignerEmail are historical identity facts protected by the signature.
type Event struct {
	SchemaVersion     int    `json:"schema_version"`
	EventID           string `json:"event_id"`
	Seq               uint64 `json:"seq"`
	Timestamp         string `json:"ts"`
	Mount             string `json:"mount"`
	Path              string `json:"path"`
	Action            string `json:"action"`
	Actor             Actor  `json:"actor"`
	Host              string `json:"host"`
	DeviceID          string `json:"device_id"`
	Result            string `json:"result"`
	SignerFingerprint string `json:"signer_fingerprint"`
	SignerName        string `json:"signer_name"`
	SignerEmail       string `json:"signer_email"`
	StoreCommit       string `json:"store_commit"`
	PolicyHash        string `json:"policy_hash"`
	TeamKeysHash      string `json:"team_keys_hash"`
	RecipientSetHash  string `json:"recipient_set_hash"`
	PrevHash          string `json:"prev_hash"`
	RowHash           string `json:"row_hash"`
	Signature         string `json:"signature"`
}

// VerifiedEvent adds the source Git branch and confirmed remote commit to a
// cryptographically verified event.
type VerifiedEvent struct {
	Event
	Branch string
	Commit string
}

// Snapshot binds an event to the exact shared-store and policy inputs read
// immediately before the append operation.
type Snapshot struct {
	StoreCommit      string
	PolicyHash       string
	TeamKeysHash     string
	RecipientSetHash string
}

// VerifyReport summarizes a complete repository verification.
type VerifyReport struct {
	Branches int
	Events   int
}

func (input Input) validate(mount string) error {
	if err := validateEventID(input.EventID); err != nil {
		return errors.New("event ID must be a canonical UUID")
	}
	if err := validateSecretPath(mount, input.Path); err != nil {
		return err
	}
	if !actionPattern.MatchString(input.Action) {
		return errors.New("audit action is invalid")
	}
	if !actorPattern.MatchString(input.ActorKind) {
		return errors.New("audit actor kind is invalid")
	}
	if err := validateText("agent label", input.AgentLabel, 128, true); err != nil {
		return err
	}
	if input.ActorKind == "ai" && input.AgentLabel == "" {
		return errors.New("AI audit actor requires an agent label")
	}
	return nil
}

func (snapshot Snapshot) validate() error {
	if !commitPattern.MatchString(snapshot.StoreCommit) ||
		snapshot.StoreCommit != strings.ToLower(snapshot.StoreCommit) {
		return errors.New("audit snapshot store commit is invalid")
	}
	for label, value := range map[string]string{
		"policy hash":        snapshot.PolicyHash,
		"team keys hash":     snapshot.TeamKeysHash,
		"recipient set hash": snapshot.RecipientSetHash,
	} {
		if !hashPattern.MatchString(value) {
			return fmt.Errorf("audit snapshot %s is invalid", label)
		}
	}
	return nil
}

func snapshotMatchesEvent(snapshot Snapshot, event Event) bool {
	return event.StoreCommit == snapshot.StoreCommit &&
		event.PolicyHash == snapshot.PolicyHash &&
		event.TeamKeysHash == snapshot.TeamKeysHash &&
		event.RecipientSetHash == snapshot.RecipientSetHash
}

func (event Event) validate(requireSignature bool) error {
	if event.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported audit schema version %d", event.SchemaVersion)
	}
	if err := validateEventID(event.EventID); err != nil {
		return err
	}
	if event.Seq == 0 {
		return errors.New("audit sequence must be positive")
	}
	if err := validateTimestamp(event.Timestamp); err != nil {
		return err
	}
	if err := validateMount(event.Mount); err != nil {
		return err
	}
	if err := validateSecretPath(event.Mount, event.Path); err != nil {
		return err
	}
	if !actionPattern.MatchString(event.Action) {
		return errors.New("audit action is invalid")
	}
	if !actorPattern.MatchString(event.Actor.Kind) {
		return errors.New("audit actor kind is invalid")
	}
	if err := validateText("agent label", event.Actor.AgentLabel, 128, true); err != nil {
		return err
	}
	if event.Actor.Kind == "ai" && event.Actor.AgentLabel == "" {
		return errors.New("AI audit actor requires an agent label")
	}
	if err := validateText("host", event.Host, 255, false); err != nil {
		return err
	}
	if err := validateEventID(event.DeviceID); err != nil {
		return fmt.Errorf("invalid audit device ID: %w", err)
	}
	if event.Result != "success" {
		return errors.New("team audit records only successful reads")
	}
	fingerprint, err := normalizeFingerprint(event.SignerFingerprint)
	if err != nil || fingerprint != event.SignerFingerprint {
		return errors.New("audit signer fingerprint is invalid")
	}
	if err := validateText("signer name", event.SignerName, 200, false); err != nil {
		return err
	}
	if err := validateEmail(event.SignerEmail); err != nil {
		return err
	}
	if !commitPattern.MatchString(event.StoreCommit) {
		return errors.New("audit store commit is invalid")
	}
	for label, value := range map[string]string{
		"policy hash":        event.PolicyHash,
		"team keys hash":     event.TeamKeysHash,
		"recipient set hash": event.RecipientSetHash,
		"previous hash":      event.PrevHash,
		"row hash":           event.RowHash,
	} {
		if !hashPattern.MatchString(value) {
			return fmt.Errorf("audit %s is invalid", label)
		}
	}
	if requireSignature && event.Signature == "" {
		return errors.New("audit signature is required")
	}
	if len(event.Signature) > maxEventLineBytes/2 {
		return errors.New("audit signature is too large")
	}
	return nil
}

func canonicalBytes(event Event) ([]byte, error) {
	fields := []string{
		strconv.Itoa(event.SchemaVersion),
		event.EventID,
		strconv.FormatUint(event.Seq, 10),
		event.Timestamp,
		event.Mount,
		event.Path,
		event.Action,
		event.Actor.Kind,
		event.Actor.AgentLabel,
		event.Host,
		event.DeviceID,
		event.Result,
		event.SignerFingerprint,
		event.SignerName,
		event.SignerEmail,
		event.StoreCommit,
		event.PolicyHash,
		event.TeamKeysHash,
		event.RecipientSetHash,
		event.PrevHash,
	}
	var buffer bytes.Buffer
	buffer.WriteString("mys-team-audit-event\x00v1\x00")
	if err := binary.Write(&buffer, binary.BigEndian, uint32(len(fields))); err != nil {
		return nil, fmt.Errorf("encode audit field count: %w", err)
	}
	for _, field := range fields {
		if len(field) > maxEventLineBytes {
			return nil, errors.New("audit canonical field is too large")
		}
		if err := binary.Write(
			&buffer,
			binary.BigEndian,
			uint32(len(field)),
		); err != nil {
			return nil, fmt.Errorf("encode audit field length: %w", err)
		}
		buffer.WriteString(field)
	}
	return buffer.Bytes(), nil
}

func computeRowHash(event Event) string {
	canonical, err := canonicalBytes(event)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func verifyRowHash(event Event) error {
	expected := computeRowHash(event)
	if expected == "" ||
		subtle.ConstantTimeCompare([]byte(expected), []byte(event.RowHash)) != 1 {
		return errors.New("audit row hash mismatch")
	}
	return nil
}

func parseEventLine(data []byte) (Event, error) {
	if len(data) == 0 || len(data) > maxEventLineBytes {
		return Event{}, errors.New("audit event line size is invalid")
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return Event{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var event Event
	if err := decoder.Decode(&event); err != nil {
		return Event{}, fmt.Errorf("decode audit event: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Event{}, err
	}
	if err := event.validate(false); err != nil {
		return Event{}, err
	}
	return event, nil
}

func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode audit JSON token: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode audit JSON key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("audit JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate audit JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("audit JSON object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("audit JSON array is not terminated")
		}
	default:
		return errors.New("invalid audit JSON delimiter")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("audit JSON has trailing data")
		}
		return fmt.Errorf("decode audit JSON trailer: %w", err)
	}
	return nil
}

func normalizeFingerprint(raw string) (string, error) {
	fingerprint := strings.ToUpper(strings.TrimSpace(raw))
	if !fingerprintPattern.MatchString(fingerprint) {
		return "", errors.New("fingerprint must contain 40 hexadecimal characters")
	}
	return fingerprint, nil
}

func validateMount(mount string) error {
	if mount == "" || len(mount) > 64 || strings.TrimSpace(mount) != mount {
		return errors.New("audit mount name is invalid")
	}
	for index, character := range mount {
		valid := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '-' || character == '_' || character == '.')
		if !valid {
			return errors.New("audit mount name is invalid")
		}
	}
	if strings.Contains(mount, "..") || strings.HasSuffix(mount, ".") ||
		strings.HasSuffix(strings.ToLower(mount), ".lock") {
		return errors.New("audit mount name is not safe for a Git ref")
	}
	return nil
}

func validateEventID(raw string) error {
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed.String() != strings.ToLower(raw) {
		return errors.New("audit identifier must be a canonical UUID")
	}
	return nil
}

func validateTimestamp(raw string) error {
	if len(raw) != len("2006-01-02T15:04:05.000000000Z") ||
		!strings.HasSuffix(raw, "Z") {
		return errors.New("audit timestamp must use UTC RFC3339 nanoseconds")
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000000Z", raw); err != nil {
		return errors.New("audit timestamp must use UTC RFC3339 nanoseconds")
	}
	return nil
}

func validateSecretPath(mount, secretPath string) error {
	if secretPath == "" || len(secretPath) > 1024 ||
		strings.TrimSpace(secretPath) != secretPath ||
		strings.Contains(secretPath, "\\") || containsControl(secretPath) ||
		strings.HasPrefix(secretPath, "/") {
		return errors.New("audit secret path is invalid")
	}
	if secretPath != filepath.ToSlash(filepath.Clean(secretPath)) ||
		!strings.HasPrefix(secretPath, mount+"/") {
		return errors.New("audit secret path is outside the configured mount")
	}
	for _, part := range strings.Split(secretPath, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("audit secret path contains an invalid segment")
		}
	}
	return nil
}

func validateText(label, value string, limit int, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > limit ||
		strings.TrimSpace(value) != value ||
		containsControl(value) {
		return fmt.Errorf("audit %s is invalid", label)
	}
	return nil
}

func validateEmail(value string) error {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, " <>") || containsControl(value) ||
		strings.Count(value, "@") != 1 {
		return errors.New("audit signer email is invalid")
	}
	return nil
}

func validateAbsoluteCleanPath(label, value string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		value == string(filepath.Separator) || containsControl(value) {
		return fmt.Errorf("%s must be a clean absolute non-root path", label)
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
