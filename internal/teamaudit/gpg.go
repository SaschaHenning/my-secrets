package teamaudit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
)

const maxSignatureBytes = 1 << 20

// Runner executes subprocesses without a shell.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner executes subprocesses with deterministic English output.
type ExecRunner struct{}

// Run invokes a command directly with an argv vector and captures its output.
func (ExecRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf(
			"%s failed: %w: %s",
			name,
			err,
			sanitizeCommandOutput(output),
		)
	}
	return output, nil
}

type signerIdentity struct {
	Fingerprint string
	Name        string
	Email       string
}

func (manager *Manager) loadSignerIdentity(
	ctx context.Context,
	snapshot Snapshot,
) (signerIdentity, error) {
	args := manager.gpgArgs(
		"--batch",
		"--with-colons",
		"--fixed-list-mode",
		"--fingerprint",
		"--list-secret-keys",
		manager.config.SigningFingerprint,
	)
	output, err := manager.runner.Run(ctx, "gpg", args...)
	if err != nil {
		return signerIdentity{}, fmt.Errorf("load audit signing key: %w", err)
	}

	var primaryFingerprint string
	expectPrimary := false
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}
		switch fields[0] {
		case "sec":
			if primaryFingerprint != "" {
				return signerIdentity{}, errors.New(
					"audit signing key query returned multiple primary keys",
				)
			}
			expectPrimary = true
		case "fpr":
			if !expectPrimary {
				continue
			}
			fingerprint, normalizeErr := normalizeFingerprint(fields[9])
			if normalizeErr != nil {
				return signerIdentity{}, errors.New(
					"audit signing key returned an invalid primary fingerprint",
				)
			}
			primaryFingerprint = fingerprint
			expectPrimary = false
		}
	}
	if primaryFingerprint == "" ||
		primaryFingerprint != manager.config.SigningFingerprint {
		return signerIdentity{}, errors.New(
			"audit signing key primary fingerprint does not match configuration",
		)
	}
	manifest, err := teamkeys.Load(manager.config.TeamKeysPath)
	if err != nil {
		return signerIdentity{}, fmt.Errorf(
			"load audit signer team membership: %w",
			err,
		)
	}
	member, found := manifest.FindFingerprint(primaryFingerprint)
	if !found {
		return signerIdentity{}, errors.New(
			"audit signing key is not a current team member",
		)
	}
	recipients, err := loadRecipientSet(manager.config.RecipientPath)
	if err != nil {
		return signerIdentity{}, fmt.Errorf("load shared recipients: %w", err)
	}
	if !containsString(recipients, primaryFingerprint) {
		return signerIdentity{}, errors.New(
			"audit signing key is not a current shared-store recipient",
		)
	}
	manifestHash, err := hashRegularFile(manager.config.TeamKeysPath)
	if err != nil || manifestHash != snapshot.TeamKeysHash {
		return signerIdentity{}, errors.New(
			"team key manifest changed during audit preflight",
		)
	}
	recipientHash, err := hashRecipientSet(manager.config.RecipientPath)
	if err != nil || recipientHash != snapshot.RecipientSetHash {
		return signerIdentity{}, errors.New(
			"recipient set changed during audit preflight",
		)
	}
	return signerIdentity{
		Fingerprint: primaryFingerprint,
		Name:        member.Name,
		Email:       member.Email,
	}, nil
}

func (manager *Manager) signEvent(ctx context.Context, event *Event) error {
	if event == nil {
		return errors.New("sign audit event: event is nil")
	}
	event.RowHash = computeRowHash(*event)
	if err := event.validate(false); err != nil {
		return fmt.Errorf("sign audit event: %w", err)
	}
	canonical, err := canonicalBytes(*event)
	if err != nil {
		return fmt.Errorf("sign audit event: %w", err)
	}
	signature, err := manager.detachedSign(ctx, canonical)
	if err != nil {
		return err
	}
	event.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (manager *Manager) verifyEvent(ctx context.Context, event Event) error {
	if err := event.validate(true); err != nil {
		return fmt.Errorf("verify audit event: %w", err)
	}
	if err := verifyRowHash(event); err != nil {
		return fmt.Errorf("verify audit event: %w", err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(event.Signature)
	if err != nil || len(signature) == 0 || len(signature) > maxSignatureBytes {
		return errors.New("verify audit event: invalid detached signature")
	}
	canonical, err := canonicalBytes(event)
	if err != nil {
		return fmt.Errorf("verify audit event: %w", err)
	}
	if err := manager.detachedVerify(
		ctx,
		canonical,
		signature,
		event.SignerFingerprint,
	); err != nil {
		return fmt.Errorf("verify audit event: %w", err)
	}
	return nil
}

func (manager *Manager) detachedSign(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	payloadPath, signaturePath, cleanup, err := manager.gpgTempPaths()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := writeFileExclusive(payloadPath, payload, 0o600); err != nil {
		return nil, fmt.Errorf("write audit signing payload: %w", err)
	}
	args := manager.gpgArgs(
		"--batch",
		"--yes",
		"--local-user",
		manager.config.SigningFingerprint,
		"--detach-sign",
		"--output",
		signaturePath,
		payloadPath,
	)
	if _, err := manager.runner.Run(ctx, "gpg", args...); err != nil {
		return nil, fmt.Errorf("sign team audit event: %w", err)
	}
	signature, err := readLimitedRegularFile(signaturePath, maxSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("read team audit signature: %w", err)
	}
	return signature, nil
}

func (manager *Manager) detachedVerify(
	ctx context.Context,
	payload []byte,
	signature []byte,
	expectedPrimary string,
) error {
	payloadPath, signaturePath, cleanup, err := manager.gpgTempPaths()
	if err != nil {
		return err
	}
	defer cleanup()
	if err := writeFileExclusive(payloadPath, payload, 0o600); err != nil {
		return fmt.Errorf("write audit verification payload: %w", err)
	}
	if err := writeFileExclusive(signaturePath, signature, 0o600); err != nil {
		return fmt.Errorf("write audit verification signature: %w", err)
	}
	args := manager.gpgArgs(
		"--batch",
		"--status-fd=1",
		"--verify",
		signaturePath,
		payloadPath,
	)
	output, err := manager.runner.Run(ctx, "gpg", args...)
	if err != nil {
		return fmt.Errorf("GPG audit signature check failed: %w", err)
	}
	primary, err := validSignaturePrimary(output)
	if err != nil {
		return err
	}
	if primary != expectedPrimary {
		return errors.New(
			"VALIDSIG primary fingerprint does not match the audit event",
		)
	}
	return nil
}

func (manager *Manager) gpgTempPaths() (
	string,
	string,
	func(),
	error,
) {
	tempDir := filepath.Join(manager.config.StateDir, "tmp")
	if err := ensurePrivateDirectory(tempDir); err != nil {
		return "", "", nil, fmt.Errorf("create audit GPG temp directory: %w", err)
	}
	payload, err := os.CreateTemp(tempDir, "payload-")
	if err != nil {
		return "", "", nil, fmt.Errorf("create audit signing payload: %w", err)
	}
	payloadPath := payload.Name()
	if closeErr := payload.Close(); closeErr != nil {
		_ = os.Remove(payloadPath)
		return "", "", nil, fmt.Errorf("close audit signing payload: %w", closeErr)
	}
	if removeErr := os.Remove(payloadPath); removeErr != nil {
		return "", "", nil, fmt.Errorf("prepare audit signing payload: %w", removeErr)
	}
	signaturePath := payloadPath + ".sig"
	cleanup := func() {
		_ = os.Remove(payloadPath)
		_ = os.Remove(signaturePath)
	}
	return payloadPath, signaturePath, cleanup, nil
}

func (manager *Manager) gpgArgs(args ...string) []string {
	if manager.config.GPGHome == "" {
		return args
	}
	withHome := make([]string, 0, len(args)+2)
	withHome = append(withHome, "--homedir", manager.config.GPGHome)
	return append(withHome, args...)
}

func validSignaturePrimary(output []byte) (string, error) {
	var primary string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG":
			return "", errors.New("GPG reported an invalid audit signature")
		case "VALIDSIG":
			if primary != "" {
				return "", errors.New("GPG reported multiple VALIDSIG records")
			}
			signing, err := normalizeFingerprint(fields[2])
			if err != nil {
				return "", errors.New("GPG returned an invalid VALIDSIG fingerprint")
			}
			primary = signing
			if len(fields) >= 12 {
				if parsed, parseErr := normalizeFingerprint(
					fields[len(fields)-1],
				); parseErr == nil {
					primary = parsed
				}
			}
		}
	}
	if primary == "" {
		return "", errors.New("GPG did not emit a VALIDSIG record")
	}
	return primary, nil
}

func sanitizeCommandOutput(output []byte) string {
	const limit = 4096
	if len(output) > limit {
		output = output[:limit]
	}
	text := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' {
			return ' '
		}
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, string(output))
	return strings.TrimSpace(text)
}

func containsString(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}
