package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const sharedPolicyVersion = 1

type sharedPolicyFile struct {
	Version int              `yaml:"version"`
	Actors  map[string]Rules `yaml:"actors"`
}

// SharedDefaultTransaction keeps a cross-process lock and an exact snapshot of
// the shared policy for the full setup lifetime. Abort never mutates the policy.
type SharedDefaultTransaction struct {
	mu           sync.Mutex
	path         string
	expectedInfo os.FileInfo
	expectedData []byte
	expectedHash [sha256.Size]byte
	release      func() error
	finished     bool
	result       error
}

type boundSharedPolicyFile struct {
	info os.FileInfo
	data []byte
	hash [sha256.Size]byte
}

// SharedPath returns the policy path for a validated shared mount.
func SharedPath(mount string) (string, error) {
	if err := validateSharedMountName(mount); err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, ".config", "my-secrets", "shared-policies")
	policyPath := filepath.Join(base, mount+".yaml")
	relative, err := filepath.Rel(base, policyPath)
	if err != nil {
		return "", fmt.Errorf("resolve shared policy path: %w", err)
	}
	if relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relative) {
		return "", errors.New("shared policy path escapes its config directory")
	}
	return policyPath, nil
}

// EnsureSharedDefault atomically creates a version-1 fail-closed policy for
// mount. Existing policies are validated and never overwritten.
func EnsureSharedDefault(mount string) (string, error) {
	transaction, err := BeginSharedDefault(mount)
	if err != nil {
		return "", err
	}
	if err := transaction.Commit(); err != nil {
		return "", err
	}
	return transaction.Path(), nil
}

// BeginSharedDefault starts a filesystem transaction using a background
// context. Call BeginSharedDefaultContext when lock waiting must be cancelable.
func BeginSharedDefault(mount string) (*SharedDefaultTransaction, error) {
	return BeginSharedDefaultContext(context.Background(), mount)
}

// BeginSharedDefaultContext starts a monotonic filesystem transaction for the
// mount's default policy. It holds a cross-process lock until Commit or Rollback.
// Existing policies are validated and never changed. A newly created fail-closed
// policy remains in place even when the surrounding setup later aborts.
func BeginSharedDefaultContext(
	ctx context.Context,
	mount string,
) (*SharedDefaultTransaction, error) {
	policyPath, err := SharedPath(mount)
	if err != nil {
		return nil, err
	}
	wire := sharedPolicyFile{
		Version: sharedPolicyVersion,
		Actors:  defaultSharedPolicy(mount).Actors,
	}
	data, err := yaml.Marshal(&wire)
	if err != nil {
		return nil, fmt.Errorf("marshal shared policy: %w", err)
	}
	release, err := acquireSharedPolicyLock(ctx, mount)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
		return nil, errors.Join(
			fmt.Errorf("create policy directory: %w", err),
			release(),
		)
	}
	transaction, err := beginSharedPolicyFile(policyPath, data)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("ensure shared policy: %w", err),
			release(),
		)
	}
	transaction.release = release
	if err := snapshotSharedPolicyTransactionFile(transaction); err != nil {
		return nil, errors.Join(
			fmt.Errorf("validate shared policy: %w", err),
			transaction.Rollback(),
		)
	}
	return transaction, nil
}

// Path returns the shared policy path governed by the transaction.
func (transaction *SharedDefaultTransaction) Path() string {
	if transaction == nil {
		return ""
	}
	return transaction.path
}

// Verify confirms that the policy still has the exact inode, bytes, and hash
// captured by BeginSharedDefaultContext.
func (transaction *SharedDefaultTransaction) Verify() error {
	if transaction == nil {
		return errors.New("shared policy transaction is nil")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.finished {
		return transaction.result
	}
	return transaction.verifyExpectedFile()
}

// Commit verifies the exact policy snapshot and then releases the setup lock.
// It never mutates the policy.
func (transaction *SharedDefaultTransaction) Commit() error {
	if transaction == nil {
		return errors.New("shared policy transaction is nil")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.finished {
		return transaction.result
	}
	transaction.finished = true
	transaction.result = errors.Join(
		transaction.verifyExpectedFile(),
		transaction.releaseLock(),
	)
	return transaction.result
}

// Rollback aborts the transaction by releasing its setup lock. The policy is
// deliberately retained: a valid fail-closed policy is monotonic security state.
func (transaction *SharedDefaultTransaction) Rollback() error {
	if transaction == nil {
		return nil
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.finished {
		return transaction.result
	}
	transaction.finished = true
	transaction.result = transaction.releaseLock()
	return transaction.result
}

func beginSharedPolicyFile(
	policyPath string,
	data []byte,
) (*SharedDefaultTransaction, error) {
	if info, err := os.Lstat(policyPath); err == nil {
		if err := validatePolicyFileInfo(info); err != nil {
			return nil, err
		}
		return &SharedDefaultTransaction{path: policyPath}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	parent := filepath.Dir(policyPath)
	temp, err := os.CreateTemp(parent, "."+filepath.Base(policyPath)+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temporary policy: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("set temporary policy permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return nil, fmt.Errorf("write temporary policy: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return nil, fmt.Errorf("sync temporary policy: %w", err)
	}
	if err := temp.Close(); err != nil {
		return nil, fmt.Errorf("close temporary policy: %w", err)
	}
	if err := os.Link(tempPath, policyPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			info, statErr := os.Lstat(policyPath)
			if statErr != nil {
				return nil, fmt.Errorf(
					"inspect concurrently created policy: %w",
					statErr,
				)
			}
			if err := validatePolicyFileInfo(info); err != nil {
				return nil, err
			}
			return &SharedDefaultTransaction{path: policyPath}, nil
		}
		return nil, fmt.Errorf("install policy: %w", err)
	}
	return &SharedDefaultTransaction{path: policyPath}, nil
}

func snapshotSharedPolicyTransactionFile(
	transaction *SharedDefaultTransaction,
) error {
	if transaction == nil {
		return errors.New("shared policy transaction is nil")
	}
	snapshot, err := readSharedPolicySnapshot(transaction.path, nil)
	if err != nil {
		return err
	}
	if _, err := decodeSharedPolicy(snapshot.data); err != nil {
		return err
	}
	transaction.expectedInfo = snapshot.info
	transaction.expectedData = append([]byte(nil), snapshot.data...)
	transaction.expectedHash = snapshot.hash
	return nil
}

func (transaction *SharedDefaultTransaction) verifyExpectedFile() error {
	if transaction.expectedInfo == nil {
		return errors.New("shared policy transaction has no policy snapshot")
	}
	snapshot, err := readSharedPolicySnapshot(
		transaction.path,
		transaction.expectedInfo,
	)
	if err != nil {
		return fmt.Errorf("read shared policy at commit: %w", err)
	}
	if snapshot.hash != transaction.expectedHash ||
		!bytes.Equal(snapshot.data, transaction.expectedData) {
		return errors.New("shared policy contents no longer match")
	}
	return nil
}

func readSharedPolicySnapshot(
	policyPath string,
	expectedInfo os.FileInfo,
) (snapshot boundSharedPolicyFile, resultErr error) {
	file, err := openSharedPolicyFile(policyPath)
	if err != nil {
		return boundSharedPolicyFile{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	return readBoundSharedPolicyFile(policyPath, file, expectedInfo)
}

func readBoundSharedPolicyFile(
	policyPath string,
	file *os.File,
	expectedInfo os.FileInfo,
) (boundSharedPolicyFile, error) {
	if policyPath == "" {
		return boundSharedPolicyFile{}, errors.New("shared policy path is empty")
	}
	if file == nil {
		return boundSharedPolicyFile{}, errors.New("shared policy file is nil")
	}
	before, err := file.Stat()
	if err != nil {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"inspect opened shared policy: %w",
			err,
		)
	}
	if err := validatePolicyFileInfo(before); err != nil {
		return boundSharedPolicyFile{}, err
	}
	if expectedInfo != nil && !os.SameFile(expectedInfo, before) {
		return boundSharedPolicyFile{}, errors.New(
			"shared policy inode no longer matches",
		)
	}
	if before.Size() > policyFileSizeLimit {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"policy exceeds %d bytes",
			policyFileSizeLimit,
		)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"seek opened shared policy: %w",
			err,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, policyFileSizeLimit+1))
	if err != nil {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"read opened shared policy: %w",
			err,
		)
	}
	if len(data) > policyFileSizeLimit {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"policy exceeds %d bytes",
			policyFileSizeLimit,
		)
	}
	after, err := file.Stat()
	if err != nil {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"reinspect opened shared policy: %w",
			err,
		)
	}
	if err := validatePolicyFileInfo(after); err != nil {
		return boundSharedPolicyFile{}, err
	}
	if !sameBoundPolicyFileState(before, after) {
		return boundSharedPolicyFile{}, errors.New(
			"shared policy changed while reading opened file",
		)
	}
	if expectedInfo != nil && !os.SameFile(expectedInfo, after) {
		return boundSharedPolicyFile{}, errors.New(
			"shared policy inode no longer matches",
		)
	}
	pathInfo, err := os.Lstat(policyPath)
	if err != nil {
		return boundSharedPolicyFile{}, fmt.Errorf(
			"inspect shared policy path after read: %w",
			err,
		)
	}
	if err := validatePolicyFileInfo(pathInfo); err != nil {
		return boundSharedPolicyFile{}, err
	}
	if !sameBoundPolicyFileState(pathInfo, after) {
		return boundSharedPolicyFile{}, errors.New(
			"shared policy path no longer matches opened file",
		)
	}
	return boundSharedPolicyFile{
		info: after,
		data: data,
		hash: sha256.Sum256(data),
	}, nil
}

func sameBoundPolicyFileState(left os.FileInfo, right os.FileInfo) bool {
	return left != nil &&
		right != nil &&
		os.SameFile(left, right) &&
		left.Mode() == right.Mode() &&
		left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}

func (transaction *SharedDefaultTransaction) releaseLock() error {
	if transaction.release == nil {
		return errors.New("shared policy transaction has no setup lock")
	}
	return transaction.release()
}

// LoadShared loads and validates a version-1 mount policy. Unlike Load, a
// missing file is always an error. The returned SHA-256 covers the exact bytes
// that were parsed and validated.
func LoadShared(mount string) (*Policy, string, string, error) {
	policyPath, err := SharedPath(mount)
	if err != nil {
		return nil, "", "", err
	}
	data, err := readPolicyFile(policyPath)
	if err != nil {
		return nil, policyPath, "", fmt.Errorf("read shared policy: %w", err)
	}
	pol, err := decodeSharedPolicy(data)
	if err != nil {
		return nil, policyPath, "", fmt.Errorf("parse shared policy: %w", err)
	}
	hash := sha256.Sum256(data)
	return pol, policyPath, hex.EncodeToString(hash[:]), nil
}

// EvaluateCombined allows access only when both global and shared policies
// allow the actor and path.
func EvaluateCombined(
	global *Policy,
	shared *Policy,
	actorKind string,
	agentLabel string,
	secretPath string,
) Decision {
	globalDecision := global.Evaluate(actorKind, agentLabel, secretPath)
	if !globalDecision.Allowed {
		globalDecision.MatchedRule = "global:" + globalDecision.MatchedRule
		globalDecision.Reason = "global policy: " + globalDecision.Reason
		return globalDecision
	}
	sharedDecision := shared.Evaluate(actorKind, agentLabel, secretPath)
	if !sharedDecision.Allowed {
		sharedDecision.MatchedRule = "shared:" + sharedDecision.MatchedRule
		sharedDecision.Reason = "shared policy: " + sharedDecision.Reason
		return sharedDecision
	}
	return Decision{
		Allowed: true,
		MatchedRule: "global:" + globalDecision.MatchedRule +
			" && shared:" + sharedDecision.MatchedRule,
		Reason: "allowed by global and shared policies",
	}
}

func defaultSharedPolicy(mount string) *Policy {
	allow := []string{mount + "/**"}
	return &Policy{
		Actors: map[string]Rules{
			"human": {
				Allow: append([]string(nil), allow...),
			},
			"script": {
				Allow: append([]string(nil), allow...),
			},
			"ai": {
				Allow: append([]string(nil), allow...),
			},
			"claude-code": {
				Allow: append([]string(nil), allow...),
			},
		},
	}
}

func decodeSharedPolicy(data []byte) (*Policy, error) {
	mapping, err := validateYAMLDocument(data)
	if err != nil {
		return nil, err
	}
	version := yamlMappingValue(mapping, "version")
	if version == nil {
		return nil, errors.New("shared policy version is required")
	}
	if version.Tag != "!!int" {
		return nil, errors.New("shared policy version must be an integer")
	}

	var wire sharedPolicyFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	if wire.Version != sharedPolicyVersion {
		return nil, fmt.Errorf(
			"unsupported shared policy version %d",
			wire.Version,
		)
	}
	pol := &Policy{Actors: wire.Actors}
	if pol.Actors == nil {
		pol.Actors = map[string]Rules{}
	}
	if err := validatePolicy(pol); err != nil {
		return nil, err
	}
	return pol, nil
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func validateSharedMountName(mount string) error {
	if mount == "" || strings.TrimSpace(mount) != mount {
		return errors.New("shared mount name is empty or padded")
	}
	if mount == "root" {
		return errors.New("root mount cannot be shared")
	}
	if len(mount) > 64 {
		return errors.New("shared mount name exceeds 64 bytes")
	}
	for index, char := range mount {
		valid := char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' ||
			(index > 0 && (char == '-' || char == '_' || char == '.'))
		if !valid {
			return fmt.Errorf(
				"shared mount contains invalid character %q",
				char,
			)
		}
	}
	return nil
}
