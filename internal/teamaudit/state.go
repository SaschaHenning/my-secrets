package teamaudit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
	"github.com/google/uuid"
)

type watermarkFile struct {
	Version  int                  `json:"version"`
	Branches map[string]watermark `json:"branches"`
}

type watermark struct {
	OID     string `json:"oid"`
	Count   uint64 `json:"count"`
	RowHash string `json:"row_hash"`
}

func (manager *Manager) loadWatermarks() (watermarkFile, error) {
	path := filepath.Join(manager.config.StateDir, watermarkFilename)
	data, err := readLimitedRegularFile(path, maxMetadataBytes)
	if errors.Is(err, os.ErrNotExist) {
		return watermarkFile{
			Version:  schemaVersion,
			Branches: make(map[string]watermark),
		}, nil
	}
	if err != nil {
		return watermarkFile{}, fmt.Errorf("read team audit watermarks: %w", err)
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return watermarkFile{}, fmt.Errorf("parse team audit watermarks: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state watermarkFile
	if err := decoder.Decode(&state); err != nil {
		return watermarkFile{}, fmt.Errorf("parse team audit watermarks: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return watermarkFile{}, fmt.Errorf("parse team audit watermarks: %w", err)
	}
	if state.Version != schemaVersion || state.Branches == nil {
		return watermarkFile{}, errors.New("invalid team audit watermark version")
	}
	for branch, mark := range state.Branches {
		if branch == "" || !commitPattern.MatchString(mark.OID) ||
			mark.Count == 0 || !hashPattern.MatchString(mark.RowHash) {
			return watermarkFile{}, fmt.Errorf(
				"invalid team audit watermark for branch %q",
				branch,
			)
		}
	}
	return state, nil
}

func (manager *Manager) saveWatermarks(state watermarkFile) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal team audit watermarks: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWriteFile(
		filepath.Join(manager.config.StateDir, watermarkFilename),
		data,
		0o600,
	); err != nil {
		return fmt.Errorf("save team audit watermarks: %w", err)
	}
	return nil
}

func (manager *Manager) checkWatermark(
	ctx context.Context,
	branch remoteBranch,
	events []Event,
	mark watermark,
) error {
	if mark.OID == "" {
		return nil
	}
	if uint64(len(events)) < mark.Count {
		return fmt.Errorf(
			"audit rollback detected on branch %s: event count decreased",
			branch.Name,
		)
	}
	if events[mark.Count-1].RowHash != mark.RowHash {
		return fmt.Errorf(
			"audit rollback detected on branch %s: verified prefix changed",
			branch.Name,
		)
	}
	if branch.OID == mark.OID {
		if uint64(len(events)) != mark.Count {
			return fmt.Errorf(
				"audit divergence detected on branch %s: commit has changed content",
				branch.Name,
			)
		}
		return nil
	}
	if uint64(len(events)) == mark.Count {
		return fmt.Errorf(
			"audit rollback detected on branch %s: commit was rewritten",
			branch.Name,
		)
	}
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"merge-base",
		"--is-ancestor",
		mark.OID,
		branch.OID,
	); err != nil {
		return fmt.Errorf(
			"audit divergence detected on branch %s: prior commit is not an ancestor",
			branch.Name,
		)
	}
	return nil
}

func watermarkFor(branch remoteBranch, events []Event) watermark {
	if len(events) == 0 {
		return watermark{}
	}
	return watermark{
		OID:     branch.OID,
		Count:   uint64(len(events)),
		RowHash: events[len(events)-1].RowHash,
	}
}

func (manager *Manager) loadOrCreateDeviceID(
	ctx context.Context,
) (_ string, returnErr error) {
	path := manager.config.DeviceIDPath
	release, err := acquireAuditFileLock(
		ctx,
		path+".lock",
		"team audit device identity",
	)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := release(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	data, err := readLimitedRegularFile(path, 128)
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return "", fmt.Errorf("inspect team audit device ID: %w", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			return "", errors.New("team audit device ID permissions must be 0600")
		}
		deviceID := strings.TrimSpace(string(data))
		if err := validateEventID(deviceID); err != nil {
			return "", fmt.Errorf("read team audit device ID: %w", err)
		}
		return deviceID, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read team audit device ID: %w", err)
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("create team audit device directory: %w", err)
	}
	deviceID := uuid.NewString()
	if err := atomicWriteFile(path, []byte(deviceID+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("create team audit device ID: %w", err)
	}
	return deviceID, nil
}

func hashRegularFile(path string) (string, error) {
	data, err := readLimitedRegularFile(path, maxMetadataBytes)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (manager *Manager) verifyMetadataAtCommit(
	ctx context.Context,
	commit string,
	path string,
	current []byte,
) error {
	relative, err := filepath.Rel(manager.config.StorePath, path)
	if err != nil || relative == "." || strings.HasPrefix(
		relative,
		".."+string(filepath.Separator),
	) {
		return errors.New("shared metadata path is outside the store")
	}
	repositoryPath := filepath.ToSlash(relative)
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"show",
		commit+":"+repositoryPath,
	)
	if err != nil {
		return fmt.Errorf(
			"read %s at shared store commit: %w",
			repositoryPath,
			err,
		)
	}
	if len(output) > maxMetadataBytes || !bytes.Equal(output, current) {
		return fmt.Errorf(
			"shared metadata %s differs from recorded store commit",
			repositoryPath,
		)
	}
	return nil
}

type historicalAuthorization struct {
	members    *teamkeys.File
	recipients []string
}

func (manager *Manager) verifyHistoricalAuthorization(
	ctx context.Context,
	event Event,
	cache map[string]*historicalAuthorization,
) error {
	cacheKey := event.StoreCommit + ":" + event.TeamKeysHash +
		":" + event.RecipientSetHash
	authorization := cache[cacheKey]
	if authorization == nil {
		loaded, err := manager.loadHistoricalAuthorization(ctx, event)
		if err != nil {
			return err
		}
		authorization = loaded
		cache[cacheKey] = loaded
	}
	member, found := authorization.members.FindFingerprint(
		event.SignerFingerprint,
	)
	if !found || !containsString(
		authorization.recipients,
		event.SignerFingerprint,
	) {
		return errors.New(
			"audit signer was not authorized by the recorded store commit",
		)
	}
	if member.Name != event.SignerName || member.Email != event.SignerEmail {
		return errors.New(
			"audit signer identity does not match the recorded store commit",
		)
	}
	return nil
}

func (manager *Manager) loadHistoricalAuthorization(
	ctx context.Context,
	event Event,
) (*historicalAuthorization, error) {
	publishedHead, err := manager.currentStoreCommit(ctx)
	if err != nil {
		return nil, err
	}
	if err := manager.verifyStoreCommitPublished(ctx, publishedHead); err != nil {
		return nil, err
	}
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"merge-base",
		"--is-ancestor",
		event.StoreCommit,
		publishedHead,
	); err != nil {
		return nil, errors.New(
			"audit store commit is not in the trusted shared-store history",
		)
	}
	teamData, err := manager.readStoreBlob(
		ctx,
		event.StoreCommit,
		teamkeys.Filename,
	)
	if err != nil {
		return nil, err
	}
	if hashBytes(teamData) != event.TeamKeysHash {
		return nil, errors.New(
			"historical team key manifest hash does not match the audit event",
		)
	}
	recipientData, err := manager.readStoreBlob(
		ctx,
		event.StoreCommit,
		".gpg-id",
	)
	if err != nil {
		return nil, err
	}
	recipientHash, err := hashRecipientData(recipientData)
	if err != nil {
		return nil, fmt.Errorf("parse historical recipient set: %w", err)
	}
	if recipientHash != event.RecipientSetHash {
		return nil, errors.New(
			"historical recipient set hash does not match the audit event",
		)
	}
	manifest, err := manager.parseHistoricalTeamKeys(teamData)
	if err != nil {
		return nil, err
	}
	recipients, err := parseRecipientSet(recipientData)
	if err != nil {
		return nil, err
	}
	return &historicalAuthorization{
		members:    manifest,
		recipients: recipients,
	}, nil
}

func (manager *Manager) readStoreBlob(
	ctx context.Context,
	commit string,
	repositoryPath string,
) ([]byte, error) {
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"show",
		commit+":"+repositoryPath,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read historical shared metadata %s: %w",
			repositoryPath,
			err,
		)
	}
	if len(output) > maxMetadataBytes {
		return nil, fmt.Errorf(
			"historical shared metadata %s is too large",
			repositoryPath,
		)
	}
	return output, nil
}

func (manager *Manager) parseHistoricalTeamKeys(
	data []byte,
) (*teamkeys.File, error) {
	tempDir := filepath.Join(manager.config.StateDir, "tmp")
	if err := ensurePrivateDirectory(tempDir); err != nil {
		return nil, fmt.Errorf(
			"create historical team key temp directory: %w",
			err,
		)
	}
	file, err := os.CreateTemp(tempDir, "team-keys-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("create historical team key file: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure historical team key file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write historical team key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close historical team key file: %w", err)
	}
	manifest, err := teamkeys.Load(path)
	if err != nil {
		return nil, fmt.Errorf("parse historical team key manifest: %w", err)
	}
	return manifest, nil
}

func validateStoreMetadataPaths(storePath string, paths ...string) error {
	storeInfo, err := os.Lstat(storePath)
	if err != nil {
		return fmt.Errorf("inspect shared store path: %w", err)
	}
	if storeInfo.Mode()&os.ModeSymlink != 0 || !storeInfo.IsDir() {
		return errors.New("shared store path is not a real directory")
	}
	for _, candidate := range paths {
		relative, err := filepath.Rel(storePath, candidate)
		if err != nil || relative == "." || strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		) {
			return errors.New("shared metadata path is outside the store")
		}
		current := storePath
		for _, segment := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, segment)
			info, err := os.Lstat(current)
			if err != nil {
				return fmt.Errorf("inspect shared metadata path: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("shared metadata path contains a symbolic link")
			}
		}
	}
	return nil
}

func hashRecipientSet(path string) (string, error) {
	data, err := readLimitedRegularFile(path, maxMetadataBytes)
	if err != nil {
		return "", err
	}
	return hashRecipientData(data)
}

func hashRecipientData(data []byte) (string, error) {
	recipients, err := parseRecipientSet(data)
	if err != nil {
		return "", err
	}
	var canonical bytes.Buffer
	canonical.WriteString("mys-team-audit-recipients\x00v1\x00")
	for _, recipient := range recipients {
		if err := binary.Write(
			&canonical,
			binary.BigEndian,
			uint32(len(recipient)),
		); err != nil {
			return "", fmt.Errorf("encode recipient set: %w", err)
		}
		canonical.WriteString(recipient)
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func loadRecipientSet(path string) ([]string, error) {
	data, err := readLimitedRegularFile(path, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	return parseRecipientSet(data)
}

func parseRecipientSet(data []byte) ([]string, error) {
	recipients := make([]string, 0)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxEventLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fingerprint, err := normalizeFingerprint(line)
		if err != nil {
			return nil, errors.New("recipient set contains an invalid fingerprint")
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, errors.New("recipient set contains a duplicate fingerprint")
		}
		seen[fingerprint] = struct{}{}
		recipients = append(recipients, fingerprint)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan recipient set: %w", err)
	}
	if len(recipients) == 0 {
		return nil, errors.New("recipient set is empty")
	}
	sort.Strings(recipients)
	return recipients, nil
}

func readLimitedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a real directory")
	}
	return os.Chmod(path, 0o700)
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a real directory")
	}
	return nil
}

func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	success := false
	defer func() {
		_ = temp.Close()
		if !success {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	if err := directory.Close(); err != nil {
		return err
	}
	success = true
	return nil
}
