package teamaudit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	repositoryMarker     = ".mys-team-audit-v1"
	repositoryMarkerBody = "mys-team-audit-worktree-v1\n"
	auditLogFilename     = "events.ndjson"
	watermarkFilename    = "watermarks-v1.json"
	maxMetadataBytes     = 1 << 20
	maxGitOutputBytes    = 40 << 20
	maxAuditBranches     = 4_096
)

// Manager coordinates signed events, Git synchronization, and local rollback
// watermarks for one shared mount.
type Manager struct {
	config   Config
	runner   Runner
	now      func() time.Time
	newID    func() string
	hostname func() (string, error)
}

// NewManager validates config before returning a manager. A nil runner uses
// direct subprocess execution without a shell.
func NewManager(config Config, runner Runner) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configure team audit: %w", err)
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Manager{
		config:   config,
		runner:   runner,
		now:      time.Now,
		newID:    uuid.NewString,
		hostname: os.Hostname,
	}, nil
}

// Provision verifies all local inputs, creates the private device identity,
// checks the signing key, and fully verifies the current remote repository.
func (manager *Manager) Provision(ctx context.Context) (returnErr error) {
	release, err := acquireAuditLock(ctx, manager.config.StateDir)
	if err != nil {
		return err
	}
	defer func() {
		if err := release(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()

	if _, err := manager.loadOrCreateDeviceID(ctx); err != nil {
		return err
	}
	snapshot, err := manager.Preflight(ctx)
	if err != nil {
		return err
	}
	if _, err := manager.loadSignerIdentity(ctx, snapshot); err != nil {
		return err
	}
	if err := manager.ensureRepository(ctx); err != nil {
		return err
	}
	if _, _, err = manager.aggregateLocked(ctx, true); err != nil {
		return err
	}
	return manager.proveRemoteWrite(ctx)
}

// Preflight snapshots the current store commit and hashes the policy, team-key
// manifest, and canonical recipient set without reading any secret value.
func (manager *Manager) Preflight(ctx context.Context) (Snapshot, error) {
	if err := manager.config.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := validateStoreMetadataPaths(
		manager.config.StorePath,
		manager.config.TeamKeysPath,
		manager.config.RecipientPath,
	); err != nil {
		return Snapshot{}, err
	}
	policyData, err := readLimitedRegularFile(
		manager.config.PolicyPath,
		maxMetadataBytes,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read shared policy: %w", err)
	}
	teamKeysData, err := readLimitedRegularFile(
		manager.config.TeamKeysPath,
		maxMetadataBytes,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read team key manifest: %w", err)
	}
	recipientData, err := readLimitedRegularFile(
		manager.config.RecipientPath,
		maxMetadataBytes,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read shared recipient set: %w", err)
	}
	storeCommit, err := manager.currentStoreCommit(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err := manager.verifyStoreCommitPublished(ctx, storeCommit); err != nil {
		return Snapshot{}, err
	}
	if err := manager.verifyMetadataAtCommit(
		ctx,
		storeCommit,
		manager.config.TeamKeysPath,
		teamKeysData,
	); err != nil {
		return Snapshot{}, err
	}
	if err := manager.verifyMetadataAtCommit(
		ctx,
		storeCommit,
		manager.config.RecipientPath,
		recipientData,
	); err != nil {
		return Snapshot{}, err
	}
	recipientSetHash, err := hashRecipientData(recipientData)
	if err != nil {
		return Snapshot{}, fmt.Errorf("hash shared recipient set: %w", err)
	}
	return Snapshot{
		StoreCommit:      strings.ToLower(storeCommit),
		PolicyHash:       hashBytes(policyData),
		TeamKeysHash:     hashBytes(teamKeysData),
		RecipientSetHash: recipientSetHash,
	}, nil
}

// AppendBatch signs and appends one atomic batch for the exact snapshot the
// caller obtained before decrypting. It returns only after the exact event IDs
// have been fetched back and verified from the remote.
func (manager *Manager) AppendBatch(
	ctx context.Context,
	expected Snapshot,
	inputs []Input,
) (_ []Event, returnErr error) {
	if len(inputs) == 0 {
		return nil, errors.New("append team audit: input batch is empty")
	}
	if len(inputs) > 1_000 {
		return nil, errors.New("append team audit: input batch is too large")
	}
	if err := expected.validate(); err != nil {
		return nil, fmt.Errorf("append team audit: %w", err)
	}
	for _, input := range inputs {
		if err := input.validate(manager.config.Mount); err != nil {
			return nil, fmt.Errorf("append team audit: %w", err)
		}
	}
	if err := validateInputIDs(inputs); err != nil {
		return nil, err
	}

	release, err := acquireAuditLock(ctx, manager.config.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := release(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	return manager.appendLocked(ctx, expected, inputs)
}

// Aggregate fetches and verifies every mount branch before returning any
// events. The result order is stable across runs.
func (manager *Manager) Aggregate(
	ctx context.Context,
) (_ []VerifiedEvent, returnErr error) {
	release, err := acquireAuditLock(ctx, manager.config.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := release(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	if err := manager.ensureRepository(ctx); err != nil {
		return nil, err
	}
	events, _, err := manager.aggregateLocked(ctx, true)
	return events, err
}

// Verify performs the same all-or-nothing remote verification as Aggregate
// and returns only counts.
func (manager *Manager) Verify(
	ctx context.Context,
) (VerifyReport, error) {
	events, err := manager.Aggregate(ctx)
	if err != nil {
		return VerifyReport{}, err
	}
	branches := make(map[string]struct{})
	for _, event := range events {
		branches[event.Branch] = struct{}{}
	}
	return VerifyReport{Branches: len(branches), Events: len(events)}, nil
}
