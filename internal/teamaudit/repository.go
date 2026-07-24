package teamaudit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const remoteProbeCleanupTimeout = 15 * time.Second

func (manager *Manager) commitAndPush(
	ctx context.Context,
	branch string,
	events []Event,
	identity signerIdentity,
) (string, error) {
	remoteOID, exists, err := manager.remoteOID(ctx, branch)
	if err != nil {
		return "", err
	}
	if err := manager.checkoutAuditParent(ctx, remoteOID, exists); err != nil {
		return "", err
	}
	if err := manager.commitEventLog(ctx, events, identity); err != nil {
		return "", err
	}
	commit, err := manager.headOID(ctx)
	if err != nil {
		return "", err
	}
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"push",
		"--porcelain",
		"origin",
		"HEAD:refs/heads/"+branch,
	); err != nil {
		return commit, fmt.Errorf("push team audit branch: %w", err)
	}
	return commit, nil
}

func (manager *Manager) checkoutAuditParent(
	ctx context.Context,
	remoteOID string,
	exists bool,
) error {
	if exists {
		if _, err := manager.runner.Run(
			ctx,
			"git",
			"-C",
			manager.config.WorkDir,
			"checkout",
			"--detach",
			"--force",
			remoteOID,
		); err != nil {
			return fmt.Errorf("checkout team audit branch: %w", err)
		}
		return nil
	}
	stagingBranch := "audit-stage-" + uuid.NewString()
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"checkout",
		"--orphan",
		stagingBranch,
	); err != nil {
		return fmt.Errorf("create team audit root commit: %w", err)
	}
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"rm",
		"-r",
		"--cached",
		"--ignore-unmatch",
		"--",
		".",
	); err != nil {
		return fmt.Errorf("clear team audit root index: %w", err)
	}
	if err := os.Remove(
		filepath.Join(manager.config.WorkDir, auditLogFilename),
	); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear team audit work log: %w", err)
	}
	return nil
}

func (manager *Manager) commitEventLog(
	ctx context.Context,
	events []Event,
	identity signerIdentity,
) error {
	data, err := marshalEventLog(events)
	if err != nil {
		return err
	}
	logPath := filepath.Join(manager.config.WorkDir, auditLogFilename)
	if err := atomicWriteFile(logPath, data, 0o600); err != nil {
		return fmt.Errorf("write team audit log: %w", err)
	}
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"add",
		"--",
		auditLogFilename,
	); err != nil {
		return fmt.Errorf("stage team audit log: %w", err)
	}
	message := "audit: append " + events[len(events)-1].EventID
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"-c",
		"user.name="+identity.Name,
		"-c",
		"user.email="+identity.Email,
		"commit",
		"--no-gpg-sign",
		"-m",
		message,
	); err != nil {
		return fmt.Errorf("commit team audit log: %w", err)
	}
	return nil
}

func (manager *Manager) headOID(ctx context.Context) (string, error) {
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"rev-parse",
		"--verify",
		"HEAD",
	)
	if err != nil {
		return "", fmt.Errorf("resolve team audit commit: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(string(output)))
	if !commitPattern.MatchString(commit) {
		return "", errors.New("Git returned an invalid team audit commit")
	}
	return commit, nil
}

func (manager *Manager) remoteOID(
	ctx context.Context,
	branch string,
) (string, bool, error) {
	output, err := manager.runner.Run(
		ctx,
		"git",
		"ls-remote",
		"--heads",
		"--",
		manager.config.URL,
		"refs/heads/"+branch,
	)
	if err != nil {
		return "", false, fmt.Errorf("confirm team audit branch: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return "", false, nil
	}
	if len(fields) != 2 || fields[1] != "refs/heads/"+branch ||
		!commitPattern.MatchString(fields[0]) {
		return "", false, errors.New(
			"team audit remote returned an invalid branch confirmation",
		)
	}
	return strings.ToLower(fields[0]), true, nil
}

func (manager *Manager) proveRemoteWrite(ctx context.Context) error {
	probeID := manager.newID()
	if err := validateEventID(probeID); err != nil {
		return fmt.Errorf("create team audit write probe ID: %w", err)
	}
	branch := "mys-team-audit-probe/v1/" + probeID
	if _, exists, err := manager.remoteOID(ctx, branch); err != nil {
		return fmt.Errorf("check team audit write probe: %w", err)
	} else if exists {
		return errors.New("team audit write probe branch already exists")
	}
	commit, err := manager.createProbeCommit(ctx)
	if err != nil {
		return err
	}
	_, pushErr := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"push",
		"--porcelain",
		"origin",
		commit+":refs/heads/"+branch,
	)
	cleanupCtx, cancelCleanup := context.WithTimeout(
		context.WithoutCancel(ctx),
		remoteProbeCleanupTimeout,
	)
	defer cancelCleanup()

	remoteCommit, exists, confirmErr := manager.remoteOID(cleanupCtx, branch)
	if confirmErr != nil {
		cleanupErr := manager.deleteRemoteProbe(cleanupCtx, branch, commit)
		return errors.Join(
			fmt.Errorf("confirm team audit write probe: %w", confirmErr),
			pushErr,
			cleanupErr,
		)
	}
	if !exists || remoteCommit != commit {
		if exists {
			return errors.Join(
				pushErr,
				errors.New("team audit write probe remote ownership mismatch"),
			)
		}
		return errors.Join(
			pushErr,
			errors.New("team audit write probe did not reach the remote"),
		)
	}
	if cleanupErr := manager.deleteRemoteProbe(
		cleanupCtx,
		branch,
		commit,
	); cleanupErr != nil {
		return errors.Join(pushErr, cleanupErr)
	}
	return nil
}

func (manager *Manager) createProbeCommit(ctx context.Context) (string, error) {
	treeOutput, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"hash-object",
		"-w",
		"-t",
		"tree",
		os.DevNull,
	)
	if err != nil {
		return "", fmt.Errorf("create team audit write probe tree: %w", err)
	}
	tree := strings.ToLower(strings.TrimSpace(string(treeOutput)))
	if !commitPattern.MatchString(tree) {
		return "", errors.New("Git returned an invalid team audit write probe tree")
	}
	commitOutput, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"-c",
		"user.name=my-secrets",
		"-c",
		"user.email=audit-probe@localhost.invalid",
		"-c",
		"commit.gpgSign=false",
		"commit-tree",
		tree,
		"-m",
		"mys team audit remote write probe",
	)
	if err != nil {
		return "", fmt.Errorf("create team audit write probe commit: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(string(commitOutput)))
	if !commitPattern.MatchString(commit) {
		return "", errors.New("Git returned an invalid team audit write probe commit")
	}
	return commit, nil
}

func (manager *Manager) deleteRemoteProbe(
	ctx context.Context,
	branch string,
	expectedCommit string,
) error {
	ref := "refs/heads/" + branch
	_, deleteErr := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"push",
		"--porcelain",
		"--force-with-lease="+ref+":"+expectedCommit,
		"origin",
		":"+ref,
	)
	remoteCommit, exists, confirmErr := manager.remoteOID(ctx, branch)
	if confirmErr != nil {
		return errors.Join(
			deleteErr,
			fmt.Errorf("confirm team audit write probe cleanup: %w", confirmErr),
		)
	}
	if exists {
		if remoteCommit != expectedCommit {
			return errors.Join(
				deleteErr,
				errors.New("team audit write probe ownership changed before cleanup"),
			)
		}
		return errors.Join(
			deleteErr,
			errors.New("team audit write probe cleanup was not confirmed"),
		)
	}
	return nil
}

func (manager *Manager) ensureRepository(ctx context.Context) error {
	info, err := os.Lstat(manager.config.WorkDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := ensureDirectory(
			filepath.Dir(manager.config.WorkDir),
		); err != nil {
			return fmt.Errorf("create team audit work parent: %w", err)
		}
		if _, err := manager.runner.Run(
			ctx,
			"git",
			"clone",
			"--no-checkout",
			"--",
			manager.config.URL,
			manager.config.WorkDir,
		); err != nil {
			return fmt.Errorf("clone team audit repository: %w", err)
		}
		if err := atomicWriteFile(
			filepath.Join(manager.config.WorkDir, repositoryMarker),
			[]byte(repositoryMarkerBody),
			0o600,
		); err != nil {
			return fmt.Errorf("mark team audit repository: %w", err)
		}
	case err != nil:
		return fmt.Errorf("inspect team audit work directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return errors.New("team audit work path is not a real directory")
	default:
		marker, err := readLimitedRegularFile(
			filepath.Join(manager.config.WorkDir, repositoryMarker),
			1024,
		)
		if err != nil || string(marker) != repositoryMarkerBody {
			return errors.New(
				"existing team audit work directory is not managed by my-secrets",
			)
		}
	}
	gitInfo, err := os.Lstat(filepath.Join(manager.config.WorkDir, ".git"))
	if err != nil || gitInfo.Mode()&os.ModeSymlink != 0 || !gitInfo.IsDir() {
		return errors.New("team audit work directory has no safe Git metadata")
	}
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"remote",
		"get-url",
		"origin",
	)
	if err != nil {
		return fmt.Errorf("read team audit origin: %w", err)
	}
	if strings.TrimSpace(string(output)) != manager.config.URL {
		return errors.New("team audit origin does not match configuration")
	}
	return nil
}

func branchName(mount, fingerprint, deviceID string) string {
	return "audit/v1/" + mount + "/" + fingerprint + "/" + deviceID
}

func (manager *Manager) verifyStoreCommitPublished(
	ctx context.Context,
	commit string,
) error {
	branchOutput, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"symbolic-ref",
		"--quiet",
		"--short",
		"HEAD",
	)
	if err != nil {
		return errors.New("shared store HEAD must be on a tracking branch")
	}
	branch := strings.TrimSpace(string(branchOutput))
	if !validGitRefComponent(branch) {
		return errors.New("shared store branch name is invalid")
	}
	remoteOutput, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"config",
		"--get",
		"branch."+branch+".remote",
	)
	if err != nil {
		return errors.New("shared store branch has no configured remote")
	}
	remote := strings.TrimSpace(string(remoteOutput))
	if !validGitRemoteName(remote) {
		return errors.New("shared store branch has an invalid remote")
	}
	mergeOutput, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"config",
		"--get",
		"branch."+branch+".merge",
	)
	if err != nil {
		return errors.New("shared store branch has no upstream ref")
	}
	mergeRef := strings.TrimSpace(string(mergeOutput))
	if !strings.HasPrefix(mergeRef, "refs/heads/") ||
		!validGitRefComponent(strings.TrimPrefix(mergeRef, "refs/heads/")) {
		return errors.New("shared store upstream ref is invalid")
	}
	remoteHead, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"ls-remote",
		"--heads",
		"--",
		remote,
		mergeRef,
	)
	if err != nil {
		return fmt.Errorf("confirm shared store remote commit: %w", err)
	}
	fields := strings.Fields(string(remoteHead))
	if len(fields) != 2 || fields[1] != mergeRef ||
		!commitPattern.MatchString(fields[0]) {
		return errors.New("shared store upstream returned an invalid commit")
	}
	if !strings.EqualFold(fields[0], commit) {
		return errors.New(
			"shared store HEAD is not published at its configured upstream",
		)
	}
	return nil
}

func (manager *Manager) currentStoreCommit(ctx context.Context) (string, error) {
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.StorePath,
		"rev-parse",
		"--verify",
		"HEAD",
	)
	if err != nil {
		return "", fmt.Errorf("resolve shared store commit: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(string(output)))
	if !commitPattern.MatchString(commit) {
		return "", errors.New("shared store returned an invalid commit ID")
	}
	return commit, nil
}

func validGitRemoteName(value string) bool {
	if value == "" || len(value) > 128 || value == "." ||
		strings.HasPrefix(value, "-") || containsControl(value) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validGitRefComponent(value string) bool {
	return value != "" && len(value) <= 255 &&
		!strings.HasPrefix(value, "-") &&
		!strings.HasPrefix(value, "/") &&
		!strings.HasSuffix(value, "/") &&
		!strings.HasSuffix(value, ".") &&
		!strings.HasSuffix(strings.ToLower(value), ".lock") &&
		!strings.Contains(value, "..") &&
		!strings.Contains(value, "@{") &&
		!strings.ContainsAny(value, " ~^:?*[\\") &&
		!containsControl(value)
}
