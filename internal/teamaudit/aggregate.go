package teamaudit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type remoteBranch struct {
	Name        string
	Ref         string
	OID         string
	Fingerprint string
	DeviceID    string
}

func (manager *Manager) aggregateLocked(
	ctx context.Context,
	updateWatermarks bool,
) ([]VerifiedEvent, map[string]remoteBranch, error) {
	branches, err := manager.listRemoteBranches(ctx)
	if err != nil {
		return nil, nil, err
	}
	watermarks, err := manager.loadWatermarks()
	if err != nil {
		return nil, nil, err
	}
	current := make(map[string]remoteBranch, len(branches))
	allEvents := make([]VerifiedEvent, 0)
	eventIDs := make(map[string]string)
	for _, branch := range branches {
		current[branch.Name] = branch
		if err := manager.fetchBranch(ctx, branch); err != nil {
			return nil, nil, err
		}
		events, err := manager.verifyBranch(ctx, branch)
		if err != nil {
			return nil, nil, err
		}
		if err := manager.checkWatermark(
			ctx,
			branch,
			events,
			watermarks.Branches[branch.Name],
		); err != nil {
			return nil, nil, err
		}
		for _, event := range events {
			if previous, duplicate := eventIDs[event.EventID]; duplicate {
				return nil, nil, fmt.Errorf(
					"audit event ID %s appears in branches %s and %s",
					event.EventID,
					previous,
					branch.Name,
				)
			}
			eventIDs[event.EventID] = branch.Name
			allEvents = append(allEvents, VerifiedEvent{
				Event:  event,
				Branch: branch.Name,
				Commit: branch.OID,
			})
			if len(allEvents) > maxAuditEvents {
				return nil, nil, errors.New(
					"team audit repository exceeds the total event limit",
				)
			}
		}
	}
	for name := range watermarks.Branches {
		if _, exists := current[name]; !exists {
			return nil, nil, fmt.Errorf(
				"audit rollback detected: remote branch %s was deleted",
				name,
			)
		}
	}
	sort.Slice(allEvents, func(first, second int) bool {
		return verifiedEventLess(allEvents[first], allEvents[second])
	})
	if updateWatermarks {
		next := watermarkFile{
			Version:  schemaVersion,
			Branches: make(map[string]watermark, len(current)),
		}
		for _, branch := range branches {
			branchEvents := make([]Event, 0)
			for _, event := range allEvents {
				if event.Branch == branch.Name {
					branchEvents = append(branchEvents, event.Event)
				}
			}
			next.Branches[branch.Name] = watermarkFor(branch, branchEvents)
		}
		if err := manager.saveWatermarks(next); err != nil {
			return nil, nil, err
		}
	}
	return allEvents, current, nil
}

func (manager *Manager) listRemoteBranches(
	ctx context.Context,
) ([]remoteBranch, error) {
	pattern := "refs/heads/audit/v1/" + manager.config.Mount + "/*"
	output, err := manager.runner.Run(
		ctx,
		"git",
		"ls-remote",
		"--heads",
		"--",
		manager.config.URL,
		pattern,
	)
	if err != nil {
		return nil, fmt.Errorf("list team audit branches: %w", err)
	}
	if len(output) > maxGitOutputBytes {
		return nil, errors.New("team audit branch listing is too large")
	}
	var branches []remoteBranch
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), maxEventLineBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || !commitPattern.MatchString(fields[0]) {
			return nil, errors.New("team audit remote returned a malformed ref")
		}
		branch, err := manager.parseBranch(fields[1], strings.ToLower(fields[0]))
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[branch.Name]; duplicate {
			return nil, fmt.Errorf(
				"team audit remote returned duplicate branch %s",
				branch.Name,
			)
		}
		seen[branch.Name] = struct{}{}
		branches = append(branches, branch)
		if len(branches) > maxAuditBranches {
			return nil, errors.New(
				"team audit remote exceeds the branch limit",
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan team audit refs: %w", err)
	}
	sort.Slice(branches, func(first, second int) bool {
		return branches[first].Name < branches[second].Name
	})
	return branches, nil
}

func (manager *Manager) parseBranch(
	ref string,
	oid string,
) (remoteBranch, error) {
	const prefix = "refs/heads/"
	if !strings.HasPrefix(ref, prefix) {
		return remoteBranch{}, errors.New("team audit remote returned a non-head ref")
	}
	name := strings.TrimPrefix(ref, prefix)
	parts := strings.Split(name, "/")
	if len(parts) != 5 || parts[0] != "audit" || parts[1] != "v1" ||
		parts[2] != manager.config.Mount {
		return remoteBranch{}, fmt.Errorf("invalid team audit branch %q", name)
	}
	fingerprint, err := normalizeFingerprint(parts[3])
	if err != nil || fingerprint != parts[3] {
		return remoteBranch{}, fmt.Errorf(
			"invalid signer fingerprint in audit branch %q",
			name,
		)
	}
	if err := validateEventID(parts[4]); err != nil {
		return remoteBranch{}, fmt.Errorf(
			"invalid device ID in audit branch %q",
			name,
		)
	}
	return remoteBranch{
		Name:        name,
		Ref:         ref,
		OID:         oid,
		Fingerprint: fingerprint,
		DeviceID:    parts[4],
	}, nil
}

func (manager *Manager) fetchBranch(
	ctx context.Context,
	branch remoteBranch,
) error {
	target := "refs/remotes/origin/" + branch.Name
	refspec := "+" + branch.Ref + ":" + target
	if _, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"fetch",
		"--no-tags",
		"origin",
		refspec,
	); err != nil {
		return fmt.Errorf("fetch team audit branch %s: %w", branch.Name, err)
	}
	return nil
}

func (manager *Manager) verifyBranch(
	ctx context.Context,
	branch remoteBranch,
) ([]Event, error) {
	if err := manager.verifyBranchTree(ctx, branch); err != nil {
		return nil, err
	}
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"show",
		branch.OID+":"+auditLogFilename,
	)
	if err != nil {
		return nil, fmt.Errorf("read team audit branch %s: %w", branch.Name, err)
	}
	if len(output) == 0 || len(output) > maxAuditLogBytes ||
		output[len(output)-1] != '\n' {
		return nil, fmt.Errorf(
			"team audit branch %s has an invalid NDJSON log",
			branch.Name,
		)
	}
	lines := bytes.Split(output[:len(output)-1], []byte{'\n'})
	if len(lines) > maxAuditEvents {
		return nil, fmt.Errorf(
			"team audit branch %s exceeds the event limit",
			branch.Name,
		)
	}
	return manager.verifyBranchEvents(ctx, branch, lines)
}

func (manager *Manager) verifyBranchTree(
	ctx context.Context,
	branch remoteBranch,
) error {
	output, err := manager.runner.Run(
		ctx,
		"git",
		"-C",
		manager.config.WorkDir,
		"ls-tree",
		"--name-only",
		branch.OID,
	)
	if err != nil {
		return fmt.Errorf("inspect team audit branch %s: %w", branch.Name, err)
	}
	if string(output) != auditLogFilename+"\n" {
		return fmt.Errorf(
			"team audit branch %s contains unexpected files",
			branch.Name,
		)
	}
	return nil
}

func (manager *Manager) verifyBranchEvents(
	ctx context.Context,
	branch remoteBranch,
	lines [][]byte,
) ([]Event, error) {
	events := make([]Event, len(lines))
	previousHash := zeroHash
	historical := make(map[string]*historicalAuthorization)
	for index, line := range lines {
		event, err := parseEventLine(line)
		if err != nil {
			return nil, fmt.Errorf(
				"parse team audit branch %s event %d: %w",
				branch.Name,
				index+1,
				err,
			)
		}
		if err := manager.verifyBranchEvent(
			ctx,
			branch,
			event,
			index,
			previousHash,
			historical,
		); err != nil {
			return nil, err
		}
		events[index] = event
		previousHash = event.RowHash
	}
	return events, nil
}

func (manager *Manager) verifyBranchEvent(
	ctx context.Context,
	branch remoteBranch,
	event Event,
	index int,
	previousHash string,
	historical map[string]*historicalAuthorization,
) error {
	if event.Seq != uint64(index+1) {
		return fmt.Errorf(
			"team audit branch %s has a sequence gap at event %d",
			branch.Name,
			index+1,
		)
	}
	if event.Mount != manager.config.Mount ||
		event.SignerFingerprint != branch.Fingerprint ||
		event.DeviceID != branch.DeviceID {
		return fmt.Errorf(
			"team audit branch %s identity does not match event %d",
			branch.Name,
			index+1,
		)
	}
	if event.PrevHash != previousHash {
		return fmt.Errorf(
			"team audit branch %s chain mismatch at event %d",
			branch.Name,
			index+1,
		)
	}
	if err := manager.verifyEvent(ctx, event); err != nil {
		return fmt.Errorf(
			"team audit branch %s event %d: %w",
			branch.Name,
			index+1,
			err,
		)
	}
	if err := manager.verifyHistoricalAuthorization(
		ctx,
		event,
		historical,
	); err != nil {
		return fmt.Errorf(
			"team audit branch %s event %d: %w",
			branch.Name,
			index+1,
			err,
		)
	}
	return nil
}
