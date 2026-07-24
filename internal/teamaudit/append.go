package teamaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type appendPlan struct {
	mount      string
	deviceID   string
	host       string
	snapshot   Snapshot
	eventIDs   []string
	timestamps []string
}

func (manager *Manager) appendLocked(
	ctx context.Context,
	expected Snapshot,
	inputs []Input,
) ([]Event, error) {
	plan, err := manager.prepareAppend(ctx, expected, inputs)
	if err != nil {
		return nil, err
	}
	var lastPushErr error
	for attempt := 0; attempt < 2; attempt++ {
		result, pushErr, confirmErr := manager.appendAttempt(ctx, inputs, plan)
		if confirmErr == nil && result != nil {
			return result, nil
		}
		if pushErr == nil {
			if confirmErr != nil {
				return nil, fmt.Errorf(
					"confirm pushed team audit batch: %w",
					confirmErr,
				)
			}
			return nil, errors.New(
				"pushed team audit batch was not present on the confirmed remote",
			)
		}
		lastPushErr = pushErr
		if attempt == 0 && isNonFastForward(pushErr) {
			continue
		}
		if confirmErr != nil {
			return nil, errors.Join(pushErr, confirmErr)
		}
		return nil, pushErr
	}
	return nil, fmt.Errorf(
		"push team audit batch after one non-fast-forward retry: %w",
		lastPushErr,
	)
}

func (manager *Manager) prepareAppend(
	ctx context.Context,
	expected Snapshot,
	inputs []Input,
) (appendPlan, error) {
	if err := manager.ensureRepository(ctx); err != nil {
		return appendPlan{}, err
	}
	deviceID, err := manager.loadOrCreateDeviceID(ctx)
	if err != nil {
		return appendPlan{}, err
	}
	host, err := manager.hostname()
	if err != nil {
		return appendPlan{}, fmt.Errorf("resolve audit host: %w", err)
	}
	if err := validateText("host", host, 255, false); err != nil {
		return appendPlan{}, err
	}
	eventIDs, timestamps, err := manager.prepareEventIdentifiers(inputs)
	if err != nil {
		return appendPlan{}, err
	}
	return appendPlan{
		mount:      manager.config.Mount,
		deviceID:   deviceID,
		host:       host,
		snapshot:   expected,
		eventIDs:   eventIDs,
		timestamps: timestamps,
	}, nil
}

func (manager *Manager) prepareEventIdentifiers(
	inputs []Input,
) ([]string, []string, error) {
	eventIDs := make([]string, len(inputs))
	timestamps := make([]string, len(inputs))
	for index := range inputs {
		eventIDs[index] = inputs[index].EventID
		if err := validateEventID(eventIDs[index]); err != nil {
			return nil, nil, fmt.Errorf("use audit event ID: %w", err)
		}
		timestamps[index] = manager.now().UTC().Format(
			"2006-01-02T15:04:05.000000000Z",
		)
	}
	return eventIDs, timestamps, nil
}

func (manager *Manager) appendAttempt(
	ctx context.Context,
	inputs []Input,
	plan appendPlan,
) ([]Event, error, error) {
	verified, _, err := manager.aggregateLocked(ctx, true)
	if err != nil {
		return nil, err, nil
	}
	existing, err := resolveExistingInputs(
		inputs,
		plan.eventIDs,
		plan.snapshot,
		verified,
	)
	if err != nil {
		return nil, err, nil
	}
	if existing != nil {
		return existing, nil, nil
	}
	identity, err := manager.prepareSigningIdentity(ctx, plan.snapshot)
	if err != nil {
		return nil, err, nil
	}
	branch := branchName(
		manager.config.Mount,
		identity.Fingerprint,
		plan.deviceID,
	)
	branchEvents := eventsForBranch(verified, branch)
	newEvents, err := manager.buildEvents(
		ctx,
		inputs,
		plan,
		identity,
		branchEvents,
	)
	if err != nil {
		return nil, err, nil
	}
	allBranchEvents := append(
		append([]Event(nil), branchEvents...),
		newEvents...,
	)
	_, pushErr := manager.commitAndPush(
		ctx,
		branch,
		allBranchEvents,
		identity,
	)
	confirmed, confirmErr := manager.confirmEvents(
		ctx,
		inputs,
		plan.eventIDs,
		plan.snapshot,
		newEvents,
	)
	return confirmed, pushErr, confirmErr
}

func (manager *Manager) prepareSigningIdentity(
	ctx context.Context,
	expected Snapshot,
) (signerIdentity, error) {
	current, err := manager.Preflight(ctx)
	if err != nil {
		return signerIdentity{}, err
	}
	if current != expected {
		return signerIdentity{}, errors.New(
			"team audit snapshot changed after the protected read",
		)
	}
	identity, err := manager.loadSignerIdentity(ctx, expected)
	if err != nil {
		return signerIdentity{}, err
	}
	current, err = manager.Preflight(ctx)
	if err != nil {
		return signerIdentity{}, err
	}
	if current != expected {
		return signerIdentity{}, errors.New(
			"team audit snapshot changed before signing",
		)
	}
	return identity, nil
}

func (manager *Manager) buildEvents(
	ctx context.Context,
	inputs []Input,
	plan appendPlan,
	identity signerIdentity,
	existing []Event,
) ([]Event, error) {
	previousHash := zeroHash
	if len(existing) > 0 {
		previousHash = existing[len(existing)-1].RowHash
	}
	events := make([]Event, len(inputs))
	for index, input := range inputs {
		event := newEvent(
			input,
			plan,
			identity,
			uint64(len(existing)+index+1),
			previousHash,
			index,
		)
		if err := manager.signEvent(ctx, &event); err != nil {
			return nil, err
		}
		events[index] = event
		previousHash = event.RowHash
	}
	return events, nil
}

func newEvent(
	input Input,
	plan appendPlan,
	identity signerIdentity,
	sequence uint64,
	previousHash string,
	index int,
) Event {
	return Event{
		SchemaVersion: schemaVersion,
		EventID:       plan.eventIDs[index],
		Seq:           sequence,
		Timestamp:     plan.timestamps[index],
		Mount:         plan.mount,
		Path:          input.Path,
		Action:        input.Action,
		Actor: Actor{
			Kind:       input.ActorKind,
			AgentLabel: input.AgentLabel,
		},
		Host:              plan.host,
		DeviceID:          plan.deviceID,
		Result:            "success",
		SignerFingerprint: identity.Fingerprint,
		SignerName:        identity.Name,
		SignerEmail:       identity.Email,
		StoreCommit:       plan.snapshot.StoreCommit,
		PolicyHash:        plan.snapshot.PolicyHash,
		TeamKeysHash:      plan.snapshot.TeamKeysHash,
		RecipientSetHash:  plan.snapshot.RecipientSetHash,
		PrevHash:          previousHash,
	}
}

func (manager *Manager) confirmEvents(
	ctx context.Context,
	inputs []Input,
	eventIDs []string,
	snapshot Snapshot,
	expected []Event,
) ([]Event, error) {
	verified, _, err := manager.aggregateLocked(ctx, true)
	if err != nil {
		return nil, err
	}
	found, err := resolveExistingInputs(
		inputs,
		eventIDs,
		snapshot,
		verified,
	)
	if err != nil || found == nil {
		return found, err
	}
	expectedByID := make(map[string]Event, len(expected))
	for _, event := range expected {
		expectedByID[event.EventID] = event
	}
	for _, event := range found {
		want := expectedByID[event.EventID]
		if event.RowHash != want.RowHash {
			return nil, fmt.Errorf(
				"remote audit event %s does not match the pushed event",
				event.EventID,
			)
		}
	}
	return found, nil
}

func resolveExistingInputs(
	inputs []Input,
	eventIDs []string,
	snapshot Snapshot,
	verified []VerifiedEvent,
) ([]Event, error) {
	byID := make(map[string]Event, len(verified))
	for _, event := range verified {
		byID[event.EventID] = event.Event
	}
	found := make([]Event, len(inputs))
	foundCount := 0
	for index, input := range inputs {
		event, exists := byID[eventIDs[index]]
		if !exists {
			continue
		}
		if event.Path != input.Path || event.Action != input.Action ||
			event.Actor.Kind != input.ActorKind ||
			event.Actor.AgentLabel != input.AgentLabel {
			return nil, fmt.Errorf(
				"audit event ID %s already exists with different attribution",
				eventIDs[index],
			)
		}
		if !snapshotMatchesEvent(snapshot, event) {
			return nil, fmt.Errorf(
				"audit event ID %s already exists for a different snapshot",
				eventIDs[index],
			)
		}
		found[index] = event
		foundCount++
	}
	switch {
	case foundCount == 0:
		return nil, nil
	case foundCount != len(inputs):
		return nil, errors.New(
			"audit batch is only partially present on the remote",
		)
	default:
		return found, nil
	}
}

func eventsForBranch(
	verified []VerifiedEvent,
	branch string,
) []Event {
	events := make([]Event, 0)
	for _, event := range verified {
		if event.Branch == branch {
			events = append(events, event.Event)
		}
	}
	sort.Slice(events, func(first, second int) bool {
		return events[first].Seq < events[second].Seq
	})
	return events
}

func verifiedEventLess(first, second VerifiedEvent) bool {
	switch {
	case first.Timestamp != second.Timestamp:
		return first.Timestamp < second.Timestamp
	case first.SignerFingerprint != second.SignerFingerprint:
		return first.SignerFingerprint < second.SignerFingerprint
	case first.DeviceID != second.DeviceID:
		return first.DeviceID < second.DeviceID
	case first.Seq != second.Seq:
		return first.Seq < second.Seq
	case first.EventID != second.EventID:
		return first.EventID < second.EventID
	default:
		return first.Branch < second.Branch
	}
}

func marshalEventLog(events []Event) ([]byte, error) {
	var buffer bytes.Buffer
	for index, event := range events {
		if err := event.validate(true); err != nil {
			return nil, fmt.Errorf("marshal team audit event %d: %w", index+1, err)
		}
		line, err := json.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("marshal team audit event %d: %w", index+1, err)
		}
		if len(line) > maxEventLineBytes {
			return nil, fmt.Errorf("team audit event %d is too large", index+1)
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	if buffer.Len() > maxAuditLogBytes {
		return nil, errors.New("team audit log exceeds the size limit")
	}
	return buffer.Bytes(), nil
}

func validateInputIDs(inputs []Input) error {
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if _, duplicate := seen[input.EventID]; duplicate {
			return fmt.Errorf(
				"append team audit: duplicate event ID %s",
				input.EventID,
			)
		}
		seen[input.EventID] = struct{}{}
	}
	return nil
}

func isNonFastForward(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "non-fast-forward") ||
		strings.Contains(message, "fetch first") ||
		strings.Contains(message, "[rejected]")
}
