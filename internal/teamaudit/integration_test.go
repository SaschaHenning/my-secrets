package teamaudit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerIntegration(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	fixture := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	managerOne := fixture.manager(t, "device-one")
	firstInputs := []Input{
		{
			EventID:    "10000000-0000-4000-8000-000000000001",
			Path:       "jasp-shared/prod/api",
			Action:     "get",
			ActorKind:  "ai",
			AgentLabel: "codex",
		},
		{
			EventID:   "10000000-0000-4000-8000-000000000002",
			Path:      "jasp-shared/prod/database",
			Action:    "totp",
			ActorKind: "human",
		},
	}
	appended, err := appendAfterPreflight(t, managerOne, ctx, firstInputs)
	if err != nil {
		t.Fatalf("append first batch: %v", err)
	}
	if len(appended) != 2 || appended[0].Seq != 1 || appended[1].Seq != 2 {
		t.Fatalf("first append sequences = %#v, want 1,2", appended)
	}
	if appended[0].SignerName != "Manifest Audit User" ||
		appended[0].SignerEmail != "manifest-audit@example.test" {
		t.Fatalf(
			"signer identity = %q <%s>, want manifest identity",
			appended[0].SignerName,
			appended[0].SignerEmail,
		)
	}
	firstBranch := branchName(
		fixture.config.Mount,
		fixture.fingerprint,
		appended[0].DeviceID,
	)
	firstOID := fixture.remoteOID(t, firstBranch)

	idempotent, err := appendAfterPreflight(t, managerOne, ctx, firstInputs[:1])
	if err != nil {
		t.Fatalf("idempotent append: %v", err)
	}
	if len(idempotent) != 1 || idempotent[0].RowHash != appended[0].RowHash {
		t.Fatalf("idempotent result = %#v, want original first event", idempotent)
	}
	if oid := fixture.remoteOID(t, firstBranch); oid != firstOID {
		t.Fatalf("idempotent append changed remote OID from %s to %s", firstOID, oid)
	}

	managerTwo := fixture.manager(t, "device-two")
	third, err := appendAfterPreflight(t, managerTwo, ctx, []Input{{
		EventID:    "10000000-0000-4000-8000-000000000003",
		Path:       "jasp-shared/staging/api",
		Action:     "get",
		ActorKind:  "script",
		AgentLabel: "deploy",
	}})
	if err != nil {
		t.Fatalf("append second device: %v", err)
	}
	if len(third) != 1 || third[0].Seq != 1 {
		t.Fatalf("second device sequence = %#v, want 1", third)
	}

	verified, err := managerOne.Aggregate(ctx)
	if err != nil {
		t.Fatalf("aggregate two devices: %v", err)
	}
	if len(verified) != 3 {
		t.Fatalf("aggregate count = %d, want 3", len(verified))
	}
	branches := map[string]struct{}{}
	for _, item := range verified {
		branches[item.Branch] = struct{}{}
	}
	if len(branches) != 2 {
		t.Fatalf("aggregate branch count = %d, want 2", len(branches))
	}
	if !sort.SliceIsSorted(verified, func(i, j int) bool {
		return verifiedEventLess(verified[i], verified[j])
	}) {
		t.Fatal("aggregate output is not stably sorted")
	}

	report, err := managerOne.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Branches != 2 || report.Events != 3 {
		t.Fatalf("verify report = %#v, want 2 branches and 3 events", report)
	}
}

func TestManagerRejectsTamperingAndRollback(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	t.Run("signature tampering", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		manager := fixture.manager(t, "device")
		appended, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:    "20000000-0000-4000-8000-000000000001",
			Path:       "jasp-shared/prod/api",
			Action:     "get",
			ActorKind:  "ai",
			AgentLabel: "codex",
		}})
		if err != nil {
			t.Fatalf("append: %v", err)
		}

		tampered := appended[0]
		tampered.Path = "jasp-shared/prod/database"
		if err := manager.verifyEvent(ctx, tampered); err == nil {
			t.Fatal("tampered signed event verified")
		}

		falseIdentity := appended[0]
		falseIdentity.SignerName = "Forged Historical Name"
		if err := manager.signEvent(ctx, &falseIdentity); err != nil {
			t.Fatalf("sign false historical identity: %v", err)
		}
		if err := manager.verifyHistoricalAuthorization(
			ctx,
			falseIdentity,
			make(map[string]*historicalAuthorization),
		); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("false historical identity error = %v", err)
		}

		orphanCommit, teamHash, recipientHash := fixture.createOrphanStoreCommit(t)
		orphanIdentity := appended[0]
		orphanIdentity.StoreCommit = orphanCommit
		orphanIdentity.TeamKeysHash = teamHash
		orphanIdentity.RecipientSetHash = recipientHash
		orphanIdentity.SignerName = "Orphan Audit User"
		orphanIdentity.SignerEmail = "orphan-audit@example.test"
		if err := manager.signEvent(ctx, &orphanIdentity); err != nil {
			t.Fatalf("sign orphan identity event: %v", err)
		}
		if err := manager.verifyHistoricalAuthorization(
			ctx,
			orphanIdentity,
			make(map[string]*historicalAuthorization),
		); err == nil || !strings.Contains(err.Error(), "trusted shared-store history") {
			t.Fatalf("orphan store commit error = %v", err)
		}
	})

	t.Run("remote rollback", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		manager := fixture.manager(t, "device")
		first, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "30000000-0000-4000-8000-000000000001",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err != nil {
			t.Fatalf("append first event: %v", err)
		}
		branch := branchName(
			fixture.config.Mount,
			fixture.fingerprint,
			first[0].DeviceID,
		)
		firstOID := fixture.remoteOID(t, branch)

		_, err = appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "30000000-0000-4000-8000-000000000002",
			Path:      "jasp-shared/prod/database",
			Action:    "get",
			ActorKind: "human",
		}})
		if err != nil {
			t.Fatalf("append second event: %v", err)
		}

		fixture.forceRemoteBranch(t, branch, firstOID)
		if _, err := manager.Aggregate(ctx); err == nil ||
			!strings.Contains(err.Error(), "rollback") {
			t.Fatalf("rollback error = %v", err)
		}
	})

	t.Run("remote branch deletion", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		manager := fixture.manager(t, "device")
		appended, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "31000000-0000-4000-8000-000000000001",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		branch := branchName(
			fixture.config.Mount,
			fixture.fingerprint,
			appended[0].DeviceID,
		)
		fixture.deleteRemoteBranch(t, branch)
		if _, err := manager.Aggregate(ctx); err == nil ||
			!strings.Contains(err.Error(), "deleted") {
			t.Fatalf("branch deletion error = %v", err)
		}
	})
}

func TestManagerSerializesConcurrentAppends(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	fixture := newIntegrationFixture(t)
	manager := fixture.manager(t, "device")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const count = 4
	errs := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := appendAfterPreflight(t, manager, ctx, []Input{{
				EventID: fmt.Sprintf(
					"40000000-0000-4000-8000-%012d",
					index+1,
				),
				Path:       fmt.Sprintf("jasp-shared/prod/service-%d", index+1),
				Action:     "get",
				ActorKind:  "ai",
				AgentLabel: "codex",
			}})
			errs <- err
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}

	events, err := manager.Aggregate(ctx)
	if err != nil {
		t.Fatalf("aggregate concurrent appends: %v", err)
	}
	if len(events) != count {
		t.Fatalf("event count = %d, want %d", len(events), count)
	}
	for index, event := range events {
		if event.Seq != uint64(index+1) {
			t.Fatalf("event %d sequence = %d, want %d", index, event.Seq, index+1)
		}
	}
}

func TestManagerRequiresCurrentMemberAndRecipient(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	t.Run("team member", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		writeTestFile(t, fixture.config.TeamKeysPath, []byte(
			"version: 1\nmembers:\n"+
				"  - name: Other User\n"+
				"    email: other@example.test\n"+
				"    fingerprint: 9999999999999999999999999999999999999999\n",
		))
		fixture.commitStoreMetadata(t, "test: replace team member")
		manager := fixture.manager(t, "device")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "45000000-0000-4000-8000-000000000001",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err == nil || !strings.Contains(err.Error(), "current team member") {
			t.Fatalf("non-member error = %v", err)
		}
	})

	t.Run("store recipient", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		writeTestFile(
			t,
			fixture.config.RecipientPath,
			[]byte("9999999999999999999999999999999999999999\n"),
		)
		fixture.commitStoreMetadata(t, "test: replace recipient")
		manager := fixture.manager(t, "device")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "45000000-0000-4000-8000-000000000002",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err == nil || !strings.Contains(err.Error(), "current shared-store recipient") {
			t.Fatalf("non-recipient error = %v", err)
		}
	})

	t.Run("committed metadata", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		writeTestFile(
			t,
			fixture.config.RecipientPath,
			[]byte(fixture.fingerprint+"\n# uncommitted change\n"),
		)
		manager := fixture.manager(t, "device")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "45000000-0000-4000-8000-000000000003",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err == nil || !strings.Contains(err.Error(), "differs from recorded store commit") {
			t.Fatalf("dirty metadata error = %v", err)
		}
	})

	t.Run("historical signer after team removal", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		manager := fixture.manager(t, "device")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:   "45000000-0000-4000-8000-000000000004",
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}}); err != nil {
			t.Fatalf("append historical event: %v", err)
		}
		writeTestFile(t, fixture.config.TeamKeysPath, []byte(
			"version: 1\nmembers:\n"+
				"  - name: Replacement User\n"+
				"    email: replacement@example.test\n"+
				"    fingerprint: 9999999999999999999999999999999999999999\n",
		))
		writeTestFile(
			t,
			fixture.config.RecipientPath,
			[]byte("9999999999999999999999999999999999999999\n"),
		)
		fixture.commitStoreMetadata(t, "test: remove historical member")

		events, err := manager.Aggregate(ctx)
		if err != nil {
			t.Fatalf("aggregate historical signer: %v", err)
		}
		if len(events) != 1 ||
			events[0].SignerFingerprint != fixture.fingerprint {
			t.Fatalf("historical events = %#v", events)
		}
	})

	t.Run("published store commit", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		writeTestFile(
			t,
			filepath.Join(fixture.config.StorePath, "version.txt"),
			[]byte("local ahead\n"),
		)
		runTestCommand(
			t,
			fixture.config.StorePath,
			fixture.env,
			"git",
			"add",
			"--",
			"version.txt",
		)
		runTestCommand(
			t,
			fixture.config.StorePath,
			fixture.env,
			"git",
			"-c",
			"user.name=Generated Audit Test",
			"-c",
			"user.email=generated-audit@example.test",
			"commit",
			"-m",
			"test: create unpublished store commit",
		)
		manager := fixture.manager(t, "device")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if _, err := manager.Preflight(ctx); err == nil ||
			!strings.Contains(err.Error(), "not published") {
			t.Fatalf("unpublished store error = %v", err)
		}
		runTestCommand(
			t,
			fixture.config.StorePath,
			fixture.env,
			"git",
			"push",
			"origin",
			"main",
		)
		if _, err := manager.Preflight(ctx); err != nil {
			t.Fatalf("published store preflight: %v", err)
		}
	})
}

func TestManagerBindsAppendToCallerSnapshot(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	fixture := newIntegrationFixture(t)
	manager := fixture.manager(t, "snapshot")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	assertRejected := func(
		label string,
		expected Snapshot,
		eventID string,
	) {
		t.Helper()
		_, err := manager.AppendBatch(ctx, expected, []Input{{
			EventID:   eventID,
			Path:      "jasp-shared/prod/api",
			Action:    "get",
			ActorKind: "human",
		}})
		if err == nil || !strings.Contains(err.Error(), "snapshot changed") {
			t.Fatalf("%s snapshot error = %v", label, err)
		}
	}

	policyData, err := os.ReadFile(fixture.config.PolicyPath)
	if err != nil {
		t.Fatalf("read policy fixture: %v", err)
	}
	policySnapshot, err := manager.Preflight(ctx)
	if err != nil {
		t.Fatalf("policy preflight: %v", err)
	}
	writeTestFile(
		t,
		fixture.config.PolicyPath,
		append(append([]byte(nil), policyData...), []byte("# changed\n")...),
	)
	assertRejected(
		"policy",
		policySnapshot,
		"46000000-0000-4000-8000-000000000001",
	)
	writeTestFile(t, fixture.config.PolicyPath, policyData)

	storeSnapshot, err := manager.Preflight(ctx)
	if err != nil {
		t.Fatalf("store preflight: %v", err)
	}
	writeTestFile(
		t,
		filepath.Join(fixture.config.StorePath, "version.txt"),
		[]byte("published change\n"),
	)
	fixture.commitAndPushStoreFiles(
		t,
		"test: publish store change",
		"version.txt",
	)
	assertRejected(
		"store",
		storeSnapshot,
		"46000000-0000-4000-8000-000000000002",
	)

	teamSnapshot, err := manager.Preflight(ctx)
	if err != nil {
		t.Fatalf("team key preflight: %v", err)
	}
	writeTestFile(t, fixture.config.TeamKeysPath, []byte(
		"version: 1\nmembers:\n"+
			"  - name: Manifest Audit User\n"+
			"    email: manifest-audit@example.test\n"+
			"    fingerprint: "+fixture.fingerprint+"\n"+
			"  - name: Second Audit User\n"+
			"    email: second-audit@example.test\n"+
			"    fingerprint: 9999999999999999999999999999999999999999\n",
	))
	fixture.commitStoreMetadata(t, "test: publish team key change")
	assertRejected(
		"team key",
		teamSnapshot,
		"46000000-0000-4000-8000-000000000003",
	)

	recipientSnapshot, err := manager.Preflight(ctx)
	if err != nil {
		t.Fatalf("recipient preflight: %v", err)
	}
	writeTestFile(
		t,
		fixture.config.RecipientPath,
		[]byte(
			fixture.fingerprint+"\n"+
				"9999999999999999999999999999999999999999\n",
		),
	)
	fixture.commitStoreMetadata(t, "test: publish recipient change")
	assertRejected(
		"recipient",
		recipientSnapshot,
		"46000000-0000-4000-8000-000000000004",
	)

	current, err := manager.Preflight(ctx)
	if err != nil {
		t.Fatalf("current preflight: %v", err)
	}
	appended, err := manager.AppendBatch(ctx, current, []Input{{
		EventID:   "46000000-0000-4000-8000-000000000005",
		Path:      "jasp-shared/prod/api",
		Action:    "get",
		ActorKind: "human",
	}})
	if err != nil {
		t.Fatalf("append current snapshot: %v", err)
	}
	if len(appended) != 1 || !snapshotMatchesEvent(current, appended[0]) {
		t.Fatalf("appended snapshot = %#v, want %#v", appended, current)
	}

	different := current
	different.PolicyHash = strings.Repeat("e", 64)
	if _, err := manager.AppendBatch(ctx, different, []Input{{
		EventID:   appended[0].EventID,
		Path:      appended[0].Path,
		Action:    appended[0].Action,
		ActorKind: appended[0].Actor.Kind,
	}}); err == nil || !strings.Contains(err.Error(), "different snapshot") {
		t.Fatalf("idempotent snapshot mismatch error = %v", err)
	}

	latePolicyData, err := os.ReadFile(fixture.config.PolicyPath)
	if err != nil {
		t.Fatalf("read late policy fixture: %v", err)
	}
	lateRunner := &afterSignerLookupRunner{
		delegate: fixture.runner,
		after: func() error {
			return os.WriteFile(
				fixture.config.PolicyPath,
				append(
					append([]byte(nil), latePolicyData...),
					[]byte("# changed during append\n")...,
				),
				0o600,
			)
		},
	}
	lateManager, err := NewManager(
		fixture.managerConfig("snapshot-late"),
		lateRunner,
	)
	if err != nil {
		t.Fatalf("new late snapshot manager: %v", err)
	}
	lateManager.hostname = func() (string, error) {
		return "integration-host", nil
	}
	lateSnapshot, err := lateManager.Preflight(ctx)
	if err != nil {
		t.Fatalf("late snapshot preflight: %v", err)
	}
	if _, err := lateManager.AppendBatch(ctx, lateSnapshot, []Input{{
		EventID:   "46000000-0000-4000-8000-000000000006",
		Path:      "jasp-shared/prod/api",
		Action:    "get",
		ActorKind: "human",
	}}); err == nil || !strings.Contains(err.Error(), "before signing") {
		t.Fatalf("late snapshot change error = %v", err)
	}
}

func TestDeviceIDIsStableAcrossMountManagers(t *testing.T) {
	root := t.TempDir()
	devicePath := filepath.Join(root, "config", "team-audit", "device.id")
	configFor := func(mount string) Config {
		store := filepath.Join(root, mount+"-store")
		return Config{
			Mount:              mount,
			URL:                filepath.Join(root, mount+"-audit.git"),
			SigningFingerprint: testFingerprint,
			StorePath:          store,
			PolicyPath:         filepath.Join(root, mount+"-policy.yaml"),
			TeamKeysPath:       filepath.Join(store, "team-keys.yaml"),
			RecipientPath:      filepath.Join(store, ".gpg-id"),
			WorkDir:            filepath.Join(root, mount+"-work"),
			StateDir:           filepath.Join(root, mount+"-state"),
			DeviceIDPath:       devicePath,
		}
	}
	first, err := NewManager(configFor("mount-one"), nil)
	if err != nil {
		t.Fatalf("new first manager: %v", err)
	}
	second, err := NewManager(configFor("mount-two"), nil)
	if err != nil {
		t.Fatalf("new second manager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		wait sync.WaitGroup
		ids  [2]string
		errs [2]error
	)
	for index, manager := range []*Manager{first, second} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ids[index], errs[index] = manager.loadOrCreateDeviceID(ctx)
		}()
	}
	wait.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("create shared device ID: %v", err)
		}
	}
	if ids[0] != ids[1] {
		t.Fatalf("device IDs differ across mounts: %q != %q", ids[0], ids[1])
	}
	info, err := os.Stat(devicePath)
	if err != nil {
		t.Fatalf("stat device ID: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("device ID mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestManagerConfirmsAmbiguousPushAndRetriesOneNonFastForward(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	t.Run("ambiguous push already reached remote", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("ambiguous")
		runner := &postPushErrorRunner{delegate: fixture.runner}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		manager.hostname = func() (string, error) {
			return "integration-host", nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		events, err := appendAfterPreflight(t, manager, ctx, []Input{{
			EventID:    "50000000-0000-4000-8000-000000000001",
			Path:       "jasp-shared/prod/api",
			Action:     "get",
			ActorKind:  "ai",
			AgentLabel: "codex",
		}})
		if err != nil {
			t.Fatalf("append after ambiguous push: %v", err)
		}
		if len(events) != 1 || runner.pushes != 1 {
			t.Fatalf("events=%d pushes=%d, want 1 and 1", len(events), runner.pushes)
		}
	})

	t.Run("retry confirms push after response and confirmation loss", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("ambiguous-retry")
		runner := &lostPushAndConfirmationRunner{delegate: fixture.runner}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		manager.hostname = func() (string, error) {
			return "integration-host", nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		snapshot, err := manager.Preflight(ctx)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		inputs := []Input{{
			EventID:    "50000000-0000-4000-8000-000000000002",
			Path:       "jasp-shared/prod/api",
			Action:     "get",
			ActorKind:  "ai",
			AgentLabel: "codex",
		}}

		if _, err := manager.AppendBatch(ctx, snapshot, inputs); err == nil ||
			!strings.Contains(err.Error(), "simulated confirmation loss") {
			t.Fatalf("first ambiguous append error = %v", err)
		}
		events, err := manager.AppendBatch(ctx, snapshot, inputs)
		if err != nil {
			t.Fatalf("retry ambiguous append: %v", err)
		}
		if len(events) != 1 || events[0].EventID != inputs[0].EventID {
			t.Fatalf("retry events = %#v", events)
		}
		verified, err := manager.Aggregate(ctx)
		if err != nil {
			t.Fatalf("aggregate retry: %v", err)
		}
		if len(verified) != 1 || runner.pushes != 1 {
			t.Fatalf(
				"verified=%d pushes=%d, want one event and one push",
				len(verified),
				runner.pushes,
			)
		}
	})

	t.Run("one non-fast-forward retry", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		const sharedDeviceID = "55555555-5555-4555-8555-555555555555"
		firstConfig := fixture.managerConfig("nff-first")
		secondConfig := fixture.managerConfig("nff-second")
		writeDeviceID(t, firstConfig, sharedDeviceID)
		writeDeviceID(t, secondConfig, sharedDeviceID)

		second, err := NewManager(secondConfig, fixture.runner)
		if err != nil {
			t.Fatalf("new competing manager: %v", err)
		}
		second.hostname = func() (string, error) {
			return "competing-host", nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		runner := &beforePushRunner{
			delegate: fixture.runner,
			beforeFirstPush: func() error {
				_, appendErr := appendAfterPreflight(t, second, ctx, []Input{{
					EventID:   "51000000-0000-4000-8000-000000000001",
					Path:      "jasp-shared/prod/competitor",
					Action:    "get",
					ActorKind: "human",
				}})
				return appendErr
			},
		}
		first, err := NewManager(firstConfig, runner)
		if err != nil {
			t.Fatalf("new first manager: %v", err)
		}
		first.hostname = func() (string, error) {
			return "first-host", nil
		}

		events, err := appendAfterPreflight(t, first, ctx, []Input{{
			EventID:    "51000000-0000-4000-8000-000000000002",
			Path:       "jasp-shared/prod/api",
			Action:     "get",
			ActorKind:  "ai",
			AgentLabel: "codex",
		}})
		if err != nil {
			t.Fatalf("append after NFF retry: %v", err)
		}
		if len(events) != 1 || events[0].Seq != 2 || runner.pushes != 2 {
			t.Fatalf(
				"events=%#v pushes=%d, want sequence 2 and exactly 2 pushes",
				events,
				runner.pushes,
			)
		}
	})
}

func TestProvisionProvesGenericRemoteWriteAndCleanup(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")

	t.Run("writes confirms and removes a unique probe branch", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		manager := fixture.manager(t, "provision")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("durable write probe refs = %q", refs)
		}
	})

	t.Run("caller cancellation after accepted push still removes probe", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		config := fixture.managerConfig("cancel-after-push")
		runner := &cancelAfterProbePushRunner{
			delegate: fixture.runner,
			cancel:   cancel,
		}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		manager.hostname = func() (string, error) {
			return "integration-host", nil
		}

		if err := manager.Provision(ctx); err != nil {
			t.Fatalf("provision after accepted push: %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("cancelled provision left probe refs = %q", refs)
		}
	})

	t.Run("read only local bare remote fails closed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("filesystem permission denial is not reliable as root")
		}
		fixture := newIntegrationFixture(t)
		restore := makeTreeReadOnly(t, fixture.remote)
		t.Cleanup(restore)
		manager := fixture.manager(t, "read-only")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err == nil ||
			!strings.Contains(err.Error(), "write probe") {
			t.Fatalf("read-only provision error = %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("read-only remote probe refs = %q", refs)
		}
	})

	t.Run("runner push error fails closed", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("push-error")
		runner := &rejectProbePushRunner{delegate: fixture.runner}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		manager.hostname = func() (string, error) {
			return "integration-host", nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err == nil ||
			!strings.Contains(err.Error(), "simulated write denial") {
			t.Fatalf("runner denial error = %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("runner denial probe refs = %q", refs)
		}
	})

	t.Run("confirmation failure cleans up and fails closed", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("confirm-error")
		runner := &probeStageErrorRunner{
			delegate: fixture.runner,
			stage:    "confirm-create",
		}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err == nil ||
			!strings.Contains(err.Error(), "simulated probe confirmation loss") {
			t.Fatalf("confirmation loss error = %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("confirmation loss probe refs = %q", refs)
		}
	})

	t.Run("cleanup confirmation failure fails closed", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("cleanup-confirm-error")
		runner := &probeStageErrorRunner{
			delegate: fixture.runner,
			stage:    "confirm-delete",
		}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err == nil ||
			!strings.Contains(err.Error(), "simulated probe confirmation loss") {
			t.Fatalf("cleanup confirmation loss error = %v", err)
		}
		if refs := fixture.probeRefs(t); refs != "" {
			t.Fatalf("cleanup confirmation loss probe refs = %q", refs)
		}
	})

	t.Run("remote cleanup denial fails closed", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		runTestCommand(
			t,
			"",
			fixture.env,
			"git",
			"--git-dir",
			fixture.remote,
			"config",
			"receive.denyDeletes",
			"true",
		)
		manager := fixture.manager(t, "cleanup-denied")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := manager.Provision(ctx); err == nil ||
			!strings.Contains(err.Error(), "cleanup") {
			t.Fatalf("cleanup denial error = %v", err)
		}
		if refs := fixture.probeRefs(t); refs == "" {
			t.Fatal("cleanup denial did not preserve evidence of the failed cleanup")
		}
	})

	t.Run("exact cleanup lease preserves an interposed foreign ref", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		config := fixture.managerConfig("cleanup-interposition")
		runner := &probeDeleteInterpositionRunner{
			delegate: fixture.runner,
			workDir:  config.WorkDir,
		}
		manager, err := NewManager(config, runner)
		if err != nil {
			t.Fatalf("new manager: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		err = manager.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "ownership changed") {
			t.Fatalf("interposed cleanup error = %v", err)
		}
		if runner.foreignOID == "" || runner.branch == "" {
			t.Fatalf(
				"interposition did not capture foreign ref: oid=%q branch=%q",
				runner.foreignOID,
				runner.branch,
			)
		}
		if got := fixture.remoteOID(t, runner.branch); got != runner.foreignOID {
			t.Fatalf(
				"foreign probe ref changed: got %s, want %s",
				got,
				runner.foreignOID,
			)
		}
	})
}

type integrationFixture struct {
	root        string
	remote      string
	gpgHome     string
	fingerprint string
	config      Config
	env         []string
	runner      Runner
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()

	root := t.TempDir()
	environment := newHermeticTestEnvironment(t, root)
	runner := hermeticTestRunner{env: environment}
	remote := filepath.Join(root, "audit.git")
	runTestCommand(
		t,
		"",
		environment,
		"git",
		"init",
		"--bare",
		"--initial-branch=main",
		remote,
	)

	gpgHome, err := os.MkdirTemp("", "mys-gpg-")
	if err != nil {
		t.Fatalf("mkdir short GNUPGHOME: %v", err)
	}
	gpgconf, _ := exec.LookPath("gpgconf")
	t.Cleanup(func() {
		if gpgconf != "" {
			command := exec.Command(
				gpgconf,
				"--homedir",
				gpgHome,
				"--kill",
				"gpg-agent",
			)
			_ = command.Run()
		}
		if err := os.RemoveAll(gpgHome); err != nil {
			t.Errorf("remove GNUPGHOME: %v", err)
		}
	})
	uid := "Generated GPG Key <generated-gpg@example.test>"
	runTestCommand(
		t,
		"",
		environment,
		"gpg",
		"--homedir",
		gpgHome,
		"--batch",
		"--pinentry-mode",
		"loopback",
		"--passphrase",
		"",
		"--quick-generate-key",
		uid,
		"ed25519",
		"sign",
		"0",
	)
	fingerprint := generatedFingerprint(t, environment, gpgHome)

	store := filepath.Join(root, "store")
	storeRemote := filepath.Join(root, "store.git")
	runTestCommand(
		t,
		"",
		environment,
		"git",
		"init",
		"--bare",
		"--initial-branch=main",
		storeRemote,
	)
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	policyPath := filepath.Join(root, "shared-policy.yaml")
	writeTestFile(t, policyPath, []byte("version: 1\n"))
	writeTestFile(t, filepath.Join(store, "team-keys.yaml"), []byte(
		"version: 1\nmembers:\n"+
			"  - name: Manifest Audit User\n"+
			"    email: manifest-audit@example.test\n"+
			"    fingerprint: "+fingerprint+"\n",
	))
	writeTestFile(t, filepath.Join(store, ".gpg-id"), []byte(fingerprint+"\n"))
	runTestCommand(
		t,
		"",
		environment,
		"git",
		"init",
		"--initial-branch=main",
		store,
	)
	runTestCommand(t, store, environment, "git", "add", "--", ".")
	runTestCommand(
		t,
		store,
		environment,
		"git",
		"-c",
		"user.name=Generated Audit Test",
		"-c",
		"user.email=generated-audit@example.test",
		"commit",
		"-m",
		"test: initialize store",
	)
	runTestCommand(
		t,
		store,
		environment,
		"git",
		"remote",
		"add",
		"origin",
		storeRemote,
	)
	runTestCommand(
		t,
		store,
		environment,
		"git",
		"push",
		"-u",
		"origin",
		"main",
	)

	config := Config{
		Mount:              "jasp-shared",
		URL:                remote,
		SigningFingerprint: fingerprint,
		StorePath:          store,
		PolicyPath:         policyPath,
		TeamKeysPath:       filepath.Join(store, "team-keys.yaml"),
		RecipientPath:      filepath.Join(store, ".gpg-id"),
		GPGHome:            gpgHome,
	}
	return &integrationFixture{
		root:        root,
		remote:      remote,
		gpgHome:     gpgHome,
		fingerprint: fingerprint,
		config:      config,
		env:         environment,
		runner:      runner,
	}
}

func (fixture *integrationFixture) manager(t *testing.T, label string) *Manager {
	t.Helper()

	config := fixture.managerConfig(label)
	manager, err := NewManager(config, fixture.runner)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	base := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	var (
		mu    sync.Mutex
		ticks int
	)
	manager.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		ticks++
		return base.Add(time.Duration(ticks) * time.Nanosecond)
	}
	manager.hostname = func() (string, error) {
		return "integration-host", nil
	}
	return manager
}

func (fixture *integrationFixture) managerConfig(label string) Config {
	config := fixture.config
	config.WorkDir = filepath.Join(fixture.root, label+"-work")
	config.StateDir = filepath.Join(fixture.root, label+"-state")
	config.DeviceIDPath = filepath.Join(config.StateDir, "device-id")
	return config
}

func appendAfterPreflight(
	t *testing.T,
	manager *Manager,
	ctx context.Context,
	inputs []Input,
) ([]Event, error) {
	t.Helper()
	snapshot, err := manager.Preflight(ctx)
	if err != nil {
		return nil, err
	}
	return manager.AppendBatch(ctx, snapshot, inputs)
}

func (fixture *integrationFixture) remoteOID(t *testing.T, branch string) string {
	t.Helper()
	out := runTestCommand(
		t,
		"",
		fixture.env,
		"git",
		"--git-dir",
		fixture.remote,
		"rev-parse",
		"refs/heads/"+branch,
	)
	return strings.TrimSpace(string(out))
}

func (fixture *integrationFixture) probeRefs(t *testing.T) string {
	t.Helper()
	output := runTestCommand(
		t,
		"",
		fixture.env,
		"git",
		"--git-dir",
		fixture.remote,
		"for-each-ref",
		"--format=%(refname)",
		"refs/heads/mys-team-audit-probe/",
	)
	return strings.TrimSpace(string(output))
}

func (fixture *integrationFixture) forceRemoteBranch(
	t *testing.T,
	branch string,
	oid string,
) {
	t.Helper()
	runTestCommand(
		t,
		"",
		fixture.env,
		"git",
		"--git-dir",
		fixture.remote,
		"update-ref",
		"refs/heads/"+branch,
		oid,
	)
}

func (fixture *integrationFixture) deleteRemoteBranch(t *testing.T, branch string) {
	t.Helper()
	runTestCommand(
		t,
		"",
		fixture.env,
		"git",
		"--git-dir",
		fixture.remote,
		"update-ref",
		"-d",
		"refs/heads/"+branch,
	)
}

func (fixture *integrationFixture) commitStoreMetadata(
	t *testing.T,
	message string,
) {
	t.Helper()
	fixture.commitAndPushStoreFiles(
		t,
		message,
		"team-keys.yaml",
		".gpg-id",
	)
}

func (fixture *integrationFixture) commitAndPushStoreFiles(
	t *testing.T,
	message string,
	files ...string,
) {
	t.Helper()
	if len(files) == 0 {
		t.Fatal("commit store files requires at least one path")
	}
	addArguments := append([]string{"add", "--"}, files...)
	runTestCommand(
		t,
		fixture.config.StorePath,
		fixture.env,
		"git",
		addArguments...,
	)
	runTestCommand(
		t,
		fixture.config.StorePath,
		fixture.env,
		"git",
		"-c",
		"user.name=Generated Audit Test",
		"-c",
		"user.email=generated-audit@example.test",
		"commit",
		"-m",
		message,
	)
	runTestCommand(
		t,
		fixture.config.StorePath,
		fixture.env,
		"git",
		"push",
		"origin",
		"main",
	)
}

func (fixture *integrationFixture) createOrphanStoreCommit(
	t *testing.T,
) (string, string, string) {
	t.Helper()
	store := fixture.config.StorePath
	runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"checkout",
		"--orphan",
		"untrusted-audit",
	)
	runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"rm",
		"-r",
		"--cached",
		"--ignore-unmatch",
		"--",
		".",
	)
	teamData := []byte(
		"version: 1\nmembers:\n" +
			"  - name: Orphan Audit User\n" +
			"    email: orphan-audit@example.test\n" +
			"    fingerprint: " + fixture.fingerprint + "\n",
	)
	recipientData := []byte(fixture.fingerprint + "\n")
	writeTestFile(t, fixture.config.TeamKeysPath, teamData)
	writeTestFile(t, fixture.config.RecipientPath, recipientData)
	runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"add",
		"--",
		"team-keys.yaml",
		".gpg-id",
	)
	runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"-c",
		"user.name=Orphan Audit User",
		"-c",
		"user.email=orphan-audit@example.test",
		"commit",
		"-m",
		"test: create untrusted audit metadata",
	)
	commit := strings.TrimSpace(string(runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"rev-parse",
		"HEAD",
	)))
	runTestCommand(
		t,
		store,
		fixture.env,
		"git",
		"checkout",
		"--force",
		"main",
	)
	recipientHash, err := hashRecipientData(recipientData)
	if err != nil {
		t.Fatalf("hash orphan recipients: %v", err)
	}
	return commit, hashBytes(teamData), recipientHash
}

type postPushErrorRunner struct {
	delegate Runner
	mu       sync.Mutex
	pushes   int
}

func (runner *postPushErrorRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	output, err := runner.delegate.Run(ctx, name, args...)
	if name != "git" || !containsArgument(args, "push") {
		return output, err
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.pushes++
	if runner.pushes == 1 && err == nil {
		return output, errors.New("simulated connection loss after receive")
	}
	return output, err
}

type lostPushAndConfirmationRunner struct {
	delegate             Runner
	mu                   sync.Mutex
	pushes               int
	failNextConfirmation bool
}

func (runner *lostPushAndConfirmationRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	runner.mu.Lock()
	if name == "git" &&
		containsArgument(args, "ls-remote") &&
		runner.failNextConfirmation {
		runner.failNextConfirmation = false
		runner.mu.Unlock()
		return nil, errors.New("simulated confirmation loss")
	}
	runner.mu.Unlock()

	output, err := runner.delegate.Run(ctx, name, args...)
	if name != "git" || !containsArgument(args, "push") || err != nil {
		return output, err
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.pushes++
	if runner.pushes == 1 {
		runner.failNextConfirmation = true
		return output, errors.New("simulated push response loss")
	}
	return output, nil
}

type rejectProbePushRunner struct {
	delegate Runner
}

type cancelAfterProbePushRunner struct {
	delegate Runner
	cancel   context.CancelFunc
	once     sync.Once
}

type probeDeleteInterpositionRunner struct {
	delegate   Runner
	workDir    string
	once       sync.Once
	foreignOID string
	branch     string
	err        error
}

func (runner *probeDeleteInterpositionRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	isProbeDelete := name == "git" &&
		containsArgument(args, "push") &&
		containsArgumentFragment(args, "mys-team-audit-probe/") &&
		containsArgumentPrefix(args, ":refs/heads/mys-team-audit-probe/")
	if !isProbeDelete {
		return runner.delegate.Run(ctx, name, args...)
	}
	runner.once.Do(func() {
		for _, argument := range args {
			if strings.HasPrefix(
				argument,
				":refs/heads/mys-team-audit-probe/",
			) {
				runner.branch = strings.TrimPrefix(argument, ":refs/heads/")
				break
			}
		}
		if runner.branch == "" {
			runner.err = errors.New("probe delete ref argument is missing")
			return
		}
		treeOutput, err := runner.delegate.Run(
			ctx,
			"git",
			"-C",
			runner.workDir,
			"hash-object",
			"-w",
			"-t",
			"tree",
			os.DevNull,
		)
		if err != nil {
			runner.err = fmt.Errorf("create foreign probe tree: %w", err)
			return
		}
		tree := strings.TrimSpace(string(treeOutput))
		commitOutput, err := runner.delegate.Run(
			ctx,
			"git",
			"-C",
			runner.workDir,
			"-c",
			"user.name=Foreign Probe Writer",
			"-c",
			"user.email=foreign-probe@localhost.invalid",
			"-c",
			"commit.gpgSign=false",
			"commit-tree",
			tree,
			"-m",
			"foreign probe ref interposition",
		)
		if err != nil {
			runner.err = fmt.Errorf("create foreign probe commit: %w", err)
			return
		}
		runner.foreignOID = strings.TrimSpace(string(commitOutput))
		_, err = runner.delegate.Run(
			ctx,
			"git",
			"-C",
			runner.workDir,
			"push",
			"--porcelain",
			"origin",
			"+"+runner.foreignOID+":refs/heads/"+runner.branch,
		)
		if err != nil {
			runner.err = fmt.Errorf("interpose foreign probe ref: %w", err)
		}
	})
	if runner.err != nil {
		return nil, runner.err
	}
	return runner.delegate.Run(ctx, name, args...)
}

func (runner *cancelAfterProbePushRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	output, err := runner.delegate.Run(ctx, name, args...)
	if err != nil ||
		name != "git" ||
		!containsArgument(args, "push") ||
		!containsArgumentFragment(args, "mys-team-audit-probe/") ||
		containsArgumentPrefix(args, ":refs/heads/mys-team-audit-probe/") {
		return output, err
	}
	runner.once.Do(runner.cancel)
	return output, ctx.Err()
}

func (runner *rejectProbePushRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	if name == "git" &&
		containsArgument(args, "push") &&
		containsArgumentFragment(args, "mys-team-audit-probe/") {
		return nil, errors.New("simulated write denial")
	}
	return runner.delegate.Run(ctx, name, args...)
}

type afterSignerLookupRunner struct {
	delegate Runner
	after    func() error
	once     sync.Once
}

func (runner *afterSignerLookupRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	output, err := runner.delegate.Run(ctx, name, args...)
	if err != nil || name != "gpg" ||
		!containsArgument(args, "--list-secret-keys") {
		return output, err
	}
	var callbackErr error
	runner.once.Do(func() {
		callbackErr = runner.after()
	})
	if callbackErr != nil {
		return output, fmt.Errorf("after signer lookup: %w", callbackErr)
	}
	return output, nil
}

type probeStageErrorRunner struct {
	delegate Runner
	stage    string
	mu       sync.Mutex
	next     bool
}

func (runner *probeStageErrorRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	runner.mu.Lock()
	if name == "git" &&
		containsArgument(args, "ls-remote") &&
		containsArgumentFragment(args, "mys-team-audit-probe/") &&
		runner.next {
		runner.next = false
		runner.mu.Unlock()
		return nil, errors.New("simulated probe confirmation loss")
	}
	runner.mu.Unlock()

	output, err := runner.delegate.Run(ctx, name, args...)
	if err != nil || name != "git" || !containsArgument(args, "push") ||
		!containsArgumentFragment(args, "mys-team-audit-probe/") {
		return output, err
	}
	isDeletion := containsArgumentPrefix(
		args,
		":refs/heads/mys-team-audit-probe/",
	)
	shouldFailConfirmation := runner.stage == "confirm-create" && !isDeletion ||
		runner.stage == "confirm-delete" && isDeletion
	if shouldFailConfirmation {
		runner.mu.Lock()
		runner.next = true
		runner.mu.Unlock()
	}
	return output, nil
}

type beforePushRunner struct {
	delegate        Runner
	beforeFirstPush func() error
	mu              sync.Mutex
	pushes          int
}

func (runner *beforePushRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	if name != "git" || !containsArgument(args, "push") {
		return runner.delegate.Run(ctx, name, args...)
	}
	runner.mu.Lock()
	runner.pushes++
	pushNumber := runner.pushes
	runner.mu.Unlock()
	if pushNumber == 1 {
		if err := runner.beforeFirstPush(); err != nil {
			return nil, fmt.Errorf("prepare competing push: %w", err)
		}
	}
	return runner.delegate.Run(ctx, name, args...)
}

func containsArgument(args []string, expected string) bool {
	for _, argument := range args {
		if argument == expected {
			return true
		}
	}
	return false
}

func containsArgumentFragment(args []string, expected string) bool {
	for _, argument := range args {
		if strings.Contains(argument, expected) {
			return true
		}
	}
	return false
}

func containsArgumentPrefix(args []string, expected string) bool {
	for _, argument := range args {
		if strings.HasPrefix(argument, expected) {
			return true
		}
	}
	return false
}

func makeTreeReadOnly(t *testing.T, root string) func() {
	t.Helper()
	modes := make(map[string]os.FileMode)
	if err := filepath.WalkDir(
		root,
		func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			modes[path] = info.Mode().Perm()
			mode := os.FileMode(0o444)
			if entry.IsDir() {
				mode = 0o555
			}
			return os.Chmod(path, mode)
		},
	); err != nil {
		t.Fatalf("make bare remote read-only: %v", err)
	}
	return func() {
		paths := make([]string, 0, len(modes))
		for path := range modes {
			paths = append(paths, path)
		}
		sort.Slice(paths, func(first, second int) bool {
			return len(paths[first]) < len(paths[second])
		})
		for _, path := range paths {
			if err := os.Chmod(path, modes[path]); err != nil &&
				!errors.Is(err, os.ErrNotExist) {
				t.Errorf("restore bare remote mode: %v", err)
			}
		}
	}
}

func writeDeviceID(t *testing.T, config Config, deviceID string) {
	t.Helper()
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		t.Fatalf("mkdir device state: %v", err)
	}
	if err := os.WriteFile(
		config.DeviceIDPath,
		[]byte(deviceID+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write device ID: %v", err)
	}
}

func generatedFingerprint(
	t *testing.T,
	environment []string,
	gpgHome string,
) string {
	t.Helper()
	out := runTestCommand(
		t,
		"",
		environment,
		"gpg",
		"--homedir",
		gpgHome,
		"--batch",
		"--with-colons",
		"--list-secret-keys",
	)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			return strings.ToUpper(fields[9])
		}
	}
	t.Fatal("generated key has no fingerprint")
	return ""
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

func runTestCommand(
	t *testing.T,
	dir string,
	env []string,
	name string,
	args ...string,
) []byte {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	command.Env = append([]string(nil), env...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"%s %s: %v: %s",
			name,
			strings.Join(args, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}
	return output
}
