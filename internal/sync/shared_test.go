package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
)

const (
	sharedFprAlice = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	sharedFprBob   = "111122223333444455556666777788889999AAAA"
	sharedFprOld   = "FFFFEEEEDDDDCCCCBBBBAAAA9999888877776666"
)

type provisionRunner struct {
	rootPath  string
	storePath string
	mounted   bool
	calls     []string
}

func (r *provisionRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch {
	case strings.HasPrefix(call, "gpg --batch --with-colons --list-keys "):
		fingerprint := args[len(args)-1]
		return []byte(gpgFingerprintFixture(fingerprint)), nil
	case call == "gpg --batch --with-colons --list-secret-keys "+sharedFprAlice:
		return nil, errors.New("no secret key")
	case call == "gpg --batch --with-colons --list-secret-keys "+sharedFprBob:
		return []byte(gpgFingerprintFixture(sharedFprBob)), nil
	case call == "gopass config mounts.jasp.path":
		if !r.mounted {
			return nil, errors.New("unknown config option")
		}
		return []byte(r.storePath + "\n"), nil
	case call == "gopass config mounts.path":
		return []byte(r.rootPath + "\n"), nil
	case call == "gopass mounts add jasp "+r.storePath:
		r.mounted = true
		return nil, nil
	case call == "gopass git --store jasp init":
		return nil, nil
	case call == "gopass git --store jasp rev-parse --verify HEAD":
		return nil, errors.New("unborn branch")
	case call == "gopass git --store jasp add -- .gpg-id":
		return nil, nil
	case call == "gopass git --store jasp commit -m Initialize shared store":
		return nil, nil
	case call == "gopass git --store jasp branch -M main":
		return nil, nil
	case call == "gopass git --store jasp remote get-url origin":
		return nil, errors.New("no origin")
	case strings.HasPrefix(call, "gopass git --store jasp remote add origin "):
		return nil, nil
	case call == "gopass git --store jasp fetch origin":
		return nil, nil
	case call == "gopass git --store jasp rev-parse --quiet --verify origin/main":
		return nil, errors.New("empty remote")
	case call == "gopass --yes recipients add --store jasp "+sharedFprAlice:
		file := filepath.Join(r.storePath, ".gpg-id")
		f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		_, writeErr := fmt.Fprintln(f, sharedFprAlice)
		closeErr := f.Close()
		return nil, errors.Join(writeErr, closeErr)
	case call == "gopass git --store jasp add -- team-keys.yaml":
		return nil, nil
	case call == "gopass git --store jasp diff --cached --name-only -- team-keys.yaml":
		return []byte("team-keys.yaml\n"), nil
	case call == "gopass git --store jasp commit -m Update shared team keys":
		return nil, nil
	case call == "gopass git --store jasp push origin main":
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected call: %s", call)
	}
}

func TestProvisionSharedMountWithManifest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	rootPath := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "shared")
	resolvedStorePath, err := resolveStorePath(storePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), teamkeys.Filename)
	manifest := &teamkeys.File{Version: 1, Members: []teamkeys.Member{
		{Name: "Alice", Email: "alice@example.org", Fingerprint: sharedFprAlice},
		{Name: "Bob", Email: "bob@example.org", Fingerprint: sharedFprBob},
	}}
	if err := teamkeys.Save(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	runner := &provisionRunner{rootPath: rootPath, storePath: resolvedStorePath}
	now := time.Date(2026, 7, 24, 16, 0, 0, 0, time.UTC)

	result, err := ProvisionSharedMount(context.Background(), SharedProvisionOptions{
		Config:       &Config{Version: 1, Layout: LayoutSingle, Remotes: []StoreRemote{{Mount: DefaultStoreMount, URL: "personal"}}},
		Mount:        "jasp",
		StorePath:    storePath,
		TeamKeysPath: manifestPath,
		RemoteURL:    filepath.Join(t.TempDir(), "shared.git"),
		Runner:       runner,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("ProvisionSharedMount: %v\ncalls:\n%s", err, strings.Join(runner.calls, "\n"))
	}
	if !result.Config.IsSharedMount("jasp") {
		t.Fatalf("result config does not mark jasp shared: %+v", result.Config.Remotes)
	}
	remote, ok := result.Config.Remote("jasp")
	if !ok || !remote.LastSync.Equal(now) {
		t.Fatalf("shared remote timestamp = %+v, want %v", remote, now)
	}
	if len(result.Fingerprints) != 2 || result.Fingerprints[0] != sharedFprBob {
		t.Fatalf("fingerprints = %v, want local secret-key owner first", result.Fingerprints)
	}
	storePath = result.StorePath
	if _, err := teamkeys.Load(filepath.Join(storePath, teamkeys.Filename)); err != nil {
		t.Fatalf("materialized manifest: %v", err)
	}
	recipients, err := readGPGID(filepath.Join(storePath, ".gpg-id"))
	if err != nil {
		t.Fatal(err)
	}
	if !recipientSetContains(recipients, sharedFprAlice) ||
		!recipientSetContains(recipients, sharedFprBob) {
		t.Fatalf("recipients = %v, want both team fingerprints", recipients)
	}
	wantConfirmedAdd := "gopass --yes recipients add --store jasp " + sharedFprAlice
	if !stringSliceContains(runner.calls, wantConfirmedAdd) {
		t.Fatalf("missing confirmed mount-scoped add %q in calls: %v", wantConfirmedAdd, runner.calls)
	}
}

func TestProvisionSharedMountRefusesPersonalMount(t *testing.T) {
	result, err := ProvisionSharedMount(context.Background(), SharedProvisionOptions{
		Config:       &Config{Remotes: []StoreRemote{{Mount: "jasp"}}},
		Mount:        "jasp",
		TeamKeysPath: "unused",
	})
	if err == nil || !strings.Contains(err.Error(), "personal") {
		t.Fatalf("result=%v error=%v, want personal mount refusal", result, err)
	}
}

func TestPreflightTeamKeysRequiresLocalSecretKey(t *testing.T) {
	runner := &scriptedRunner{results: map[string]scriptedResult{
		"gpg --batch --with-colons --list-keys " + sharedFprAlice: {
			out: []byte(gpgFingerprintFixture(sharedFprAlice)),
		},
		"gpg --batch --with-colons --list-secret-keys " + sharedFprAlice: {
			err: errors.New("no secret key"),
		},
	}}
	_, err := preflightTeamKeys(context.Background(), runner, []string{sharedFprAlice})
	if err == nil || !strings.Contains(err.Error(), "local secret key") {
		t.Fatalf("error = %v, want local secret key refusal", err)
	}
}

type recipientReconcileRunner struct {
	storePath string
	calls     []string
}

type stubResponse struct {
	out  []byte
	errs []error
}

type sequenceSharedRunner struct {
	handlers map[string]stubResponse
	offsets  map[string]int
	calls    []string
}

func (r *sequenceSharedRunner) Run(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	response, ok := r.handlers[call]
	if !ok {
		return nil, fmt.Errorf("unexpected call: %s", call)
	}
	if r.offsets == nil {
		r.offsets = map[string]int{}
	}
	offset := r.offsets[call]
	r.offsets[call] = offset + 1
	if offset < len(response.errs) && response.errs[offset] != nil {
		return response.out, response.errs[offset]
	}
	return response.out, nil
}

func (r *recipientReconcileRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	file := filepath.Join(r.storePath, ".gpg-id")
	switch call {
	case "gopass --yes recipients add --store jasp " + sharedFprBob:
		f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		_, writeErr := fmt.Fprintln(f, sharedFprBob)
		closeErr := f.Close()
		return nil, errors.Join(writeErr, closeErr)
	case "gopass --yes recipients remove --store jasp " + sharedFprOld:
		return nil, atomicWriteFile(file, []byte(sharedFprAlice+"\n"+sharedFprBob+"\n"), 0o600)
	default:
		return nil, fmt.Errorf("unexpected call: %s", call)
	}
}

func TestReconcileSharedRecipientsAddsBeforeRemoving(t *testing.T) {
	storePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(storePath, ".gpg-id"),
		[]byte(sharedFprAlice+"\n"+sharedFprOld+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recipientReconcileRunner{storePath: storePath}
	if err := reconcileSharedRecipients(context.Background(), runner, "jasp", storePath,
		[]string{sharedFprAlice, sharedFprBob}); err != nil {
		t.Fatalf("reconcileSharedRecipients: %v", err)
	}
	want := []string{
		"gopass --yes recipients add --store jasp " + sharedFprBob,
		"gopass --yes recipients remove --store jasp " + sharedFprOld,
	}
	if strings.Join(runner.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v, want add-before-remove %v", runner.calls, want)
	}
}

func TestSyncSharedMountWithRetry(t *testing.T) {
	mountPath := t.TempDir()
	config := &Config{Version: 1, Remotes: []StoreRemote{{
		Mount: "jasp-shared", URL: "file:///audit/shared.git", Shared: true,
	}}}
	tests := []struct {
		name      string
		handlers  map[string]stubResponse
		wantCalls []string
		wantErr   string
	}{
		{
			name: "success",
			handlers: map[string]stubResponse{
				"gopass config mounts.jasp-shared.path": {out: []byte(mountPath + "\n")},
				"gopass sync --store jasp-shared":       {},
			},
			wantCalls: []string{
				"gopass config mounts.jasp-shared.path",
				"gopass sync --store jasp-shared",
			},
		},
		{
			name: "one non-fast-forward retry",
			handlers: map[string]stubResponse{
				"gopass config mounts.jasp-shared.path": {out: []byte(mountPath + "\n")},
				"gopass sync --store jasp-shared": {
					errs: []error{errors.New("non-fast-forward"), nil},
				},
				"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
					out: []byte("main\n"),
				},
				"gopass git --store jasp-shared pull origin main": {},
			},
			wantCalls: []string{
				"gopass config mounts.jasp-shared.path",
				"gopass sync --store jasp-shared",
				"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD",
				"gopass git --store jasp-shared pull origin main",
				"gopass sync --store jasp-shared",
			},
		},
		{
			name: "non retryable error",
			handlers: map[string]stubResponse{
				"gopass config mounts.jasp-shared.path": {out: []byte(mountPath + "\n")},
				"gopass sync --store jasp-shared": {
					errs: []error{errors.New("authentication failed")},
				},
			},
			wantCalls: []string{
				"gopass config mounts.jasp-shared.path",
				"gopass sync --store jasp-shared",
			},
			wantErr: "authentication failed",
		},
		{
			name: "second non-fast-forward is returned",
			handlers: map[string]stubResponse{
				"gopass config mounts.jasp-shared.path": {out: []byte(mountPath + "\n")},
				"gopass sync --store jasp-shared": {
					errs: []error{
						errors.New("non-fast-forward"),
						errors.New("fetch first"),
					},
				},
				"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
					out: []byte("main\n"),
				},
				"gopass git --store jasp-shared pull origin main": {},
			},
			wantCalls: []string{
				"gopass config mounts.jasp-shared.path",
				"gopass sync --store jasp-shared",
				"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD",
				"gopass git --store jasp-shared pull origin main",
				"gopass sync --store jasp-shared",
			},
			wantErr: "after one retry",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &sequenceSharedRunner{handlers: test.handlers}
			err := SyncSharedMountWithRetry(
				context.Background(), runner, config, "jasp-shared")
			if test.wantErr == "" && err != nil {
				t.Fatalf("SyncSharedMountWithRetry: %v", err)
			}
			if test.wantErr != "" &&
				(err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			if strings.Join(runner.calls, "\n") != strings.Join(test.wantCalls, "\n") {
				t.Fatalf("calls = %v, want %v", runner.calls, test.wantCalls)
			}
		})
	}
}

func TestSyncSharedMountWithRetryRequiresSharedMount(t *testing.T) {
	runner := &sequenceSharedRunner{}
	err := SyncSharedMountWithRetry(context.Background(), runner,
		&Config{Version: 1, Remotes: []StoreRemote{{
			Mount: "personal", URL: "file:///personal.git",
		}}}, "personal")
	if err == nil || !strings.Contains(err.Error(), "not configured as shared") {
		t.Fatalf("error = %v, want fail-closed shared validation", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner calls = %v, want none", runner.calls)
	}
}

func TestMaterializeTeamKeysRejectsSymlinkedAssetDirectory(t *testing.T) {
	storePath := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(storePath, ".public-keys")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	manifest := &teamkeys.File{Version: 1, Members: []teamkeys.Member{{
		Name:        "Alice",
		Email:       "alice@example.org",
		Fingerprint: sharedFprAlice,
		PublicKey:   ".public-keys/alice.asc",
	}}}
	_, _, err := materializeTeamKeys(storePath, manifest, []publicKeyAsset{{
		relativePath: ".public-keys/alice.asc",
		data:         []byte("public key"),
	}})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("materializeTeamKeys error = %v, want symbolic-link refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "alice.asc")); !os.IsNotExist(statErr) {
		t.Fatalf("public key escaped shared repo: %v", statErr)
	}
}

func gpgFingerprintFixture(fingerprint string) string {
	return "pub:-:2048:1:0123456789ABCDEF:0::::::scESC:::::::\n" +
		"fpr:::::::::" + fingerprint + ":\n"
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
