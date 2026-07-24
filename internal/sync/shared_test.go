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

type sharedPrivacyResponse struct {
	out []byte
	err error
}

type sharedPrivacyRunner struct {
	responses map[string][]sharedPrivacyResponse
	calls     []string
}

func (r *sharedPrivacyRunner) Run(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	responses := r.responses[call]
	if len(responses) == 0 {
		return nil, fmt.Errorf("unexpected call: %s", call)
	}
	response := responses[0]
	r.responses[call] = responses[1:]
	return response.out, response.err
}

func installSharedTestGH(t *testing.T) {
	t.Helper()
	binaryDir := t.TempDir()
	ghPath := filepath.Join(binaryDir, "gh")
	if err := os.WriteFile(
		ghPath,
		[]byte("#!/bin/sh\nexit 0\n"),
		0o700,
	); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", binaryDir)
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

func TestEnsureSharedRemoteChecksEveryDirectGitHubForm(t *testing.T) {
	remotes := []string{
		"github.com:jasp/mys-store-shared.git",
		"git@github.com:jasp/mys-store-shared.git",
		"https://github.com/jasp/mys-store-shared.git",
		"ssh://git@github.com/jasp/mys-store-shared.git",
		"ssh://git@ssh.github.com:443/jasp/mys-store-shared.git",
		"WWW.GITHUB.COM.:jasp/mys-store-shared.git",
		"git@WWW.GITHUB.COM.:jasp/mys-store-shared.git",
		"https://GITHUB.COM./jasp/mys-store-shared.git",
		"https://www.github.com/jasp/mys-store-shared.git",
		"ssh://git@SSH.GITHUB.COM.:443/jasp/mys-store-shared.git",
	}
	for _, remote := range remotes {
		remote := remote
		t.Run(remote, func(t *testing.T) {
			installSharedTestGH(t)
			runner := &sharedPrivacyRunner{
				responses: map[string][]sharedPrivacyResponse{
					"gh repo view jasp/mys-store-shared --json visibility --jq .visibility": {
						{out: []byte("PRIVATE\n")},
					},
				},
			}
			got, err := ensureSharedRemote(
				context.Background(),
				runner,
				SharedProvisionOptions{RemoteURL: remote},
			)
			if err != nil {
				t.Fatalf("ensureSharedRemote(%q): %v", remote, err)
			}
			if got != remote {
				t.Fatalf("remote = %q, want unchanged %q", got, remote)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("calls = %v, want one visibility query", runner.calls)
			}
		})
	}
}

func TestEnsureSharedRemoteRejectsUnprovenGitHubPrivacy(t *testing.T) {
	tests := []struct {
		name      string
		response  sharedPrivacyResponse
		wantError string
	}{
		{
			name:      "public",
			response:  sharedPrivacyResponse{out: []byte("PUBLIC\n")},
			wantError: "must be PRIVATE",
		},
		{
			name:      "internal",
			response:  sharedPrivacyResponse{out: []byte("INTERNAL\n")},
			wantError: "must be PRIVATE",
		},
		{
			name:      "empty",
			wantError: "unexpected response",
		},
		{
			name:      "CLI error",
			response:  sharedPrivacyResponse{err: errors.New("API unavailable")},
			wantError: "API unavailable",
		},
		{
			name:      "unavailable",
			response:  sharedPrivacyResponse{err: errors.New("HTTP 404")},
			wantError: "repository is unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installSharedTestGH(t)
			runner := &sharedPrivacyRunner{
				responses: map[string][]sharedPrivacyResponse{
					"gh repo view jasp/mys-store-shared --json visibility --jq .visibility": {
						test.response,
					},
				},
			}
			_, err := ensureSharedRemote(
				context.Background(),
				runner,
				SharedProvisionOptions{
					RemoteURL: "github.com:jasp/mys-store-shared.git",
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestEnsureSharedRemoteCreatesAndRechecksPrivateGitHubRepo(t *testing.T) {
	installSharedTestGH(t)
	const view = "gh repo view jasp/mys-store-shared --json visibility --jq .visibility"
	runner := &sharedPrivacyRunner{
		responses: map[string][]sharedPrivacyResponse{
			view: {
				{err: errors.New("HTTP 404")},
				{out: []byte("PRIVATE\n")},
			},
			"gh repo create jasp/mys-store-shared --private": {
				{out: []byte("created\n")},
			},
		},
	}
	remote, err := ensureSharedRemote(
		context.Background(),
		runner,
		SharedProvisionOptions{
			Owner:       "jasp",
			Repo:        "mys-store-shared",
			RemoteStyle: RemoteHTTPS,
		},
	)
	if err != nil {
		t.Fatalf("ensureSharedRemote: %v", err)
	}
	if remote != "https://github.com/jasp/mys-store-shared.git" {
		t.Fatalf("remote = %q, want managed HTTPS remote", remote)
	}
	wantCalls := []string{
		view,
		"gh repo create jasp/mys-store-shared --private",
		view,
	}
	if strings.Join(runner.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %v, want create followed by privacy recheck", runner.calls)
	}
}

func TestEnsureSharedRemoteRejectsUnconfirmedCreatedGitHubRepo(t *testing.T) {
	tests := []struct {
		name         string
		confirmation sharedPrivacyResponse
		wantError    string
	}{
		{
			name:         "public",
			confirmation: sharedPrivacyResponse{out: []byte("PUBLIC\n")},
			wantError:    "must be PRIVATE",
		},
		{
			name:         "internal",
			confirmation: sharedPrivacyResponse{out: []byte("INTERNAL\n")},
			wantError:    "must be PRIVATE",
		},
		{
			name:      "empty",
			wantError: "unexpected response",
		},
		{
			name:         "CLI error",
			confirmation: sharedPrivacyResponse{err: errors.New("API unavailable")},
			wantError:    "API unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installSharedTestGH(t)
			const view = "gh repo view jasp/mys-store-shared --json visibility --jq .visibility"
			runner := &sharedPrivacyRunner{
				responses: map[string][]sharedPrivacyResponse{
					view: {
						{err: errors.New("HTTP 404")},
						test.confirmation,
					},
					"gh repo create jasp/mys-store-shared --private": {
						{out: []byte("created\n")},
					},
				},
			}
			_, err := ensureSharedRemote(
				context.Background(),
				runner,
				SharedProvisionOptions{
					Owner:       "jasp",
					Repo:        "mys-store-shared",
					RemoteStyle: RemoteHTTPS,
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
			if len(runner.calls) != 3 || runner.calls[2] != view {
				t.Fatalf("calls = %v, want post-create visibility recheck", runner.calls)
			}
		})
	}
}

func TestProvisionSharedMountProvesPrivacyBeforeMountOrConfigMutation(
	t *testing.T,
) {
	for _, remoteURL := range []string{
		"github.com:jasp/mys-store-shared.git",
		"https://github.com./jasp/mys-store-shared.git",
		"https://www.github.com/jasp/mys-store-shared.git",
	} {
		remoteURL := remoteURL
		t.Run(remoteURL, func(t *testing.T) {
			installSharedTestGH(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			storePath := filepath.Join(t.TempDir(), "shared")
			config := &Config{
				Version: 1,
				Layout:  LayoutSingle,
				Remotes: []StoreRemote{{
					Mount: DefaultStoreMount,
					URL:   "personal.git",
				}},
			}
			runner := &sharedPrivacyRunner{
				responses: map[string][]sharedPrivacyResponse{
					"gpg --batch --with-colons --list-keys " + sharedFprBob: {
						{out: []byte(gpgFingerprintFixture(sharedFprBob))},
					},
					"gpg --batch --with-colons --list-secret-keys " + sharedFprBob: {
						{out: []byte(gpgFingerprintFixture(sharedFprBob))},
					},
					"gh repo view jasp/mys-store-shared --json visibility --jq .visibility": {
						{out: []byte("PUBLIC\n")},
					},
				},
			}

			result, err := ProvisionSharedMount(
				context.Background(),
				SharedProvisionOptions{
					Config:       config,
					Mount:        "jasp",
					StorePath:    storePath,
					Fingerprints: []string{sharedFprBob},
					RemoteURL:    remoteURL,
					Runner:       runner,
				},
			)
			if err == nil || !strings.Contains(err.Error(), "must be PRIVATE") {
				t.Fatalf("result = %v, error = %v; want PRIVATE refusal", result, err)
			}
			if len(config.Remotes) != 1 ||
				config.Remotes[0].Mount != DefaultStoreMount ||
				config.Remotes[0].Shared {
				t.Fatalf(
					"input config mutated before privacy proof: %+v",
					config.Remotes,
				)
			}
			if _, statErr := os.Lstat(storePath); !os.IsNotExist(statErr) {
				t.Fatalf("shared store path mutated before privacy proof: %v", statErr)
			}
			for _, call := range runner.calls {
				if strings.HasPrefix(call, "gopass ") {
					t.Fatalf("mount/store command ran before privacy proof: %s", call)
				}
			}
		})
	}
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
