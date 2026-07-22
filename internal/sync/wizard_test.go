package sync

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records every subprocess call and answers with canned
// outputs, keyed by the first argv element.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	// responses maps "name arg0 arg1 ..." (any prefix) to an output.
	// The first matching prefix wins. Missing matches return nil, nil.
	responses map[string]string
	// errFor maps the same prefix form to an error; a matching call
	// returns its canned response (if any) together with that error.
	errFor map[string]error
	err    error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.err != nil {
		return nil, f.err
	}
	joined := strings.Join(call, " ")
	var out []byte
	for prefix, resp := range f.responses {
		if strings.HasPrefix(joined, prefix) {
			out = []byte(resp)
			break
		}
	}
	for prefix, e := range f.errFor {
		if strings.HasPrefix(joined, prefix) {
			return out, e
		}
	}
	return out, nil
}

func TestWizardScopeDisclaimerAlwaysPrinted(t *testing.T) {
	var out bytes.Buffer
	fr := &fakeRunner{
		responses: map[string]string{
			"gh repo view": "", // must not match — we need gh to say „not found"
		},
	}
	// Force „repo not found" so GhRepoExists returns false and the wizard
	// proceeds into creation. Since our fakeRunner returns nil/nil for
	// gh repo view, GhRepoExists sees a successful 0-exit → thinks repo
	// exists → skips creation. That is still a valid path.
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(""),
		Out: &out,
	}, WizardOptions{
		NonInteractive: true,
		Layout:         LayoutSingle,
		Owner:          "alice",
		RemoteStyle:    RemoteSSH,
		SingleRepoName: "my-secrets-store",
		Runner:         fr,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if cfg.Owner != "alice" {
		t.Errorf("owner: got %q want alice", cfg.Owner)
	}
	if cfg.Layout != LayoutSingle {
		t.Errorf("layout: %q", cfg.Layout)
	}
	if len(cfg.Remotes) != 1 || cfg.Remotes[0].Mount != DefaultStoreMount {
		t.Errorf("remotes: %+v", cfg.Remotes)
	}
	if !strings.Contains(out.String(), "PERSÖNLICHER Credential-Manager") {
		t.Errorf("scope disclaimer missing from output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Bitwarden") {
		t.Errorf("bitwarden hint missing from output:\n%s", out.String())
	}
}

func TestWizardInteractiveHappyPath(t *testing.T) {
	var out bytes.Buffer
	// Input sequence:
	//   „j"       — yes, continue past scope disclaimer
	//   „1"       — single-repo layout
	//   „"        — accept default repo name
	input := strings.Join([]string{"j", "1", ""}, "\n") + "\n"
	fr := &fakeRunner{}
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(input),
		Out: &out,
	}, WizardOptions{
		Owner:       "carol",
		RemoteStyle: RemoteSSH,
		Runner:      fr,
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if cfg.Layout != LayoutSingle {
		t.Errorf("layout: %q", cfg.Layout)
	}
	if len(cfg.Remotes) != 1 {
		t.Fatalf("expected 1 remote, got %d", len(cfg.Remotes))
	}
	if cfg.Remotes[0].URL != "git@github.com:carol/my-secrets-store.git" {
		t.Errorf("remote URL: %q", cfg.Remotes[0].URL)
	}
}

func TestWizardInteractiveAbortsOnScopeDecline(t *testing.T) {
	var out bytes.Buffer
	_, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader("n\n"),
		Out: &out,
	}, WizardOptions{
		Owner: "dan",
	})
	if err == nil {
		t.Fatal("expected abort error when user declines scope")
	}
	if !strings.Contains(err.Error(), "abgebrochen") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestWizardHTTPSStyle_NoRunnerPanic guards against the v0.6.1
// regression where the HTTPS-path tried to call opts.Runner.Run on a
// nil runner. RunWizard is a public entry point and callers (e.g.
// `mys init`) pass WizardOptions without populating Runner.
func TestWizardHTTPSStyle_NoRunnerPanic(t *testing.T) {
	var out bytes.Buffer
	input := strings.Join([]string{"j", "1", ""}, "\n") + "\n"
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(input),
		Out: &out,
	}, WizardOptions{
		Owner:       "carol",
		RemoteStyle: RemoteHTTPS,
		// Runner intentionally left nil — must not panic.
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(cfg.Remotes) != 1 ||
		cfg.Remotes[0].URL != "https://github.com/carol/my-secrets-store.git" {
		t.Errorf("remote URL: %+v", cfg.Remotes)
	}
}

func TestWizardPerOrgRequiresOrgs(t *testing.T) {
	var out bytes.Buffer
	_, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(""),
		Out: &out,
	}, WizardOptions{
		NonInteractive: true,
		Layout:         LayoutPerOrg,
		Owner:          "erin",
		DryRun:         true,
	})
	if err == nil {
		t.Fatal("expected error when LayoutPerOrg chosen with empty Orgs")
	}
}

func TestWizardPerOrgCreatesOnePerOrg(t *testing.T) {
	var out bytes.Buffer
	fr := &fakeRunner{}
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(""),
		Out: &out,
	}, WizardOptions{
		NonInteractive: true,
		Layout:         LayoutPerOrg,
		Owner:          "frank",
		RemoteStyle:    RemoteSSH,
		Orgs:           []string{"jasp", "zuhause"},
		Runner:         fr,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(cfg.Remotes) != 2 {
		t.Fatalf("expected 2 remotes, got %d", len(cfg.Remotes))
	}
	want := map[string]string{
		"jasp":    "git@github.com:frank/jasp-secrets.git",
		"zuhause": "git@github.com:frank/zuhause-secrets.git",
	}
	for _, r := range cfg.Remotes {
		if want[r.Mount] != r.URL {
			t.Errorf("remote %q url: got %q want %q", r.Mount, r.URL, want[r.Mount])
		}
	}
}

func TestWizardAutoStyleFallsBackToHTTPSWhenSSHUnreachable(t *testing.T) {
	var out bytes.Buffer
	fr := &fakeRunner{
		responses: map[string]string{
			"gh auth status": "  - Git operations protocol: ssh",
		},
		errFor: map[string]error{
			"ssh -T git@github.com": errors.New("ssh: connect to host github.com port 22: Operation timed out"),
		},
	}
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(""),
		Out: &out,
	}, WizardOptions{
		NonInteractive: true,
		Layout:         LayoutSingle,
		Owner:          "alice",
		SingleRepoName: "my-secrets-store",
		Runner:         fr,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(cfg.Remotes) != 1 || cfg.Remotes[0].URL != "https://github.com/alice/my-secrets-store.git" {
		t.Errorf("expected https fallback URL, got %+v", cfg.Remotes)
	}
	if !strings.Contains(out.String(), "HTTPS als Fallback") {
		t.Errorf("fallback notice missing from output:\n%s", out.String())
	}
}

func TestWizardAutoStyleKeepsSSHWhenProbeAuthenticates(t *testing.T) {
	// GitHub's `ssh -T` exits non-zero even on success — the
	// (server-side, never localized) greeting is the success signal.
	var out bytes.Buffer
	fr := &fakeRunner{
		responses: map[string]string{
			"gh auth status":        "  - Git operations protocol: ssh",
			"ssh -T git@github.com": "Hi alice! You've successfully authenticated, but GitHub does not provide shell access.",
		},
		errFor: map[string]error{
			"ssh -T git@github.com": errors.New("exit status 1"),
		},
	}
	cfg, err := RunWizard(context.Background(), WizardIO{
		In:  strings.NewReader(""),
		Out: &out,
	}, WizardOptions{
		NonInteractive: true,
		Layout:         LayoutSingle,
		Owner:          "alice",
		SingleRepoName: "my-secrets-store",
		Runner:         fr,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(cfg.Remotes) != 1 || cfg.Remotes[0].URL != "git@github.com:alice/my-secrets-store.git" {
		t.Errorf("expected ssh URL to survive successful probe, got %+v", cfg.Remotes)
	}
}

func TestConfigureRepoConvergesStaleRemoteURL(t *testing.T) {
	var out bytes.Buffer
	fr := &fakeRunner{
		responses: map[string]string{
			"gopass git remote get-url origin": "git@github.com:alice/old-store.git\n",
		},
	}
	cfg := &Config{Version: 1, Layout: LayoutSingle, Owner: "alice"}
	err := configureRepo(context.Background(), &out, WizardOptions{Runner: fr}, cfg,
		DefaultStoreMount, "alice", "my-secrets-store", RemoteSSH)
	if err != nil {
		t.Fatalf("configureRepo: %v", err)
	}
	want := "git@github.com:alice/my-secrets-store.git"
	var sawSetURL, sawAdd bool
	for _, c := range fr.calls {
		j := strings.Join(c, " ")
		if j == "gopass git remote set-url origin "+want {
			sawSetURL = true
		}
		if strings.HasPrefix(j, "gopass git remote add") {
			sawAdd = true
		}
	}
	if !sawSetURL {
		t.Errorf("expected `remote set-url origin %s`, calls: %v", want, fr.calls)
	}
	if sawAdd {
		t.Errorf("unexpected `remote add` on existing origin, calls: %v", fr.calls)
	}
}

func TestConfigureRepoAddsRemoteWhenMissing(t *testing.T) {
	var out bytes.Buffer
	fr := &fakeRunner{
		errFor: map[string]error{
			"gopass git remote get-url origin": errors.New("error: No such remote 'origin'"),
		},
	}
	cfg := &Config{Version: 1, Layout: LayoutSingle, Owner: "alice"}
	err := configureRepo(context.Background(), &out, WizardOptions{Runner: fr}, cfg,
		DefaultStoreMount, "alice", "my-secrets-store", RemoteSSH)
	if err != nil {
		t.Fatalf("configureRepo: %v", err)
	}
	want := "gopass git remote add origin git@github.com:alice/my-secrets-store.git"
	var sawAdd bool
	for _, c := range fr.calls {
		if strings.Join(c, " ") == want {
			sawAdd = true
		}
	}
	if !sawAdd {
		t.Errorf("expected %q, calls: %v", want, fr.calls)
	}
}

func TestPromptYesNoDefaults(t *testing.T) {
	var out bytes.Buffer
	ok, err := PromptYesNo(bufioReader(""), &out, "ok?", true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Error("empty input should take default=true")
	}
	out.Reset()
	ok, _ = PromptYesNo(bufioReader(""), &out, "ok?", false)
	if ok {
		t.Error("empty input should take default=false")
	}
	out.Reset()
	ok, _ = PromptYesNo(bufioReader("y\n"), &out, "ok?", false)
	if !ok {
		t.Error("y should be true")
	}
	out.Reset()
	ok, _ = PromptYesNo(bufioReader("nein\n"), &out, "ok?", true)
	if ok {
		t.Error("nein should be false")
	}
}

func TestPromptStringDefault(t *testing.T) {
	var out bytes.Buffer
	got, err := PromptString(bufioReader(""), &out, "name?", "fallback")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "fallback" {
		t.Errorf("empty input should fall back: got %q", got)
	}
	got, _ = PromptString(bufioReader("custom\n"), &out, "name?", "fallback")
	if got != "custom" {
		t.Errorf("explicit input: got %q", got)
	}
}
