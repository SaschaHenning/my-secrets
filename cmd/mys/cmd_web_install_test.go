package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	errUnloadNotLoaded = errors.New("no such process")
	errAgentNotRunning = errors.New("could not find service")
)

// stubLaunchctl replaces launchctlRun with a recorder for the duration
// of t. Real launchctl operates on the live, global launchd session for
// the current user — it is never safe to invoke from a test, regardless
// of how $HOME is isolated, since the plist path itself is still passed
// straight to the real system daemon.
func stubLaunchctl(t *testing.T, fn func(args ...string) ([]byte, error)) *[][]string {
	t.Helper()
	var calls [][]string
	prev := launchctlRun
	launchctlRun = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string{}, args...))
		if fn != nil {
			return fn(args...)
		}
		return nil, nil
	}
	t.Cleanup(func() { launchctlRun = prev })
	return &calls
}

func TestWebInstallCmd_WritesPlistAndCallsLaunchctl(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	calls := stubLaunchctl(t, nil)

	var out bytes.Buffer
	cmd := webInstallCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	plistPath := filepath.Join(fakeHome, "Library", "LaunchAgents", launchAgentLabel+".plist")
	body, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	content := string(body)
	for _, want := range []string{
		"<key>Label</key><string>" + launchAgentLabel + "</string>",
		"<string>web</string>",
		"<string>--port</string>",
		"<string>7823</string>",
		"<key>EnvironmentVariables</key>",
		"<key>PATH</key>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("plist missing %q:\n%s", want, content)
		}
	}

	wantCalls := [][]string{
		{"unload", plistPath},
		{"load", plistPath},
	}
	if len(*calls) != len(wantCalls) {
		t.Fatalf("launchctl calls = %v, want %v", *calls, wantCalls)
	}
	for i, c := range *calls {
		if len(c) != len(wantCalls[i]) || c[0] != wantCalls[i][0] || c[1] != wantCalls[i][1] {
			t.Errorf("call %d = %v, want %v", i, c, wantCalls[i])
		}
	}

	if !strings.Contains(out.String(), plistPath) {
		t.Errorf("stdout should mention the plist path: %s", out.String())
	}
}

// TestWebInstallCmd_CapturesInstallingShellPATH is a regression test:
// launchd gives a LaunchAgent a bare minimal PATH
// (/usr/bin:/bin:/usr/sbin:/sbin) with no inheritance from the
// installing shell. Without baking $PATH into the plist, `mys web`
// cannot find gpg/gopass/git (typically under /opt/homebrew) and fails
// on every request that touches the store — this was caught by actually
// installing and running the LaunchAgent, not by unit tests alone.
func TestWebInstallCmd_CapturesInstallingShellPATH(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("PATH", "/opt/homebrew/bin:/custom/gpg/location:/usr/bin:/bin")
	stubLaunchctl(t, nil)

	var out bytes.Buffer
	cmd := webInstallCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	plistPath := filepath.Join(fakeHome, "Library", "LaunchAgents", launchAgentLabel+".plist")
	body, _ := os.ReadFile(plistPath)
	if !strings.Contains(string(body), "/opt/homebrew/bin:/custom/gpg/location:/usr/bin:/bin") {
		t.Errorf("plist did not capture the installing shell's PATH:\n%s", body)
	}
}

func TestRenderLaunchAgentPlist_FallsBackWhenPATHEmpty(t *testing.T) {
	plist := renderLaunchAgentPlist("/usr/local/bin/mys", 7823, "/tmp/web.log", "")
	if !strings.Contains(plist, fallbackAgentPATH) {
		t.Errorf("expected fallback PATH when none given:\n%s", plist)
	}
}

func TestWebInstallCmd_CustomPort(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	stubLaunchctl(t, nil)

	var out bytes.Buffer
	cmd := webInstallCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--port", "9999"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	plistPath := filepath.Join(fakeHome, "Library", "LaunchAgents", launchAgentLabel+".plist")
	body, _ := os.ReadFile(plistPath)
	if !strings.Contains(string(body), "<string>9999</string>") {
		t.Errorf("plist did not pick up --port 9999:\n%s", body)
	}
}

// TestRenderLaunchAgentPlist_EscapesXMLMetacharacters is a regression
// test for a review finding: binPath/logPath are interpolated into the
// plist as raw XML text. Neither is attacker-controlled under this
// tool's single-user threat model, but a path containing &, <, or >
// must not produce malformed or structurally altered XML regardless.
func TestRenderLaunchAgentPlist_EscapesXMLMetacharacters(t *testing.T) {
	plist := renderLaunchAgentPlist(`/Users/a&b/<mys>/"x"`, 7823, `/tmp/log&<>"'.log`, "/usr/bin:/bin")
	for _, raw := range []string{"a&b", "<mys>", `"x"`, `log&<>"'`} {
		if strings.Contains(plist, raw) {
			t.Errorf("plist contains unescaped XML metacharacters %q:\n%s", raw, plist)
		}
	}
	if !strings.Contains(plist, "a&amp;b") || !strings.Contains(plist, "&lt;mys&gt;") {
		t.Errorf("expected properly escaped path in plist:\n%s", plist)
	}
}

func TestWebInstallCmd_UnloadFailureDoesNotBlockLoad(t *testing.T) {
	// "unload" failing (e.g. nothing was loaded yet — the common,
	// first-install case) must not prevent "load" from running.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	calls := stubLaunchctl(t, func(args ...string) ([]byte, error) {
		if args[0] == "unload" {
			return []byte("no such process"), errUnloadNotLoaded
		}
		return nil, nil
	})

	var out bytes.Buffer
	cmd := webInstallCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute should succeed even if unload errors: %v", err)
	}
	if len(*calls) != 2 || (*calls)[1][0] != "load" {
		t.Fatalf("expected load to run after a failed unload, got %v", *calls)
	}
}

func TestWebUninstallCmd_RemovesPlistAndCallsUnload(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	stubLaunchctl(t, nil)

	// Install first so there's something to remove.
	installCmd := webInstallCmd()
	installCmd.SetOut(&bytes.Buffer{})
	installCmd.SetErr(&bytes.Buffer{})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	plistPath := filepath.Join(fakeHome, "Library", "LaunchAgents", launchAgentLabel+".plist")

	calls := stubLaunchctl(t, nil) // reset call log for the uninstall assertion
	var out bytes.Buffer
	uninstallCmd := webUninstallCmd()
	uninstallCmd.SetOut(&out)
	uninstallCmd.SetErr(&out)
	if err := uninstallCmd.Execute(); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Errorf("plist should be removed, stat err = %v", err)
	}
	if len(*calls) != 1 || (*calls)[0][0] != "unload" {
		t.Fatalf("expected exactly one unload call, got %v", *calls)
	}
}

func TestWebUninstallCmd_NoOpWhenNotInstalled(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	calls := stubLaunchctl(t, nil)

	var out bytes.Buffer
	cmd := webUninstallCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("uninstall on a never-installed agent must not touch launchctl, got %v", *calls)
	}
	if !strings.Contains(out.String(), "kein LaunchAgent") {
		t.Errorf("expected a not-installed message: %s", out.String())
	}
}

func TestWebStatusCmd_NotInstalled(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	calls := stubLaunchctl(t, nil)

	var out bytes.Buffer
	cmd := webStatusCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("status on a never-installed agent must not touch launchctl, got %v", *calls)
	}
	if !strings.Contains(out.String(), "nicht installiert") {
		t.Errorf("expected a not-installed message: %s", out.String())
	}
}

func TestWebStatusCmd_InstalledAndActive(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	stubLaunchctl(t, nil)
	installCmd := webInstallCmd()
	installCmd.SetOut(&bytes.Buffer{})
	installCmd.SetErr(&bytes.Buffer{})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	stubLaunchctl(t, func(args ...string) ([]byte, error) {
		return []byte("PID\tStatus\tLabel\n123\t0\t" + launchAgentLabel + "\n"), nil
	})
	var out bytes.Buffer
	statusCmd := webStatusCmd()
	statusCmd.SetOut(&out)
	statusCmd.SetErr(&out)
	if err := statusCmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "installiert und aktiv") {
		t.Errorf("expected active status: %s", out.String())
	}
}

func TestWebStatusCmd_InstalledButInactive(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	stubLaunchctl(t, nil)
	installCmd := webInstallCmd()
	installCmd.SetOut(&bytes.Buffer{})
	installCmd.SetErr(&bytes.Buffer{})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	stubLaunchctl(t, func(args ...string) ([]byte, error) {
		return []byte("Could not find service"), errAgentNotRunning
	})
	var out bytes.Buffer
	statusCmd := webStatusCmd()
	statusCmd.SetOut(&out)
	statusCmd.SetErr(&out)
	if err := statusCmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "nicht aktiv") {
		t.Errorf("expected an inactive status: %s", out.String())
	}
}
