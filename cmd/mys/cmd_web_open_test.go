package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubOpenURL replaces openURLFunc with a recorder for the duration of t
// and returns a pointer to the slice of URLs it was asked to open.
func stubOpenURL(t *testing.T, err error) *[]string {
	t.Helper()
	var opened []string
	prev := openURLFunc
	openURLFunc = func(url string) error {
		opened = append(opened, url)
		return err
	}
	t.Cleanup(func() { openURLFunc = prev })
	return &opened
}

// stubWaitForListen replaces waitForListen with a no-op so tests never
// dial a real (never-started) TCP port and block for the full timeout.
func stubWaitForListen(t *testing.T) {
	t.Helper()
	prev := waitForListen
	waitForListen = func(port int, timeout time.Duration) {}
	t.Cleanup(func() { waitForListen = prev })
}

// installForTest installs the LaunchAgent into an isolated $HOME so an
// open-command test has a plist to read a port from. launchctl must
// already be stubbed by the caller.
func installForTest(t *testing.T, args ...string) {
	t.Helper()
	cmd := webInstallCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
}

func TestInstalledWebPort_NotInstalled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	port, installed, err := installedWebPort()
	if err != nil {
		t.Fatalf("installedWebPort: %v", err)
	}
	if installed || port != 0 {
		t.Errorf("want (0, false), got (%d, %v)", port, installed)
	}
}

func TestInstalledWebPort_DefaultPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubLaunchctl(t, nil)
	installForTest(t)

	port, installed, err := installedWebPort()
	if err != nil {
		t.Fatalf("installedWebPort: %v", err)
	}
	if !installed || port != defaultWebPort {
		t.Errorf("want (%d, true), got (%d, %v)", defaultWebPort, port, installed)
	}
}

// writePlist places a raw plist body at the LaunchAgent path for the
// current (test-isolated) $HOME, creating the directory as needed. Used to
// stage malformed/edge-case agents that installForTest can't produce.
func writePlist(t *testing.T, body string) {
	t.Helper()
	p := mustPlistPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write plist: %v", err)
	}
}

// TestInstalledWebPort_PresentButPortUnparsable covers the fallback where a
// plist exists but portArgRe matches nothing (here: no --port pair at all,
// e.g. a hand-edited or future-format agent). Must report installed=true at
// the default port rather than erroring or claiming not-installed.
func TestInstalledWebPort_PresentButPortUnparsable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePlist(t, `<?xml version="1.0"?><plist version="1.0"><dict>
	<key>ProgramArguments</key><array>
		<string>/usr/local/bin/mys</string>
		<string>web</string>
	</array>
</dict></plist>`)

	port, installed, err := installedWebPort()
	if err != nil {
		t.Fatalf("installedWebPort: %v", err)
	}
	if !installed || port != defaultWebPort {
		t.Errorf("unparsable port: want (%d, true), got (%d, %v)", defaultWebPort, port, installed)
	}
}

// TestInstalledWebPort_PresentButPortOutOfRange covers the other fallback:
// the --port value parses as an int but is outside 1..65535, so it must be
// rejected in favour of the default rather than opening a nonsense port.
func TestInstalledWebPort_PresentButPortOutOfRange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePlist(t, renderLaunchAgentPlist("/usr/local/bin/mys", 99999, "/tmp/web.log", "/usr/bin:/bin"))

	port, installed, err := installedWebPort()
	if err != nil {
		t.Fatalf("installedWebPort: %v", err)
	}
	if !installed || port != defaultWebPort {
		t.Errorf("out-of-range port: want (%d, true), got (%d, %v)", defaultWebPort, port, installed)
	}
}

func TestInstalledWebPort_CustomPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubLaunchctl(t, nil)
	installForTest(t, "--port", "9999")

	port, installed, err := installedWebPort()
	if err != nil {
		t.Fatalf("installedWebPort: %v", err)
	}
	if !installed || port != 9999 {
		t.Errorf("want (9999, true), got (%d, %v)", port, installed)
	}
}

func TestWebOpenCmd_OpensInstalledDefaultPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubLaunchctl(t, nil)
	installForTest(t)
	opened := stubOpenURL(t, nil)

	var out bytes.Buffer
	cmd := webOpenCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("open: %v", err)
	}

	if len(*opened) != 1 || (*opened)[0] != "http://127.0.0.1:7823" {
		t.Fatalf("expected open of default URL, got %v", *opened)
	}
	if !bytes.Contains(out.Bytes(), []byte("geöffnet")) {
		t.Errorf("expected a 'geöffnet' message: %s", out.String())
	}
}

func TestWebOpenCmd_OpensInstalledCustomPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubLaunchctl(t, nil)
	installForTest(t, "--port", "9999")
	opened := stubOpenURL(t, nil)

	var out bytes.Buffer
	cmd := webOpenCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("open: %v", err)
	}

	if len(*opened) != 1 || (*opened)[0] != "http://127.0.0.1:9999" {
		t.Fatalf("expected open of custom-port URL, got %v", *opened)
	}
}

func TestWebOpenCmd_NoInstallFlagWhenMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	calls := stubLaunchctl(t, nil)
	opened := stubOpenURL(t, nil)

	var out bytes.Buffer
	cmd := webOpenCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--no-install"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("open: %v", err)
	}

	if len(*calls) != 0 {
		t.Errorf("--no-install on a missing agent must not touch launchctl, got %v", *calls)
	}
	if len(*opened) != 0 {
		t.Errorf("--no-install on a missing agent must not open a browser, got %v", *opened)
	}
	if !bytes.Contains(out.Bytes(), []byte("nicht installiert")) {
		t.Errorf("expected a not-installed message: %s", out.String())
	}
}

func TestWebOpenCmd_AutoInstallsWhenMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	calls := stubLaunchctl(t, nil)
	stubWaitForListen(t)
	opened := stubOpenURL(t, nil)

	var out bytes.Buffer
	cmd := webOpenCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("open: %v", err)
	}

	// The plist must have been written and loaded via launchctl.
	if _, err := os.Stat(mustPlistPath(t)); err != nil {
		t.Errorf("open should have installed the plist: %v", err)
	}
	var loaded bool
	for _, c := range *calls {
		if len(c) > 0 && c[0] == "load" {
			loaded = true
		}
	}
	if !loaded {
		t.Errorf("open should have run `launchctl load`, calls: %v", *calls)
	}
	if len(*opened) != 1 || (*opened)[0] != "http://127.0.0.1:7823" {
		t.Fatalf("expected open of default URL after auto-install, got %v", *opened)
	}
	if !bytes.Contains(out.Bytes(), []byte("installiert")) {
		t.Errorf("expected an install notice: %s", out.String())
	}
}

func TestWebOpenCmd_ReportsBrowserOpenFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubLaunchctl(t, nil)
	installForTest(t)
	stubOpenURL(t, os.ErrPermission)

	var out bytes.Buffer
	cmd := webOpenCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("open must not hard-fail on a browser error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("manuell öffnen")) {
		t.Errorf("expected a manual-open fallback message: %s", out.String())
	}
}

// mustPlistPath returns the LaunchAgent plist path for the current
// (test-isolated) $HOME, failing the test if it cannot be resolved.
func mustPlistPath(t *testing.T) string {
	t.Helper()
	p, err := launchAgentPlistPath()
	if err != nil {
		t.Fatalf("launchAgentPlistPath: %v", err)
	}
	return p
}
