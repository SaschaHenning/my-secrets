package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// launchAgentLabel matches the reverse-DNS style already used for this
// project's Keychain service names (com.jasp.my-secrets.audit-signing).
const launchAgentLabel = "com.jasp.my-secrets.web"

// defaultWebPort is the single source of truth for the port `mys web`,
// `mys web install`, and `mys web open` default to. The web UI binds
// 127.0.0.1 only (internal/web), so this is a loopback-local port.
const defaultWebPort = 7823

// webURL renders the loopback URL the web UI is reachable at. Kept in one
// place so install/open/status all print an identical, correct address.
func webURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// launchctlRun is the subprocess indirection `mys web install/uninstall/
// status` use for every launchctl call. A package-level var (same
// pattern as internal/web's requireTouchIDFunc and internal/history's
// mountPathLookup) so tests can stub it out entirely: launchctl operates
// on the real, live, global launchd session for the current user — NOT
// scoped to any test's isolated $HOME — so a test must never invoke the
// real binary, or `go test` would register/deregister an actual
// LaunchAgent on the machine running the tests.
var launchctlRun = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput()
}

// launchAgentPlistPath returns where the LaunchAgent definition lives:
// ~/Library/LaunchAgents/com.jasp.my-secrets.web.plist.
func launchAgentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

// webLogPath returns ~/.local/share/my-secrets/web.log — same base
// directory as the audit DB (audit.DefaultPath), used here for the
// LaunchAgent's stdout/stderr capture.
func webLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "my-secrets", "web.log"), nil
}

// xmlEscape escapes a string for safe inclusion as plist XML text
// content. binPath/logPath below come from os.Executable() and $HOME —
// not attacker-controlled under this tool's single-user threat model —
// but a path containing &, <, or > would otherwise produce malformed or
// structurally altered XML, so escape unconditionally rather than
// relying on that assumption staying true forever.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// fallbackAgentPATH is used when $PATH is empty at install time (should
// not normally happen — os.Getenv("PATH") is empty only in a stripped
// environment). Covers Homebrew on both Apple Silicon and Intel plus the
// standard system dirs, matching where this project's own docs tell
// users to install gopass/gnupg/git (README "Voraussetzungen").
const fallbackAgentPATH = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

// renderLaunchAgentPlist builds the plist body. KeepAlive is
// unconditional (not the {SuccessfulExit: false} form) — deliberately,
// so launchd restarts the process even after the existing 30-minute
// idle-shutdown's *clean* exit, not just a crash. The security posture
// is unchanged by this: the session cookie still expires after 30
// minutes of inactivity (internal/web/session.go), and every relaunch
// starts with an empty in-memory session store — only the *process*
// stops sleeping forever, not the login requirement.
//
// EnvironmentVariables/PATH is required, not cosmetic: launchd gives a
// LaunchAgent a bare minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin) with
// no inheritance from the installing shell, so without this `mys web`
// cannot find `gpg`/`gopass`/`git` (typically under /opt/homebrew) and
// fails on every single request that touches the store. path is the
// installing shell's own $PATH, captured at `mys web install` time —
// this correctly picks up whatever the user actually has configured
// (Homebrew, MacGPG2, a custom gopass build, ...) rather than guessing.
func renderLaunchAgentPlist(binPath string, port int, logPath, path string) string {
	if path == "" {
		path = fallbackAgentPATH
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array>
		<string>%s</string>
		<string>web</string>
		<string>--port</string>
		<string>%d</string>
	</array>
	<key>EnvironmentVariables</key><dict>
		<key>PATH</key><string>%s</string>
	</dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardOutPath</key><string>%s</string>
	<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, launchAgentLabel, xmlEscape(binPath), port, xmlEscape(path), xmlEscape(logPath), xmlEscape(logPath))
}

// installWebAgent writes the LaunchAgent plist for `mys web --port <port>`
// and (re)loads it via launchctl, returning the plist path on success. It
// holds the full install sequence so both `mys web install` and the
// auto-install path of `mys web open` share exactly one implementation.
func installWebAgent(port int) (plistPath string, err error) {
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("eigenen Binary-Pfad ermitteln: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	plistPath, err = launchAgentPlistPath()
	if err != nil {
		return "", err
	}
	logPath, err := webLogPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return "", fmt.Errorf("log-Verzeichnis anlegen: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
		return "", fmt.Errorf("LaunchAgents-Verzeichnis anlegen: %w", err)
	}
	plist := renderLaunchAgentPlist(bin, port, logPath, os.Getenv("PATH"))
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return "", fmt.Errorf("plist schreiben: %w", err)
	}
	// Unload first so a re-install (e.g. after --port changed) actually
	// picks up the new definition; ignore the error, since "not currently
	// loaded" is the common case and is not itself a failure.
	_, _ = launchctlRun("unload", plistPath)
	if out, err := launchctlRun("load", plistPath); err != nil {
		return "", fmt.Errorf("launchctl load: %w\n%s", err, out)
	}
	return plistPath, nil
}

// webInstallCmd builds `mys web install`.
func webInstallCmd() *cobra.Command {
	var port int
	c := &cobra.Command{
		Use:   "install",
		Short: "Installiert mys web als LaunchAgent (Autostart, übersteht Idle-Shutdown)",
		Long: `Schreibt eine macOS-LaunchAgent-Definition, die "mys web" beim Login startet
und sofort neu startet, sobald der Prozess endet — auch nach dem regulären
30-Minuten-Idle-Shutdown. Sicherheitsverhalten bleibt unverändert: die
Login-Session läuft weiterhin nach 30 Minuten Inaktivität ab, nur der
Server-Prozess selbst schläft nie dauerhaft ein. Ein installiertes
PWA-Icon trifft danach immer auf einen laufenden Server statt auf
"Verbindung abgelehnt".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			plistPath, err := installWebAgent(port)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"installiert: %s\nmys web läuft künftig dauerhaft auf %s — auch nach Neustart oder Idle-Shutdown\nÖffnen mit: mys web open\n",
				plistPath, webURL(port))
			return nil
		},
	}
	c.Flags().IntVar(&port, "port", defaultWebPort, "Port für den Autostart-Server")
	return c
}

// webUninstallCmd builds `mys web uninstall`.
func webUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Entfernt den mys-web-LaunchAgent wieder",
		RunE: func(cmd *cobra.Command, args []string) error {
			plistPath, err := launchAgentPlistPath()
			if err != nil {
				return err
			}
			if _, statErr := os.Stat(plistPath); os.IsNotExist(statErr) {
				fmt.Fprintln(cmd.OutOrStdout(), "kein LaunchAgent installiert")
				return nil
			}
			_, _ = launchctlRun("unload", plistPath)
			if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("plist entfernen: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "entfernt:", plistPath)
			return nil
		},
	}
}

// webStatusCmd builds `mys web status`.
func webStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Zeigt, ob der mys-web-LaunchAgent installiert und aktiv ist",
		RunE: func(cmd *cobra.Command, args []string) error {
			plistPath, err := launchAgentPlistPath()
			if err != nil {
				return err
			}
			if _, statErr := os.Stat(plistPath); os.IsNotExist(statErr) {
				fmt.Fprintln(cmd.OutOrStdout(), "nicht installiert — `mys web install` ausführen")
				return nil
			}
			out, err := launchctlRun("list", launchAgentLabel)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "installiert (%s), aber aktuell nicht aktiv: %s\n",
					plistPath, strings.TrimSpace(string(out)))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installiert und aktiv: %s\n%s", plistPath, out)
			return nil
		},
	}
}
