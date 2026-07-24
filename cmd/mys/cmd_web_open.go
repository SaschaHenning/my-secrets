package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

// portArgRe extracts the configured port from an installed LaunchAgent
// plist. The plist is authored by renderLaunchAgentPlist, so its
// ProgramArguments always carry `--port` immediately followed by the
// numeric value — matching that pair is enough and avoids pulling in a
// full plist parser for one integer.
var portArgRe = regexp.MustCompile(`<string>--port</string>\s*<string>(\d+)</string>`)

// openURLFunc opens a URL in the user's default browser. A package-level
// var (same testability pattern as launchctlRun) so tests can record the
// call instead of spawning a real `open`.
var openURLFunc = func(url string) error {
	return exec.Command("open", url).Run()
}

// waitForListen blocks until 127.0.0.1:port accepts a TCP connection or
// timeout elapses. A freshly (re)loaded LaunchAgent needs a brief moment
// before its HTTP listener is up; without this the first browser open
// races the server and shows a transient "connection refused". Best-effort
// — it never fails the command, it just improves the first-open UX. A
// package-level var so tests skip the real dial.
var waitForListen = func(port int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// installedWebPort reports the port the installed LaunchAgent is
// configured for, honoring a custom `mys web install --port`. installed is
// false when no plist exists yet. A plist that exists but cannot be parsed
// (or carries an out-of-range port) falls back to defaultWebPort with
// installed=true, so `open` still does something sensible rather than
// erroring on a malformed-but-present agent.
func installedWebPort() (port int, installed bool, err error) {
	plistPath, err := launchAgentPlistPath()
	if err != nil {
		return 0, false, err
	}
	data, err := os.ReadFile(plistPath)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	m := portArgRe.FindSubmatch(data)
	if m == nil {
		return defaultWebPort, true, nil
	}
	p, convErr := strconv.Atoi(string(m[1]))
	if convErr != nil || p <= 0 || p > 65535 {
		return defaultWebPort, true, nil
	}
	return p, true, nil
}

// webOpenCmd builds `mys web open`.
func webOpenCmd() *cobra.Command {
	var noInstall bool
	c := &cobra.Command{
		Use:   "open",
		Short: "Öffnet die mys-web-Oberfläche im Browser (installiert den Autostart bei Bedarf)",
		Long: `Öffnet die lokale mys-web-Oberfläche (http://127.0.0.1:<port>) im
Standardbrowser. Der Port wird aus dem installierten LaunchAgent gelesen
und respektiert damit ein früheres "mys web install --port".

Ist noch kein LaunchAgent installiert, wird er automatisch eingerichtet
und dann geöffnet. Mit --no-install unterbleibt das: stattdessen wird nur
gemeldet, dass nichts installiert ist.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			port, installed, err := installedWebPort()
			if err != nil {
				return err
			}
			if !installed {
				if noInstall {
					fmt.Fprintln(out, "nicht installiert — `mys web install` ausführen (oder `mys web open` ohne --no-install)")
					return nil
				}
				fmt.Fprintln(out, "kein LaunchAgent installiert — richte ihn jetzt ein…")
				plistPath, err := installWebAgent(defaultWebPort)
				if err != nil {
					return err
				}
				port = defaultWebPort
				fmt.Fprintf(out, "installiert: %s\n", plistPath)
				// Give the just-loaded server a moment to bind before the
				// browser races it.
				waitForListen(port, 5*time.Second)
			}
			url := webURL(port)
			if err := openURLFunc(url); err != nil {
				fmt.Fprintf(out, "konnte den Browser nicht öffnen (%v) — bitte manuell öffnen: %s\n", err, url)
				return nil
			}
			fmt.Fprintf(out, "geöffnet: %s\n", url)
			return nil
		},
	}
	c.Flags().BoolVar(&noInstall, "no-install", false,
		"nicht automatisch installieren, wenn kein LaunchAgent vorhanden ist")
	return c
}
