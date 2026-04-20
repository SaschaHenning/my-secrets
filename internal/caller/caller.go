// Package caller identifies who is invoking the current process: a human at
// an interactive shell, Claude Code / another AI agent, or a script. The
// classification is a best-effort signal from multiple sources (parent process
// chain, environment variables, TTY presence, explicit overrides).
package caller

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// Kind represents the classified caller.
type Kind string

const (
	KindHuman  Kind = "human"
	KindAI     Kind = "ai"
	KindScript Kind = "script"
)

// Detail is serialised into the audit log's actor_detail column.
type Detail struct {
	Kind       Kind     `json:"kind"`
	AgentLabel string   `json:"agent_label,omitempty"` // e.g. claude-code, cursor
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	PPIDChain  []string `json:"ppid_chain"` // executable names, child-to-parent
	TTY        bool     `json:"tty"`
	EnvFlags   []string `json:"env_flags,omitempty"`
	Executable string   `json:"executable,omitempty"`
	Override   string   `json:"override,omitempty"` // --requester value if any
	Reason     string   `json:"reason,omitempty"`   // human-readable classification reason
}

// Identify classifies the current caller.
// `override` takes precedence over detection (used by the Claude skill to
// explicitly mark AI calls).
func Identify(override string) Detail {
	d := Detail{
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
		Executable: executablePath(),
		Override:   override,
		TTY:        term.IsTerminal(int(os.Stdin.Fd())) || term.IsTerminal(int(os.Stdout.Fd())),
	}
	d.PPIDChain = parentChain(d.PPID)
	d.EnvFlags = detectEnvFlags()

	d.Kind, d.AgentLabel, d.Reason = classify(d, override)
	return d
}

// classify runs the decision rules. Rules are evaluated first-match with
// one important twist: if the caller has environmental or ancestry signals
// indicating AI, the override cannot downgrade them to `human` or `script`.
// It can only *escalate* to AI or stay at AI — this prevents a compromised
// agent from setting `--requester human` to bypass policy.
func classify(d Detail, override string) (Kind, string, string) {
	// Pre-compute the "detected" classification from env/chain/tty.
	detectedKind, detectedLabel, detectedReason := classifyDetected(d)

	switch strings.ToLower(override) {
	case "claude-code", "claude", "ai":
		return KindAI, "claude-code", "explicit --requester override"
	case "human":
		if detectedKind == KindAI {
			return detectedKind, detectedLabel,
				"override=human rejected because AI signals present (" + detectedReason + ")"
		}
		return KindHuman, "", "explicit --requester override"
	case "script":
		if detectedKind == KindAI {
			return detectedKind, detectedLabel,
				"override=script rejected because AI signals present (" + detectedReason + ")"
		}
		return KindScript, "", "explicit --requester override"
	}
	return detectedKind, detectedLabel, detectedReason
}

// classifyDetected returns the kind/label derived purely from environmental
// signals, without consulting the override.
func classifyDetected(d Detail) (Kind, string, string) {

	// Env-flag heuristics
	for _, f := range d.EnvFlags {
		switch f {
		case "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION":
			return KindAI, "claude-code", "CLAUDECODE env flag"
		case "CURSOR":
			return KindAI, "cursor", "CURSOR env flag"
		}
	}

	// Parent chain heuristics
	for _, exe := range d.PPIDChain {
		low := strings.ToLower(exe)
		if strings.Contains(low, "claude") {
			return KindAI, "claude-code", "claude in parent chain"
		}
		if strings.Contains(low, "cursor") {
			return KindAI, "cursor", "cursor in parent chain"
		}
		if strings.Contains(low, "cline") || strings.Contains(low, "aider") {
			return KindAI, low, "agent binary in parent chain"
		}
	}

	// TTY = human interactive
	if d.TTY {
		return KindHuman, "", "interactive TTY"
	}
	return KindScript, "", "non-interactive, no AI markers"
}

// aiEnvVars enumerates env variables that strongly signal an AI-driven
// invocation. ANTHROPIC_API_KEY is intentionally NOT in this list because
// humans commonly export it; its presence alone is too weak a signal.
var aiEnvVars = []string{
	"CLAUDECODE",
	"CLAUDE_CODE_ENTRYPOINT",
	"CLAUDE_CODE_SESSION",
	"CURSOR",
	"CURSOR_SESSION",
}

func detectEnvFlags() []string {
	found := []string{}
	for _, v := range aiEnvVars {
		if val, ok := os.LookupEnv(v); ok && val != "" {
			found = append(found, v)
		}
	}
	// Informational: record TERM_PROGRAM if present (e.g. vscode, iTerm).
	if tp := os.Getenv("TERM_PROGRAM"); tp != "" {
		found = append(found, "TERM_PROGRAM="+tp)
	}
	return found
}

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

// parentChain walks from ppid up to PID 1, returning executable names.
//
// On macOS and Linux we use a per-platform native lookup (sysctl / procfs)
// that returns both the process name and parent PID in a single call — one
// syscall per hop instead of two ps(1) subprocess spawns on every mys
// invocation. See caller_darwin.go and caller_linux.go. Unknown platforms
// fall back to ps via caller_other.go.
func parentChain(ppid int) []string {
	chain := []string{}
	for p := ppid; p > 1 && len(chain) < 12; {
		name, next, ok := processInfo(p)
		if !ok || name == "" {
			break
		}
		// Mirror what `ps -o comm=` would print on macOS: trim any
		// surrounding whitespace / trailing null bytes.
		chain = append(chain, strings.TrimSpace(name))
		if next == p || next <= 0 {
			break
		}
		p = next
	}
	return chain
}
