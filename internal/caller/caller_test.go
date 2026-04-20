package caller

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestClassifyOverride(t *testing.T) {
	cases := []struct {
		override string
		want     Kind
		label    string
	}{
		{"claude-code", KindAI, "claude-code"},
		{"claude", KindAI, "claude-code"},
		{"ai", KindAI, "claude-code"},
		{"human", KindHuman, ""},
		{"script", KindScript, ""},
	}
	for _, tc := range cases {
		k, label, _ := classify(Detail{}, tc.override)
		if k != tc.want {
			t.Errorf("override %q: want kind=%s, got %s", tc.override, tc.want, k)
		}
		if label != tc.label {
			t.Errorf("override %q: want label=%s, got %s", tc.override, tc.label, label)
		}
	}
}

func TestClassifyEnvFlags(t *testing.T) {
	k, label, _ := classify(Detail{EnvFlags: []string{"CLAUDECODE"}}, "")
	if k != KindAI || label != "claude-code" {
		t.Errorf("CLAUDECODE env: got kind=%s label=%s", k, label)
	}
	k, _, _ = classify(Detail{EnvFlags: []string{"CURSOR"}}, "")
	if k != KindAI {
		t.Errorf("CURSOR env: want AI, got %s", k)
	}
}

func TestClassifyTTY(t *testing.T) {
	k, _, _ := classify(Detail{TTY: true}, "")
	if k != KindHuman {
		t.Errorf("TTY human: want human, got %s", k)
	}
	k, _, _ = classify(Detail{TTY: false}, "")
	if k != KindScript {
		t.Errorf("non-TTY: want script, got %s", k)
	}
}

func TestClassifyParentChain(t *testing.T) {
	k, label, _ := classify(Detail{PPIDChain: []string{"node", "claude", "zsh"}}, "")
	if k != KindAI || label != "claude-code" {
		t.Errorf("parent chain claude: got kind=%s label=%s", k, label)
	}
}

func TestIdentifyRuns(t *testing.T) {
	// Smoke test: Identify() should not panic on a normal test process.
	d := Identify("")
	if d.PID == 0 {
		t.Error("expected non-zero PID")
	}
}

// TestProcessInfoMatchesOS ensures our native processInfo (sysctl on macOS,
// procfs on Linux, ps fallback elsewhere) returns the same ppid the kernel
// reports to the Go runtime. The process name is platform-dependent but
// must not be empty.
func TestProcessInfoMatchesOS(t *testing.T) {
	pid := os.Getpid()
	name, ppid, ok := processInfo(pid)
	if !ok {
		t.Fatalf("processInfo(%d) returned ok=false", pid)
	}
	if name == "" {
		t.Errorf("processInfo(%d): empty name", pid)
	}
	if ppid != os.Getppid() {
		t.Errorf("processInfo(%d): ppid=%d, want %d", pid, ppid, os.Getppid())
	}
}

// TestProcessInfoMatchesPS cross-checks processInfo against ps(1) for the
// current process. It is skipped if ps is unavailable or returns something
// we cannot parse — we do not want flaky CI failures, only a positive
// integrity check when the environment cooperates.
func TestProcessInfoMatchesPS(t *testing.T) {
	psBin, err := exec.LookPath("ps")
	if err != nil {
		t.Skip("ps not available")
	}
	pid := os.Getpid()
	out, err := exec.Command(psBin, "-o", "comm=,ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Skipf("ps failed: %v", err)
	}
	line := strings.TrimSpace(string(out))
	idx := strings.LastIndexAny(line, " \t")
	if idx < 0 {
		t.Skipf("unexpected ps output: %q", line)
	}
	psPPID, err := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
	if err != nil {
		t.Skipf("cannot parse ps ppid from %q: %v", line, err)
	}

	_, nativePPID, ok := processInfo(pid)
	if !ok {
		t.Fatalf("processInfo(%d) ok=false", pid)
	}
	if nativePPID != psPPID {
		t.Errorf("ppid mismatch: native=%d ps=%d", nativePPID, psPPID)
	}
}

// BenchmarkParentChain measures the cost of a full parent-chain walk for
// the current process. Before this change the hot path spawned up to 24
// ps subprocesses per mys invocation (two per hop, up to 12 hops); after
// the change it issues one syscall per hop.
func BenchmarkParentChain(b *testing.B) {
	ppid := os.Getppid()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parentChain(ppid)
	}
}
