package caller

import (
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
