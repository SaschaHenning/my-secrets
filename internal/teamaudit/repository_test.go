package teamaudit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	probeTestTreeOID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	probeTestCommitOID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	probeTestStaleOID  = "cccccccccccccccccccccccccccccccccccccccc"
)

type probeConfirmationRunner struct {
	confirmation string
	cleanupErr   error

	branch        string
	remoteCommit  string
	lsRemoteCalls int
	deleteCalls   int
}

func (runner *probeConfirmationRunner) Run(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	if name != "git" {
		return nil, fmt.Errorf("unexpected command %q", name)
	}
	if hasProbeTestArgument(args, "hash-object") {
		return []byte(probeTestTreeOID + "\n"), nil
	}
	if hasProbeTestArgument(args, "commit-tree") {
		return []byte(probeTestCommitOID + "\n"), nil
	}
	if hasProbeTestArgument(args, "ls-remote") {
		runner.lsRemoteCalls++
		ref := args[len(args)-1]
		runner.branch = strings.TrimPrefix(ref, "refs/heads/")
		if runner.lsRemoteCalls == 1 {
			return nil, nil
		}
		if runner.lsRemoteCalls == 2 {
			switch runner.confirmation {
			case "missing":
				return nil, nil
			case "stale":
				return []byte(probeTestStaleOID + "\t" + ref + "\n"), nil
			default:
				return nil, fmt.Errorf(
					"unexpected confirmation mode %q",
					runner.confirmation,
				)
			}
		}
		if runner.remoteCommit == "" {
			return nil, nil
		}
		return []byte(runner.remoteCommit + "\t" + ref + "\n"), nil
	}
	if hasProbeTestArgument(args, "push") {
		refspec := args[len(args)-1]
		if strings.HasPrefix(refspec, ":refs/heads/") {
			runner.deleteCalls++
			if runner.cleanupErr != nil {
				return nil, runner.cleanupErr
			}
			runner.remoteCommit = ""
			return []byte("ok\n"), nil
		}
		commit, ref, ok := strings.Cut(refspec, ":refs/heads/")
		if !ok {
			return nil, fmt.Errorf("unexpected probe refspec %q", refspec)
		}
		runner.branch = ref
		runner.remoteCommit = commit
		return []byte("ok\n"), nil
	}
	return nil, fmt.Errorf("unexpected git arguments %q", args)
}

func hasProbeTestArgument(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func TestProveRemoteWriteCleansUpAfterUnconfirmedPush(t *testing.T) {
	tests := []struct {
		name          string
		confirmation  string
		wantErrorText string
	}{
		{
			name:          "missing confirmation",
			confirmation:  "missing",
			wantErrorText: "did not reach the remote",
		},
		{
			name:          "stale confirmation",
			confirmation:  "stale",
			wantErrorText: "remote ownership mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &probeConfirmationRunner{
				confirmation: test.confirmation,
			}
			manager := probeTestManager(runner)

			err := manager.proveRemoteWrite(context.Background())

			if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Fatalf("probe error = %v, want %q", err, test.wantErrorText)
			}
			if runner.deleteCalls != 1 {
				t.Fatalf(
					"probe cleanup calls = %d, want 1",
					runner.deleteCalls,
				)
			}
			if runner.remoteCommit != "" {
				t.Fatalf(
					"probe ref %q remains at %q",
					runner.branch,
					runner.remoteCommit,
				)
			}
		})
	}
}

func TestProveRemoteWriteFailsClosedWhenUnconfirmedCleanupFails(
	t *testing.T,
) {
	cleanupErr := errors.New("simulated probe cleanup denial")
	runner := &probeConfirmationRunner{
		confirmation: "missing",
		cleanupErr:   cleanupErr,
	}
	manager := probeTestManager(runner)

	err := manager.proveRemoteWrite(context.Background())

	if err == nil ||
		!strings.Contains(err.Error(), "did not reach the remote") ||
		!errors.Is(err, cleanupErr) ||
		!strings.Contains(err.Error(), "cleanup was not confirmed") {
		t.Fatalf("probe cleanup error = %v", err)
	}
	if runner.deleteCalls != 1 {
		t.Fatalf("probe cleanup calls = %d, want 1", runner.deleteCalls)
	}
	if runner.remoteCommit != probeTestCommitOID {
		t.Fatalf(
			"failed cleanup remote commit = %q, want %q",
			runner.remoteCommit,
			probeTestCommitOID,
		)
	}
}

func probeTestManager(runner Runner) *Manager {
	return &Manager{
		config: Config{
			URL:     "file:///audit.git",
			WorkDir: "/audit-work",
		},
		runner: runner,
		newID: func() string {
			return "11111111-1111-4111-8111-111111111111"
		},
	}
}
