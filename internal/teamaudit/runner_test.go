package teamaudit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type hermeticTestRunner struct {
	env []string
}

func (runner hermeticTestRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append([]string(nil), runner.env...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf(
			"%s failed: %w: %s",
			name,
			err,
			sanitizeCommandOutput(output),
		)
	}
	return output, nil
}

func newHermeticTestEnvironment(t *testing.T, root string) []string {
	home := filepath.Join(root, "command-home")
	config := filepath.Join(root, "command-config")
	templates := filepath.Join(root, "empty-git-templates")
	for _, path := range []string{home, config, templates} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create hermetic command directory: %v", err)
		}
	}
	environment := make([]string, 0, 16)
	for _, key := range []string{
		"PATH",
		"TMPDIR",
		"TMP",
		"TEMP",
		"SystemRoot",
		"COMSPEC",
		"PATHEXT",
	} {
		if value, exists := os.LookupEnv(key); exists {
			environment = append(environment, key+"="+value)
		}
	}
	return append(
		environment,
		"HOME="+home,
		"XDG_CONFIG_HOME="+config,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TEMPLATE_DIR="+templates,
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
		"SSH_ASKPASS_REQUIRE=never",
		"LC_ALL=C",
	)
}
