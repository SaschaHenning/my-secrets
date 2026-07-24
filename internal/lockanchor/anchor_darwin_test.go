//go:build darwin

package lockanchor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinRuntimeAnchorFilesystemIsLocal(t *testing.T) {
	anchor, _, err := openAnchor()
	if err != nil {
		t.Fatalf("open runtime anchor: %v", err)
	}
	defer anchor.Close()

	name, err := validateAnchorFilesystem(anchor)
	if err != nil {
		t.Fatalf("validate runtime anchor filesystem: %v", err)
	}
	t.Logf("validated local Darwin lock-anchor filesystem: %s", name)
}

func TestDarwinAnchorValidationRejectsInvalidInputs(t *testing.T) {
	if _, err := validateAnchorFilesystem(nil); err == nil {
		t.Fatal("nil filesystem anchor unexpectedly accepted")
	}
	if got := darwinFilesystemName([16]byte{}); got != "unknown" {
		t.Fatalf("empty filesystem name = %q", got)
	}
	if directory, err := openDirectory(
		filepath.Join(t.TempDir(), "missing"),
	); err == nil {
		_ = directory.Close()
		t.Fatal("missing anchor directory unexpectedly opened")
	}
	if err := validateLockedAnchor(nil, ""); err == nil {
		t.Fatal("nil locked anchor unexpectedly accepted")
	}
	canonicalHome, effectiveUID, err := canonicalAnchorHome()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := openDirectory(canonicalHome)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	if err := validateAnchor(nil, canonicalHome, effectiveUID); err == nil {
		t.Fatal("nil anchor unexpectedly accepted")
	}
	if err := validateAnchor(anchor, "relative", effectiveUID); err == nil {
		t.Fatal("relative anchor path unexpectedly accepted")
	}
	if _, _, err := parentWritable(nil); err == nil {
		t.Fatal("nil anchor parent unexpectedly accepted")
	}
	if mode := directoryMode(0o600); mode != os.FileMode(0o600) {
		t.Fatalf("regular mode conversion = %v", mode)
	}
}
