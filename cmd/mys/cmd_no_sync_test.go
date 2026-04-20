package main

import (
	"io"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/spf13/cobra"
)

// TestRootCmd_NoSyncFlagExists proves the root command exposes the
// persistent `--no-sync` boolean flag with a default of false.
func TestRootCmd_NoSyncFlagExists(t *testing.T) {
	root := rootCmd()
	f := root.PersistentFlags().Lookup("no-sync")
	if f == nil {
		t.Fatal("expected persistent --no-sync flag on root command")
	}
	if f.Value.Type() != "bool" {
		t.Errorf("--no-sync should be a bool, got %q", f.Value.Type())
	}
	if f.DefValue != "false" {
		t.Errorf("--no-sync default = %q, want false", f.DefValue)
	}
}

// TestRootCmd_NoSyncFlagWiresIntoAppPackage verifies that parsing
// `--no-sync` on the root command flips app.NoSyncFlag to true once
// PersistentPreRun has fired. We attach a throwaway subcommand so
// cobra actually reaches the PreRun stage — running with --version or
// --help exits early before PreRun is called.
func TestRootCmd_NoSyncFlagWiresIntoAppPackage(t *testing.T) {
	prev := app.NoSyncFlag
	t.Cleanup(func() { app.NoSyncFlag = prev })
	app.NoSyncFlag = false

	root := rootCmd()
	// Quiet the root output so the test log stays clean.
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	// A no-op subcommand that still triggers the root's PersistentPreRun.
	root.AddCommand(&cobra.Command{
		Use:  "_noop_",
		RunE: func(*cobra.Command, []string) error { return nil },
	})
	root.SetArgs([]string{"--no-sync", "_noop_"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !app.NoSyncFlag {
		t.Error("expected app.NoSyncFlag=true after --no-sync on root command")
	}
}

// TestRootCmd_NoSyncFlagDefaultsFalse proves that running without the
// flag leaves app.NoSyncFlag at its zero value after PreRun runs.
func TestRootCmd_NoSyncFlagDefaultsFalse(t *testing.T) {
	prev := app.NoSyncFlag
	t.Cleanup(func() { app.NoSyncFlag = prev })
	app.NoSyncFlag = true // start from true to prove PreRun resets it

	root := rootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.AddCommand(&cobra.Command{
		Use:  "_noop_",
		RunE: func(*cobra.Command, []string) error { return nil },
	})
	root.SetArgs([]string{"_noop_"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if app.NoSyncFlag {
		t.Error("expected app.NoSyncFlag=false when --no-sync is not passed")
	}
}
