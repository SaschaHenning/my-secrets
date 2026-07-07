package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// TestBwPushE2E drives runBwPush against a real bw CLI + Vaultwarden.
// It is orchestrated by scripts/run_bw_push_e2e.sh, which provides the
// container, the logged-in bw state and BW_SESSION, and asserts on top
// that an unrelated vault item outside mys/* stayed byte-identical.
func TestBwPushE2E(t *testing.T) {
	if os.Getenv("MYS_BW_E2E") != "1" {
		t.Skip("set MYS_BW_E2E=1 (via scripts/run_bw_push_e2e.sh) to run")
	}
	session := os.Getenv("BW_SESSION")
	if session == "" {
		t.Fatal("BW_SESSION must be set by the orchestrating script")
	}
	ctx := context.Background()
	api := &store.Entry{
		Path: "jasp/stage/api", Org: "jasp", Kind: store.KindAPIKey,
		Username: "svc", URL: "https://api.jasp.eu", Password: "s3cr3t-1",
		Fields: map[string]string{"region": "eu-central-1"},
	}
	totp := &store.Entry{
		Path: "zuhause/github-2fa", Org: "zuhause", Kind: store.KindTOTP,
		Password: "JBSWY3DPEHPK3PXP", TOTPIssuer: "GitHub", TOTPLabel: "sascha",
	}
	a := fakeApp(t, api, totp)
	c := bw.NewClient(nil)
	opts := bwPushOptions{Session: session, Yes: true, Prune: true}
	push := func() string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runBwPush(ctx, a, c, &bytes.Buffer{}, &stdout, &stderr, opts); err != nil {
			t.Fatalf("runBwPush: %v\nstderr: %s", err, stderr.String())
		}
		return stdout.String()
	}

	// 1. Initial push creates folders + items.
	if out := push(); !strings.Contains(out, "2 created") {
		t.Fatalf("initial push: want 2 created, got:\n%s", out)
	}

	// 2. Idempotence: an immediate re-push must be a no-op.
	if out := push(); !strings.Contains(out, "already in sync") {
		t.Fatalf("re-push: want no-op, got:\n%s", out)
	}

	// 3. Rotate one entry → exactly one update.
	rotated := *api
	rotated.Password = "s3cr3t-2"
	if err := a.Store.Set(ctx, &rotated); err != nil {
		t.Fatalf("rotate in fake store: %v", err)
	}
	if out := push(); !strings.Contains(out, "0 created, 1 updated, 0 pruned") {
		t.Fatalf("after rotate: want exactly one update, got:\n%s", out)
	}

	// 4. Delete the TOTP entry → prune moves it to the trash.
	if err := a.Store.Remove(ctx, totp.Path); err != nil {
		t.Fatalf("remove in fake store: %v", err)
	}
	if out := push(); !strings.Contains(out, "0 created, 0 updated, 1 pruned") {
		t.Fatalf("after remove: want exactly one prune, got:\n%s", out)
	}

	// 5. Remote end state: only the api item remains in the namespace,
	// carrying the rotated password and a working otpauth-free login.
	if _, err := c.EnsureSession(ctx, session, nil); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}
	remote, err := bw.FetchRemoteState(ctx, c)
	if err != nil {
		t.Fatalf("fetch remote: %v", err)
	}
	if len(remote.Items) != 1 {
		t.Fatalf("remote items = %d, want 1 after prune", len(remote.Items))
	}
	got := remote.Items[0]
	if bw.PathOf(got) != api.Path {
		t.Errorf("remaining item path = %q, want %q", bw.PathOf(got), api.Path)
	}
	if got.Login == nil || got.Login.Password != "s3cr3t-2" {
		t.Error("rotated password did not arrive in the vault")
	}
}
