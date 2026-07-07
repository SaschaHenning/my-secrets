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

// TestBwImportE2E drives runBwImport against a real bw CLI + Vaultwarden.
// It is orchestrated by scripts/run_bw_import_e2e.sh, which provides the
// container, the logged-in bw state and BW_SESSION, and asserts on top
// that an unrelated vault item outside mys/* stayed byte-identical and
// that the trash stayed empty (import never deletes anything anywhere).
func TestBwImportE2E(t *testing.T) {
	if os.Getenv("MYS_BW_E2E") != "1" {
		t.Skip("set MYS_BW_E2E=1 (via scripts/run_bw_import_e2e.sh) to run")
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
	a := fakeApp(t, api)
	c := bw.NewClient(nil)

	// 1. Seed the vault via a real push, then plant the divergence a
	// phone would produce: the pushed item's password is rotated
	// remotely, and a TOTP item without a mys-path key appears in a
	// fresh mys/zuhause folder.
	var stdout, stderr bytes.Buffer
	if err := runBwPush(ctx, a, c, &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: session, Yes: true}); err != nil {
		t.Fatalf("seed push: %v\nstderr: %s", err, stderr.String())
	}
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
	if len(remote.Items) != 1 || bw.PathOf(remote.Items[0]) != api.Path {
		t.Fatalf("seed push left unexpected namespace state: %+v", remote.Items)
	}
	mutated := remote.Items[0]
	mutated.Login.Password = "rotated-on-phone"
	if err := c.EditItem(ctx, mutated.ID, mutated); err != nil {
		t.Fatalf("remote edit: %v", err)
	}
	zuhause, err := c.CreateFolder(ctx, "mys/zuhause")
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	if _, err := c.CreateItem(ctx, bw.Item{
		Type: bw.TypeLogin, Name: "github-phone", FolderID: zuhause.ID,
		Login: &bw.Login{TOTP: "otpauth://totp/GitHub:sascha?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"},
	}); err != nil {
		t.Fatalf("create phone item: %v", err)
	}
	// A store entry the vault has never seen → STORE-ONLY material.
	extra := &store.Entry{Path: "jasp/extra", Org: "jasp", Kind: store.KindPassword, Password: "extra-pw"}
	if err := a.Store.Set(ctx, extra); err != nil {
		t.Fatalf("plant store-only entry: %v", err)
	}

	imp := func(opts bwImportOptions) string {
		t.Helper()
		var out, errb bytes.Buffer
		opts.Session = session
		if err := runBwImport(ctx, a, c, &bytes.Buffer{}, &out, &errb, opts); err != nil {
			t.Fatalf("runBwImport: %v\nstderr: %s", err, errb.String())
		}
		return out.String()
	}

	// 2. Diff-only: correct classification, zero writes on either side.
	out := imp(bwImportOptions{})
	for _, want := range []string{
		"CHANGED",
		api.Path + " (password)",
		"NEW",
		"zuhause/github-phone",
		"STORE-ONLY",
		"jasp/extra",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rotated-on-phone") || strings.Contains(out, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("diff output must never carry values:\n%s", out)
	}
	if e, err := a.Store.Get(ctx, api.Path); err != nil || e.Password != "s3cr3t-1" {
		t.Fatalf("diff-only run must not touch the store (got %+v, err %v)", e, err)
	}

	// 3. Apply: the rotated password lands in the store, the phone item
	// becomes a TOTP entry, the store-only entry survives.
	if out := imp(bwImportOptions{Apply: true, Yes: true}); !strings.Contains(out, "2 applied") {
		t.Fatalf("apply: want 2 applied, got:\n%s", out)
	}
	if e, err := a.Store.Get(ctx, api.Path); err != nil || e.Password != "rotated-on-phone" {
		t.Errorf("rotated password did not arrive in the store: %+v (err %v)", e, err)
	}
	phone, err := a.Store.Get(ctx, "zuhause/github-phone")
	if err != nil {
		t.Fatalf("phone item was not created: %v", err)
	}
	if phone.Kind != store.KindTOTP || phone.Password != "JBSWY3DPEHPK3PXP" || phone.TOTPIssuer != "GitHub" {
		t.Errorf("phone entry = %+v, want totp entry with seed", phone)
	}
	if _, err := a.Store.Get(ctx, extra.Path); err != nil {
		t.Errorf("STORE-ONLY entry must never be deleted: %v", err)
	}

	// 4. Idempotence: a second apply run finds nothing to import.
	if out := imp(bwImportOptions{Apply: true, Yes: true}); !strings.Contains(out, "nothing to import") {
		t.Fatalf("re-import: want no-op, got:\n%s", out)
	}

	// 5. Import must not have written to the vault: same two items, the
	// phone item still without a mys-path key.
	if err := c.Sync(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}
	after, err := bw.FetchRemoteState(ctx, c)
	if err != nil {
		t.Fatalf("fetch remote: %v", err)
	}
	if len(after.Items) != 2 {
		t.Fatalf("vault items = %d, want 2 (import never writes to Bitwarden)", len(after.Items))
	}
	for _, it := range after.Items {
		if it.Name == "github-phone" && bw.PathOf(it) != "" {
			t.Error("import must not stamp mys-path onto vault items")
		}
	}
}
