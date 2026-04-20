package recipient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- parser unit tests ------------------------------------------------------

const showKeysFixture = `tru::1:1705320000:1760441808:3:1:5
pub:-:3072:1:ABCDEF0123456789:1705320000:1760441808::-:::scESC:::::::
fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
uid:-::::1705320000::11111111111111111111111111111111::Alice Example \x3calice@example.org\x3e::::::::::0:
sub:-:3072:1:1111222233334444:1705320000:1760441808:::::e::::::
fpr:::::::::1111111111111111111111111111111111111111:
`

func TestParseFirstFprUID(t *testing.T) {
	fpr, uid := parseFirstFprUID([]byte(showKeysFixture))
	wantFpr := "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	if fpr != wantFpr {
		t.Errorf("fpr = %q, want %q", fpr, wantFpr)
	}
	if !strings.Contains(uid, "Alice Example") {
		t.Errorf("uid = %q, expected it to contain 'Alice Example'", uid)
	}
	if !strings.Contains(uid, "<alice@example.org>") {
		t.Errorf("uid = %q, expected it to contain '<alice@example.org>' (unescaped)", uid)
	}
}

func TestParseFirstFprUID_Empty(t *testing.T) {
	fpr, uid := parseFirstFprUID([]byte(""))
	if fpr != "" || uid != "" {
		t.Errorf("expected empty result, got fpr=%q uid=%q", fpr, uid)
	}
}

const listKeysFixture = `tru::1:1705320000:1760441808:3:1:5
pub:-:3072:1:ABCDEF0123456789:1705320000:1760441808::-:::scESC:::::::
fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
uid:-::::1705320000::11111111111111111111111111111111::Alice Example \x3calice@example.org\x3e::::::::::0:
uid:-::::1705320000::22222222222222222222222222222222::Alice at Work \x3calice@work.example\x3e::::::::::0:
sub:-:3072:1:1111222233334444:1705320000:1760441808:::::e::::::
pub:-:3072:1:DEADBEEFDEADBEEF:1705320000:1760441808::-:::scESC:::::::
fpr:::::::::DDDDEEEEFFFF0000111122223333444455556666:
uid:-::::1705320000::33333333333333333333333333333333::Other Person \x3cother@example.org\x3e::::::::::0:
`

func TestParseKeyDetails(t *testing.T) {
	uids, expires := parseKeyDetails([]byte(listKeysFixture))
	if len(uids) != 2 {
		t.Fatalf("want 2 uids for the first pub, got %d: %v", len(uids), uids)
	}
	if !strings.Contains(uids[0], "alice@example.org") {
		t.Errorf("first uid mismatch: %q", uids[0])
	}
	if !strings.Contains(uids[1], "alice@work.example") {
		t.Errorf("second uid mismatch: %q", uids[1])
	}
	// Expiry: 1760441808 -> 2025-10-14 10:16:48 UTC
	if expires.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
	want := time.Unix(1760441808, 0).UTC()
	if !expires.Equal(want) {
		t.Errorf("expiry = %v, want %v", expires, want)
	}
}

func TestParseKeyDetails_NoExpiry(t *testing.T) {
	input := "pub:-:3072:1:ABCDEF0123456789:1705320000:::-:::scESC:::::::\n" +
		"fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:\n" +
		"uid:-::::1705320000::11111111111111111111111111111111::Alice::::::::::0:\n"
	uids, expires := parseKeyDetails([]byte(input))
	if len(uids) != 1 {
		t.Errorf("want 1 uid, got %d", len(uids))
	}
	if !expires.IsZero() {
		t.Errorf("expected zero expiry, got %v", expires)
	}
}

const gopassRecipientsFixture = `gopass
└── gpg
    ├── 0xAAAA1111BBBB2222 - Alice Example <alice@example.org>
    │   AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
    └── 0xDDDDEEEEFFFF0000 - Bob Builder <bob@example.org>
        DDDDEEEEFFFF0000111122223333444455556666
`

func TestParseGopassRecipients(t *testing.T) {
	fprs := parseGopassRecipients([]byte(gopassRecipientsFixture))
	if len(fprs) != 2 {
		t.Fatalf("want 2 fingerprints, got %d: %v", len(fprs), fprs)
	}
	want := []string{
		"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
		"DDDDEEEEFFFF0000111122223333444455556666",
	}
	for i, w := range want {
		if fprs[i] != w {
			t.Errorf("fpr[%d] = %q, want %q", i, fprs[i], w)
		}
	}
}

func TestParseGopassRecipients_Dedup(t *testing.T) {
	input := "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555\n" +
		"  AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555\n"
	fprs := parseGopassRecipients([]byte(input))
	if len(fprs) != 1 {
		t.Errorf("want 1 unique fpr, got %d: %v", len(fprs), fprs)
	}
}

func TestIsFingerprint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", true},
		{"aaaa1111bbbb2222cccc3333dddd4444eeee5555", true},
		{"AAAA1111BBBB2222CCCC3333DDDD4444EEEE555", false}, // too short
		{"AAAA1111BBBB2222CCCC3333DDDD4444EEEE55556", false},
		{"GGGG1111BBBB2222CCCC3333DDDD4444EEEE5555", false}, // non-hex
		{"", false},
	}
	for _, tc := range cases {
		if got := isFingerprint(tc.in); got != tc.want {
			t.Errorf("isFingerprint(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestUnescapeColon(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Alice \\x3calice@example.org\\x3e", "Alice <alice@example.org>"},
		{"plain", "plain"},
		{"trailing\\x3e", "trailing>"},
		{"bad-escape\\x", "bad-escape\\x"}, // gracefully pass through
	}
	for _, tc := range cases {
		if got := unescapeColon(tc.in); got != tc.want {
			t.Errorf("unescapeColon(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseEpoch(t *testing.T) {
	ts := parseEpoch("1760441808")
	if ts.Unix() != 1760441808 {
		t.Errorf("parseEpoch failed: %v", ts)
	}
	if !parseEpoch("").IsZero() {
		t.Error("empty should be zero")
	}
	if !parseEpoch("notanumber").IsZero() {
		t.Error("garbage should be zero")
	}
	if !parseEpoch("0").IsZero() {
		t.Error("zero epoch should be treated as zero time")
	}
}

// --- runner plumbing --------------------------------------------------------

// stubRunner returns hardcoded output/err per command. Used for unit tests
// that exercise Import / Add / Remove / List without invoking gpg or gopass.
type stubRunner struct {
	calls    []string
	handlers map[string]stubResp
}

type stubResp struct {
	out []byte
	err error
}

func (s *stubRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, key)
	if r, ok := s.handlers[key]; ok {
		return r.out, r.err
	}
	// Match by prefix so we do not have to enumerate arg sequences.
	for pfx, r := range s.handlers {
		if strings.HasPrefix(key, pfx) {
			return r.out, r.err
		}
	}
	return nil, fmt.Errorf("unexpected call: %s", key)
}

func TestImport_MissingFile(t *testing.T) {
	_, _, err := Import(context.Background(), "/nope/does/not/exist.asc")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestImport_EmptyPath(t *testing.T) {
	_, _, err := Import(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestImport_StubbedRunner(t *testing.T) {
	keyfile := filepath.Join(t.TempDir(), "key.asc")
	if err := os.WriteFile(keyfile, []byte("-- dummy --"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &stubRunner{handlers: map[string]stubResp{
		"gpg --batch --import ":         {out: nil, err: nil},
		"gpg --with-colons --show-keys": {out: []byte(showKeysFixture), err: nil},
	}}
	restore := WithRunner(stub)
	defer restore()

	fpr, uid, err := Import(context.Background(), keyfile)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if fpr != "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555" {
		t.Errorf("fpr = %q", fpr)
	}
	if !strings.Contains(uid, "Alice") {
		t.Errorf("uid = %q", uid)
	}
}

func TestImport_NoFingerprintInOutput(t *testing.T) {
	keyfile := filepath.Join(t.TempDir(), "key.asc")
	if err := os.WriteFile(keyfile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &stubRunner{handlers: map[string]stubResp{
		"gpg --batch --import ":         {out: nil, err: nil},
		"gpg --with-colons --show-keys": {out: []byte(""), err: nil},
	}}
	restore := WithRunner(stub)
	defer restore()
	if _, _, err := Import(context.Background(), keyfile); err == nil {
		t.Fatal("expected error when no fpr in output")
	}
}

func TestAddRemove_Empty(t *testing.T) {
	if err := Add(context.Background(), ""); err == nil {
		t.Error("Add('') should fail")
	}
	if err := Remove(context.Background(), ""); err == nil {
		t.Error("Remove('') should fail")
	}
}

func TestAdd_Stubbed(t *testing.T) {
	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass recipients add ": {out: nil, err: nil},
	}}
	restore := WithRunner(stub)
	defer restore()
	if err := Add(context.Background(), "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(stub.calls) != 1 {
		t.Errorf("want 1 call, got %d", len(stub.calls))
	}
}

func TestRemove_Stubbed(t *testing.T) {
	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass recipients remove ": {out: nil, err: errors.New("boom")},
	}}
	restore := WithRunner(stub)
	defer restore()
	if err := Remove(context.Background(), "AAAA"); err == nil {
		t.Fatal("expected error from stub")
	}
}

func TestList_Stubbed(t *testing.T) {
	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass recipients": {out: []byte(gopassRecipientsFixture), err: nil},
		"gpg --with-colons --fixed-list-mode --list-keys AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555": {
			out: []byte(showKeysFixture),
		},
		"gpg --with-colons --fixed-list-mode --list-keys DDDDEEEEFFFF0000111122223333444455556666": {
			out: nil, err: errors.New("unknown key"),
		},
	}}
	restore := WithRunner(stub)
	defer restore()

	recs, err := List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 recipients, got %d", len(recs))
	}
	if len(recs[0].UIDs) == 0 || !strings.Contains(recs[0].UIDs[0], "Alice") {
		t.Errorf("first recipient uids: %+v", recs[0].UIDs)
	}
	// Second recipient's gpg lookup failed → UIDs empty, but Fingerprint still
	// present so the list is still useful.
	if recs[1].Fingerprint != "DDDDEEEEFFFF0000111122223333444455556666" {
		t.Errorf("second fpr: %q", recs[1].Fingerprint)
	}
}

// --- integration test -------------------------------------------------------

// TestIntegration_ImportAndAdd exercises Import + Add + List + Remove against
// a real temporary GNUPGHOME and gopass store. Skipped if gpg/gopass are not
// on PATH, so unit CI stays fast and the Mac dev loop catches regressions.
func TestIntegration_ImportAndAdd(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not available")
	}
	if _, err := exec.LookPath("gopass"); err != nil {
		t.Skip("gopass not available")
	}
	root := t.TempDir()
	gnupghome := filepath.Join(root, "gnupg")
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(gnupghome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupghome)
	t.Setenv("PASSWORD_STORE_DIR", store)

	// 1. Generate a passphrase-less test key in batch mode.
	batchFile := filepath.Join(root, "keygen")
	batch := `%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Primary Test
Name-Email: primary@mys.local
Expire-Date: 1y
%commit
`
	if err := os.WriteFile(batchFile, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("gpg", "--batch", "--quiet", "--generate-key", batchFile).Run(); err != nil {
		t.Skipf("gpg generate-key failed (no entropy?): %v", err)
	}
	// Grab primary fingerprint to initialise gopass with.
	out, err := exec.Command("gpg", "--list-secret-keys", "--with-colons").Output()
	if err != nil {
		t.Fatalf("list-secret-keys: %v", err)
	}
	var primaryFpr string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fs := strings.Split(line, ":")
			if len(fs) > 9 && fs[9] != "" {
				primaryFpr = fs[9]
				break
			}
		}
	}
	if primaryFpr == "" {
		t.Fatal("could not extract primary fpr")
	}

	// 2. Initialise gopass non-interactively at our temp PASSWORD_STORE_DIR.
	initCmd := exec.Command("gopass", "init", "--path", store, "--crypto", "gpg", primaryFpr)
	if outb, err := initCmd.CombinedOutput(); err != nil {
		t.Skipf("gopass init failed: %v\n%s", err, outb)
	}

	// 3. Generate a SECOND key, export it, and run Import+Add.
	batch2File := filepath.Join(root, "keygen2")
	batch2 := `%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Second Device
Name-Email: second@mys.local
Expire-Date: 1y
%commit
`
	if err := os.WriteFile(batch2File, []byte(batch2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("gpg", "--batch", "--quiet", "--generate-key", batch2File).Run(); err != nil {
		t.Skipf("gpg generate-key (2) failed: %v", err)
	}
	// Export the second key.
	exportPath := filepath.Join(root, "second.asc")
	outb, err := exec.Command("gpg", "--armor", "--export", "second@mys.local").Output()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := os.WriteFile(exportPath, outb, 0o600); err != nil {
		t.Fatal(err)
	}
	// Delete the secret & public copy, then re-import via our package to
	// exercise the Import call end-to-end.
	_ = exec.Command("gpg", "--batch", "--yes", "--delete-secret-and-public-key", "second@mys.local").Run()

	fpr, uid, err := Import(context.Background(), exportPath)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if fpr == "" {
		t.Fatal("empty fpr after Import")
	}
	if !strings.Contains(uid, "second@mys.local") {
		t.Errorf("uid missing email: %q", uid)
	}

	if err := Add(context.Background(), fpr); err != nil {
		t.Fatalf("Add: %v", err)
	}
	recs, err := List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Fingerprint == fpr {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("fpr %s not found in recipients: %+v", fpr, recs)
	}
	if err := Remove(context.Background(), fpr); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}
