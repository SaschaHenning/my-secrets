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

	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
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

// Realistic gopass output: the "0x..." header contains the short key id
// (the LAST 16 chars of the fingerprint), with the full 40-char
// fingerprint listed on the line below. The parser must deduplicate
// these pairs so we return one Recipient per key, not two.
const gopassRecipientsFixture = `gopass
└── gpg
    ├── 0xDDDD4444EEEE5555 - Alice Example <alice@example.org>
    │   AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
    └── 0x3333444455556666 - Bob Builder <bob@example.org>
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

func TestParseGPGIDRecipients(t *testing.T) {
	const fullFingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "accepts supported forms",
			in:   strings.ToLower(fullFingerprint) + "\n0x3333444455556666\n",
			want: []string{fullFingerprint, "3333444455556666"},
		},
		{
			name: "ignores comments and invalid tokens",
			in:   "# " + fullFingerprint + "\nnot-a-key\n" + fullFingerprint + " # Alice\n",
			want: []string{fullFingerprint},
		},
		{
			name: "drops short shadow of full fingerprint",
			in:   "DDDD4444EEEE5555\n" + fullFingerprint + "\n",
			want: []string{fullFingerprint},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseGPGIDRecipients([]byte(tc.in))
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("parseGPGIDRecipients() = %v, want %v", got, tc.want)
			}
		})
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

func TestRecipientMutationArgv(t *testing.T) {
	const fingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	tests := []struct {
		name string
		run  func(context.Context) error
		want string
	}{
		{
			name: "legacy add",
			run:  func(ctx context.Context) error { return Add(ctx, fingerprint) },
			want: "gopass recipients add " + fingerprint,
		},
		{
			name: "add empty mount",
			run: func(ctx context.Context) error {
				return AddToMount(ctx, "", fingerprint)
			},
			want: "gopass recipients add " + fingerprint,
		},
		{
			name: "add root mount",
			run: func(ctx context.Context) error {
				return AddToMount(ctx, syncpkg.DefaultStoreMount, fingerprint)
			},
			want: "gopass recipients add " + fingerprint,
		},
		{
			name: "add named mount",
			run: func(ctx context.Context) error {
				return AddToMount(ctx, "jasp", fingerprint)
			},
			want: "gopass recipients add --store jasp " + fingerprint,
		},
		{
			name: "legacy remove",
			run:  func(ctx context.Context) error { return Remove(ctx, fingerprint) },
			want: "gopass recipients remove " + fingerprint,
		},
		{
			name: "remove empty mount",
			run: func(ctx context.Context) error {
				return RemoveFromMount(ctx, "", fingerprint)
			},
			want: "gopass recipients remove " + fingerprint,
		},
		{
			name: "remove root mount",
			run: func(ctx context.Context) error {
				return RemoveFromMount(ctx, syncpkg.DefaultStoreMount, fingerprint)
			},
			want: "gopass recipients remove " + fingerprint,
		},
		{
			name: "remove named mount",
			run: func(ctx context.Context) error {
				return RemoveFromMount(ctx, "jasp", fingerprint)
			},
			want: "gopass recipients remove --store jasp " + fingerprint,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: map[string]stubResp{
				tc.want: {},
			}}
			restore := WithRunner(stub)
			defer restore()

			if err := tc.run(context.Background()); err != nil {
				t.Fatalf("mutation: %v", err)
			}
			if len(stub.calls) != 1 || stub.calls[0] != tc.want {
				t.Fatalf("calls = %v, want [%q]", stub.calls, tc.want)
			}
		})
	}
}

func TestRecipientMutationErrors(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context) error
		want string
	}{
		{
			name: "add empty fingerprint",
			run: func(ctx context.Context) error {
				return AddToMount(ctx, "jasp", "")
			},
			want: "empty fingerprint",
		},
		{
			name: "remove empty fingerprint",
			run: func(ctx context.Context) error {
				return RemoveFromMount(ctx, "jasp", "")
			},
			want: "empty fingerprint",
		},
		{
			name: "add runner failure",
			run: func(ctx context.Context) error {
				return AddToMount(ctx, "jasp", "AAAA")
			},
			want: "gopass recipients add",
		},
		{
			name: "remove runner failure",
			run: func(ctx context.Context) error {
				return RemoveFromMount(ctx, "jasp", "AAAA")
			},
			want: "gopass recipients remove",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: map[string]stubResp{}}
			restore := WithRunner(stub)
			defer restore()

			err := tc.run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
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

func TestListFromMount_DefaultArgvUnchanged(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context) ([]Recipient, error)
	}{
		{
			name: "legacy list",
			run:  List,
		},
		{
			name: "empty mount",
			run: func(ctx context.Context) ([]Recipient, error) {
				return ListFromMount(ctx, "")
			},
		},
		{
			name: "root mount",
			run: func(ctx context.Context) ([]Recipient, error) {
				return ListFromMount(ctx, syncpkg.DefaultStoreMount)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: map[string]stubResp{
				"gopass recipients": {},
			}}
			restore := WithRunner(stub)
			defer restore()

			recipients, err := tc.run(context.Background())
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(recipients) != 0 {
				t.Fatalf("recipients = %+v, want none", recipients)
			}
			if len(stub.calls) != 1 || stub.calls[0] != "gopass recipients" {
				t.Fatalf("calls = %v, want [gopass recipients]", stub.calls)
			}
		})
	}
}

func TestListFromMount_ReadsLiveGPGID(t *testing.T) {
	const (
		fullFingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
		shortID         = "3333444455556666"
	)
	mountPath := t.TempDir()
	gpgID := strings.Join([]string{
		"# team recipients",
		strings.ToLower(fullFingerprint),
		"0x" + shortID,
		fullFingerprint + " # duplicate",
		"not-a-key",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(mountPath, ".gpg-id"), []byte(gpgID), 0o600); err != nil {
		t.Fatal(err)
	}
	secondKeyFixture := `pub:-:3072:1:3333444455556666:1705320000::::::scESC:::::::
fpr:::::::::DDDDEEEEFFFF0000111122223333444455556666:
uid:-::::1705320000::33333333333333333333333333333333::Bob Builder \x3cbob@example.org\x3e::::::::::0:
`
	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp.path": {
			out: []byte(mountPath + "\n"),
		},
		"gpg --with-colons --fixed-list-mode --list-keys " + fullFingerprint: {
			out: []byte(showKeysFixture),
		},
		"gpg --with-colons --fixed-list-mode --list-keys " + shortID: {
			out: []byte(secondKeyFixture),
		},
	}}
	restore := WithRunner(stub)
	defer restore()

	recipients, err := ListFromMount(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("ListFromMount: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("recipients = %+v, want two unique IDs", recipients)
	}
	if recipients[0].Fingerprint != fullFingerprint ||
		len(recipients[0].UIDs) == 0 ||
		!strings.Contains(recipients[0].UIDs[0], "Alice") {
		t.Errorf("first recipient = %+v", recipients[0])
	}
	if recipients[1].Fingerprint != shortID ||
		len(recipients[1].UIDs) == 0 ||
		!strings.Contains(recipients[1].UIDs[0], "Bob") {
		t.Errorf("second recipient = %+v", recipients[1])
	}
	wantCalls := []string{
		"gopass config mounts.jasp.path",
		"gpg --with-colons --fixed-list-mode --list-keys " + fullFingerprint,
		"gpg --with-colons --fixed-list-mode --list-keys " + shortID,
	}
	if strings.Join(stub.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %v, want %v", stub.calls, wantCalls)
	}
	for _, call := range stub.calls {
		if strings.Contains(call, "gopass recipients") {
			t.Fatalf("non-default list must not invoke gopass recipients: %v", stub.calls)
		}
	}
}

func TestListFromMountErrors(t *testing.T) {
	tests := []struct {
		name       string
		mountPath  func(*testing.T) string
		pathResult stubResp
		want       string
	}{
		{
			name: "mount lookup failure",
			pathResult: stubResp{
				err: errors.New("lookup failed"),
			},
			want: "resolve gopass mount",
		},
		{
			name: "missing gpg id",
			mountPath: func(t *testing.T) string {
				return t.TempDir()
			},
			want: "read recipients",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.pathResult
			if tc.mountPath != nil {
				result.out = []byte(tc.mountPath(t) + "\n")
			}
			stub := &stubRunner{handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": result,
			}}
			restore := WithRunner(stub)
			defer restore()

			_, err := ListFromMount(context.Background(), "jasp")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateSharedMount(t *testing.T) {
	validMountPath := t.TempDir()
	writeTeamManifest(t, validMountPath, []teamkeys.Member{validTeamMember()})
	missingManifestPath := t.TempDir()
	invalidManifestPath := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(invalidManifestPath, teamkeys.Filename),
		[]byte("version: 1\nmembers: ["),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		mount      string
		cfg        *syncpkg.Config
		pathResult stubResp
		want       string
		wantCalls  int
	}{
		{
			name:      "nil config",
			mount:     "jasp",
			want:      "not configured as shared",
			wantCalls: 0,
		},
		{
			name:      "root refused",
			mount:     syncpkg.DefaultStoreMount,
			cfg:       sharedConfig("jasp"),
			want:      "non-root",
			wantCalls: 0,
		},
		{
			name:      "empty refused",
			cfg:       sharedConfig("jasp"),
			want:      "non-root",
			wantCalls: 0,
		},
		{
			name:      "personal refused",
			mount:     "jasp",
			cfg:       &syncpkg.Config{Remotes: []syncpkg.StoreRemote{{Mount: "jasp"}}},
			want:      "not configured as shared",
			wantCalls: 0,
		},
		{
			name:  "live path failure",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			pathResult: stubResp{
				err: errors.New("lookup failed"),
			},
			want:      "resolve shared mount",
			wantCalls: 1,
		},
		{
			name:  "missing manifest",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			pathResult: stubResp{
				out: []byte(missingManifestPath + "\n"),
			},
			want:      teamkeys.Filename,
			wantCalls: 1,
		},
		{
			name:  "invalid manifest",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			pathResult: stubResp{
				out: []byte(invalidManifestPath + "\n"),
			},
			want:      teamkeys.Filename,
			wantCalls: 1,
		},
		{
			name:  "valid shared mount",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			pathResult: stubResp{
				out: []byte(validMountPath + "\n"),
			},
			wantCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": tc.pathResult,
			}}
			restore := WithRunner(stub)
			defer restore()

			err := ValidateSharedMount(context.Background(), tc.mount, tc.cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateSharedMount: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			if len(stub.calls) != tc.wantCalls {
				t.Fatalf("calls = %v, want %d", stub.calls, tc.wantCalls)
			}
		})
	}
}

func TestInspectForeign(t *testing.T) {
	const unlistedFingerprint = "111122223333444455556666777788889999AAAA"
	mountPath := t.TempDir()
	member := validTeamMember()
	writeTeamManifest(t, mountPath, []teamkeys.Member{member})

	tests := []struct {
		name        string
		fingerprint string
		want        ForeignInfo
		wantErr     string
	}{
		{
			name:        "listed canonicalizes fingerprint",
			fingerprint: strings.ToLower(member.Fingerprint),
			want: ForeignInfo{
				Fingerprint: member.Fingerprint,
				Name:        member.Name,
				Email:       member.Email,
				Listed:      true,
			},
		},
		{
			name:        "unlisted is not an error",
			fingerprint: unlistedFingerprint,
			want: ForeignInfo{
				Fingerprint: unlistedFingerprint,
			},
		},
		{
			name:        "invalid fingerprint",
			fingerprint: "not-a-fingerprint",
			wantErr:     "invalid fingerprint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": {out: []byte(mountPath + "\n")},
			}}
			restore := WithRunner(stub)
			defer restore()

			got, err := InspectForeign(
				context.Background(),
				"jasp",
				tc.fingerprint,
				sharedConfig("jasp"),
			)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("InspectForeign: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ForeignInfo = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAddForeignRevalidatesSharedMount(t *testing.T) {
	member := validTeamMember()
	mountPath := t.TempDir()
	writeTeamManifest(t, mountPath, []teamkeys.Member{member})
	missingManifestPath := t.TempDir()

	tests := []struct {
		name      string
		mount     string
		cfg       *syncpkg.Config
		handlers  map[string]stubResp
		want      string
		wantCalls []string
	}{
		{
			name:  "non-shared refused",
			mount: "jasp",
			cfg:   &syncpkg.Config{Remotes: []syncpkg.StoreRemote{{Mount: "jasp"}}},
			want:  "not configured as shared",
		},
		{
			name:  "root refused",
			mount: syncpkg.DefaultStoreMount,
			cfg:   sharedConfig("jasp"),
			want:  "non-root",
		},
		{
			name:  "missing manifest refused",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": {
					out: []byte(missingManifestPath + "\n"),
				},
			},
			want: teamkeys.Filename,
			wantCalls: []string{
				"gopass config mounts.jasp.path",
			},
		},
		{
			name:  "valid shared mount adds",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": {
					out: []byte(mountPath + "\n"),
				},
				"gopass --yes recipients add --store jasp " + member.Fingerprint: {},
			},
			wantCalls: []string{
				"gopass config mounts.jasp.path",
				"gopass --yes recipients add --store jasp " + member.Fingerprint,
			},
		},
		{
			name:  "add error returned",
			mount: "jasp",
			cfg:   sharedConfig("jasp"),
			handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": {
					out: []byte(mountPath + "\n"),
				},
				"gopass --yes recipients add --store jasp " + member.Fingerprint: {
					err: errors.New("reencryption failed"),
				},
			},
			want: "gopass recipients add",
			wantCalls: []string{
				"gopass config mounts.jasp.path",
				"gopass --yes recipients add --store jasp " + member.Fingerprint,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubRunner{handlers: tc.handlers}
			restore := WithRunner(stub)
			defer restore()

			err := AddForeign(context.Background(), tc.mount, member.Fingerprint, tc.cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("AddForeign: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			if strings.Join(stub.calls, "\n") != strings.Join(tc.wantCalls, "\n") {
				t.Fatalf("calls = %v, want %v", stub.calls, tc.wantCalls)
			}
		})
	}
}

func sharedConfig(mount string) *syncpkg.Config {
	return &syncpkg.Config{
		Remotes: []syncpkg.StoreRemote{{Mount: mount, Shared: true}},
	}
}

func validTeamMember() teamkeys.Member {
	return teamkeys.Member{
		Name:        "Alice Example",
		Email:       "alice@example.org",
		Fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
	}
}

func writeTeamManifest(t *testing.T, dir string, members []teamkeys.Member) {
	t.Helper()
	if err := teamkeys.Save(
		filepath.Join(dir, teamkeys.Filename),
		&teamkeys.File{Version: 1, Members: members},
	); err != nil {
		t.Fatalf("write team manifest: %v", err)
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
