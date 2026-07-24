package teamkeys

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	fingerprintA = "0123456789abcdef0123456789abcdef01234567"
	fingerprintB = "89abcdef0123456789abcdef0123456789abcdef"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", Filename)
	input := &File{
		Members: []Member{
			{
				Name:        " Alice Example ",
				Fingerprint: fingerprintA,
				Email:       " Alice@Example.COM ",
				PublicKey:   "keys/alice.asc",
			},
			{
				Name:        "Alice Example",
				Fingerprint: fingerprintB,
				Email:       "other@example.com",
			},
		},
	}

	if err := Save(path, input); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := &File{
		Version: 1,
		Members: []Member{
			{
				Name:        "Alice Example",
				Fingerprint: strings.ToUpper(fingerprintA),
				Email:       "alice@example.com",
				PublicKey:   "keys/alice.asc",
			},
			{
				Name:        "Alice Example",
				Fingerprint: strings.ToUpper(fingerprintB),
				Email:       "other@example.com",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, want)
	}

	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if runtime.GOOS != "windows" && parentInfo.Mode().Perm() != 0o700 {
		t.Errorf("parent mode = %#o, want 0700", parentInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if runtime.GOOS != "windows" && fileInfo.Mode().Perm() != 0o644 {
		t.Errorf("file mode = %#o, want 0644", fileInfo.Mode().Perm())
	}
}

func TestLoadRejectsMalformedManifest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid YAML", body: "version: [\n"},
		{name: "unknown top-level field", body: "version: 1\nmembers: []\nextra: true\n"},
		{
			name: "unknown member field",
			body: validManifestYAML("    nickname: ally\n"),
		},
		{name: "second document", body: "version: 1\nmembers: []\n---\nversion: 1\nmembers: []\n"},
		{name: "empty second document", body: "version: 1\nmembers: []\n---\n"},
		{name: "unsupported version", body: "version: 2\nmembers: []\n"},
		{name: "zero version", body: "version: 0\nmembers: []\n"},
		{name: "scalar root", body: "not-a-manifest\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), Filename)
			if err := os.WriteFile(path, []byte(tt.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load unexpectedly succeeded")
			}
		})
	}
}

func TestLoadDefaultsVersionToOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	body := strings.TrimPrefix(validManifestYAML(""), "version: 1\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
}

func TestValidateRejectsMissingRequiredMemberFields(t *testing.T) {
	tests := []struct {
		name   string
		member Member
	}{
		{
			name: "name",
			member: Member{
				Email:       "alice@example.com",
				Fingerprint: fingerprintA,
			},
		},
		{
			name: "email",
			member: Member{
				Name:        "Alice",
				Fingerprint: fingerprintA,
			},
		},
		{
			name: "fingerprint",
			member: Member{
				Name:  "Alice",
				Email: "alice@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{Version: 1, Members: []Member{tt.member}}
			if err := file.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}

func TestValidateRejectsInvalidFingerprintAndEmail(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		email       string
	}{
		{name: "short fingerprint", fingerprint: strings.Repeat("A", 39), email: "alice@example.com"},
		{name: "long fingerprint", fingerprint: strings.Repeat("A", 41), email: "alice@example.com"},
		{name: "non-hex fingerprint", fingerprint: strings.Repeat("G", 40), email: "alice@example.com"},
		{name: "display-name email", fingerprint: fingerprintA, email: "Alice <alice@example.com>"},
		{name: "malformed email", fingerprint: fingerprintA, email: "alice.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Version: 1,
				Members: []Member{{
					Name:        "Alice",
					Email:       tt.email,
					Fingerprint: tt.fingerprint,
				}},
			}
			if err := file.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}

func TestValidateRejectsCaseInsensitiveDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		members []Member
	}{
		{
			name: "fingerprint",
			members: []Member{
				validMember("Alice", "alice@example.com", fingerprintA),
				validMember("Bob", "bob@example.com", strings.ToUpper(fingerprintA)),
			},
		},
		{
			name: "email",
			members: []Member{
				validMember("Alice", "alice@example.com", fingerprintA),
				validMember("Bob", "ALICE@EXAMPLE.COM", fingerprintB),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{Version: 1, Members: tt.members}
			if err := file.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}

func TestValidateCanonicalizesAndSupportsDuplicateNames(t *testing.T) {
	file := &File{
		Members: []Member{
			validMember(" Alice ", " Alice@Example.COM ", fingerprintA),
			validMember("Alice", "other@example.com", fingerprintB),
		},
	}

	if err := file.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if file.Version != 1 {
		t.Errorf("Version = %d, want 1", file.Version)
	}
	if file.Members[0].Name != "Alice" {
		t.Errorf("Name = %q, want Alice", file.Members[0].Name)
	}
	if file.Members[0].Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", file.Members[0].Email)
	}
	if file.Members[0].Fingerprint != strings.ToUpper(fingerprintA) {
		t.Errorf("Fingerprint = %q, want uppercase", file.Members[0].Fingerprint)
	}

	wantFingerprints := []string{
		strings.ToUpper(fingerprintA),
		strings.ToUpper(fingerprintB),
	}
	if got := file.Fingerprints(); !reflect.DeepEqual(got, wantFingerprints) {
		t.Errorf("Fingerprints() = %#v, want %#v", got, wantFingerprints)
	}
	member, ok := file.FindFingerprint(" " + fingerprintB + " ")
	if !ok || member.Email != "other@example.com" {
		t.Fatalf("FindFingerprint() = %#v, %v", member, ok)
	}
	if _, ok := file.FindFingerprint("not-a-fingerprint"); ok {
		t.Fatal("FindFingerprint accepted an invalid fingerprint")
	}
}

func TestValidatePublicKeyPaths(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "omitted", path: ""},
		{name: "simple", path: "alice.asc"},
		{name: "nested", path: "keys/team/alice.asc"},
		{name: "absolute", path: "/tmp/alice.asc", wantErr: true},
		{name: "windows absolute", path: "C:/keys/alice.asc", wantErr: true},
		{name: "traversal", path: "../alice.asc", wantErr: true},
		{name: "nested traversal", path: "keys/../alice.asc", wantErr: true},
		{name: "backslash", path: `keys\alice.asc`, wantErr: true},
		{name: "newline", path: "keys/alice.asc\nother", wantErr: true},
		{name: "carriage return", path: "keys/alice.asc\rother", wantErr: true},
		{name: "nul", path: "keys/alice\x00.asc", wantErr: true},
		{name: "dot segment", path: "./keys/alice.asc", wantErr: true},
		{name: "empty segment", path: "keys//alice.asc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			member := validMember("Alice", "alice@example.com", fingerprintA)
			member.PublicKey = tt.path
			file := &File{Version: 1, Members: []Member{member}}
			err := file.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolvePublicKey(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		want    []byte
		wantErr bool
	}{
		{
			name: "regular file",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, "keys"), 0o700); err != nil {
					t.Fatal(err)
				}
				content := []byte("public-key-data")
				if err := os.WriteFile(filepath.Join(dir, "keys", "alice.asc"), content, 0o644); err != nil {
					t.Fatal(err)
				}
				return "keys/alice.asc"
			},
			want: []byte("public-key-data"),
		},
		{
			name: "final symlink",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				target := filepath.Join(dir, "target.asc")
				if err := os.WriteFile(target, []byte("public-key-data"), 0o644); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "alice.asc")
				if err := os.Symlink(target, link); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
					t.Fatal(err)
				}
				return "alice.asc"
			},
			wantErr: true,
		},
		{
			name: "intermediate symlink",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				targetDir := filepath.Join(dir, "real-keys")
				if err := os.Mkdir(targetDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(targetDir, "alice.asc"), []byte("public-key-data"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(targetDir, filepath.Join(dir, "keys")); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
					t.Fatal(err)
				}
				return "keys/alice.asc"
			},
			wantErr: true,
		},
		{
			name: "directory",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, "alice.asc"), 0o700); err != nil {
					t.Fatal(err)
				}
				return "alice.asc"
			},
			wantErr: true,
		},
		{
			name: "oversize",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				content := bytes.Repeat([]byte("x"), maxPublicKeySize+1)
				if err := os.WriteFile(filepath.Join(dir, "alice.asc"), content, 0o644); err != nil {
					t.Fatal(err)
				}
				return "alice.asc"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			publicKey := tt.setup(t, dir)
			member := validMember("Alice", "alice@example.com", fingerprintA)
			member.PublicKey = publicKey

			got, err := ResolvePublicKey(filepath.Join(dir, Filename), member)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolvePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ResolvePublicKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvePublicKeyOmitted(t *testing.T) {
	got, err := ResolvePublicKey(filepath.Join(t.TempDir(), Filename), Member{})
	if err != nil {
		t.Fatalf("ResolvePublicKey: %v", err)
	}
	if got != nil {
		t.Errorf("ResolvePublicKey = %q, want nil", got)
	}
}

func TestLoadRejectsOversizeManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), maxManifestSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load unexpectedly accepted an oversize manifest")
	}
}

func TestLoadRejectsSymlinkManifest(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.yaml")
	if err := Save(target, &File{Members: []Member{
		validMember("Alice", "alice@example.com", fingerprintA),
	}}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, Filename)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Load(link); err == nil ||
		!strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("Load symlink error = %v, want symbolic-link refusal", err)
	}
}

func TestSaveValidationFailureLeavesExistingManifestUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	original := []byte("sentinel\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	invalid := &File{Version: 1, Members: []Member{{Name: "Alice"}}}

	if err := Save(path, invalid); err == nil {
		t.Fatal("Save unexpectedly succeeded")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing file changed to %q, want %q", got, original)
	}
}

func TestConcurrentSaveLeavesCompleteManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	files := []*File{
		{Members: []Member{validMember("Alice", "alice@example.com", fingerprintA)}},
		{Members: []Member{validMember("Bob", "bob@example.com", fingerprintB)}},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(files))
	for _, file := range files {
		wg.Add(1)
		go func(file *File) {
			defer wg.Done()
			errs <- Save(path, file)
		}(file)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load after concurrent saves: %v", err)
	}
	if len(got.Members) != 1 {
		t.Fatalf("members = %d, want 1", len(got.Members))
	}
	if got.Members[0].Name != "Alice" && got.Members[0].Name != "Bob" {
		t.Errorf("unexpected member: %#v", got.Members[0])
	}
}

func validMember(name, email, fingerprint string) Member {
	return Member{
		Name:        name,
		Email:       email,
		Fingerprint: fingerprint,
	}
}

func validManifestYAML(extraMemberField string) string {
	return "version: 1\n" +
		"members:\n" +
		"  - name: Alice\n" +
		"    fingerprint: " + fingerprintA + "\n" +
		"    email: alice@example.com\n" +
		extraMemberField
}
