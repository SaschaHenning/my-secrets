// Package bw maps my-secrets store entries to Bitwarden's unencrypted
// JSON export format — the shape `bw import bitwardenjson` and the web
// vault's „Bitwarden (json)" importer accept. The same types feed the
// bw-push / bw-import mirror commands, so the mapping lives in one place.
package bw

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/totp"
)

// TypeLogin is the Bitwarden item-type discriminator for login items.
// Every store entry is exported as a login: the secret always lives in
// the password (or TOTP) slot, which keeps the import path simple.
const TypeLogin = 1

// FieldText is the Bitwarden custom-field type for plain-text fields.
const FieldText = 0

// FieldPath is the custom-field name carrying the full store path on
// every exported item. It is the stable match key the push/import
// mirror commands use to pair Bitwarden items with store entries.
const FieldPath = "mys-path"

// FolderPrefix is the dedicated Bitwarden folder namespace for mirrored
// entries. Bitwarden renders "/" in folder names as nesting, so every
// org shows up as a child of one "mys" folder and never mixes with the
// rest of the personal vault.
const FolderPrefix = "mys"

// folderNamespace seeds the deterministic UUIDv5 folder ids. Stable ids
// keep golden files reproducible and let repeated imports reference
// identical folders.
var folderNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/SaschaHenning/my-secrets/bw-folder"))

// Export is the top-level unencrypted Bitwarden JSON payload.
type Export struct {
	Encrypted bool     `json:"encrypted"`
	Folders   []Folder `json:"folders"`
	Items     []Item   `json:"items"`
}

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Item struct {
	ID       string  `json:"id,omitempty"`
	Type     int     `json:"type"`
	Name     string  `json:"name"`
	Notes    string  `json:"notes,omitempty"`
	FolderID string  `json:"folderId"`
	Favorite bool    `json:"favorite"`
	Fields   []Field `json:"fields,omitempty"`
	Login    *Login  `json:"login,omitempty"`
}

type Login struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TOTP     string `json:"totp,omitempty"`
	URIs     []URI  `json:"uris,omitempty"`
}

type URI struct {
	URI string `json:"uri"`
}

type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

// FolderName returns the Bitwarden folder for an org, e.g. "mys/jasp".
// Entries without an org land directly in the "mys" root folder.
func FolderName(org string) string {
	if org == "" {
		return FolderPrefix
	}
	return FolderPrefix + "/" + org
}

// FolderID returns the deterministic UUIDv5 for a folder name.
func FolderID(name string) string {
	return uuid.NewSHA1(folderNamespace, []byte(name)).String()
}

// orgOf returns the entry's org, deriving it from the path's first
// segment when the Org field was not populated by the reader.
func orgOf(e *store.Entry) string {
	if e.Org != "" {
		return e.Org
	}
	if i := strings.IndexByte(e.Path, '/'); i > 0 {
		return e.Path[:i]
	}
	return ""
}

// ItemName returns the item's display name: the path with the org
// prefix stripped, since the org is already encoded in the folder.
func ItemName(e *store.Entry) string {
	if org := orgOf(e); org != "" {
		return strings.TrimPrefix(e.Path, org+"/")
	}
	return e.Path
}

// ItemFromEntry maps one store entry to a Bitwarden login item. TOTP
// entries put their seed into login.totp as an otpauth URI instead of
// the password slot, so authenticator codes work after import.
func ItemFromEntry(e *store.Entry) (Item, error) {
	login := &Login{Username: e.Username}
	if e.URL != "" {
		login.URIs = []URI{{URI: e.URL}}
	}
	if e.Kind == store.KindTOTP {
		uri, err := totpURI(e)
		if err != nil {
			return Item{}, fmt.Errorf("%s: %w", e.Path, err)
		}
		login.TOTP = uri
	} else {
		login.Password = e.Password
	}
	return Item{
		Type:     TypeLogin,
		Name:     ItemName(e),
		Notes:    e.Notes,
		FolderID: FolderID(FolderName(orgOf(e))),
		Fields:   metadataFields(e),
		Login:    login,
	}, nil
}

// metadataFields serialises the store metadata that Bitwarden has no
// native slot for. FieldPath comes first — it is the mirror match key.
func metadataFields(e *store.Entry) []Field {
	fs := []Field{
		{Name: FieldPath, Value: e.Path, Type: FieldText},
		{Name: "org", Value: orgOf(e), Type: FieldText},
		{Name: "kind", Value: e.Kind, Type: FieldText},
	}
	if e.RotateAfter != "" {
		fs = append(fs, Field{Name: "rotate_after", Value: e.RotateAfter, Type: FieldText})
	}
	if len(e.Tags) > 0 {
		fs = append(fs, Field{Name: "tags", Value: strings.Join(e.Tags, ","), Type: FieldText})
	}
	if e.Domain != "" {
		fs = append(fs, Field{Name: "domain", Value: e.Domain, Type: FieldText})
	}
	if e.GitHubProject != "" {
		fs = append(fs, Field{Name: "github_project", Value: e.GitHubProject, Type: FieldText})
	}
	return fs
}

// totpURI builds the otpauth URI for a Kind==totp entry. Zero-valued
// digits/period fall back to the authenticator defaults (6 / 30s), the
// same tolerance App.GenerateTOTP applies.
func totpURI(e *store.Entry) (string, error) {
	alg, err := totp.ParseAlgorithm(e.TOTPAlgorithm)
	if err != nil {
		return "", err
	}
	digitsStr := ""
	if e.TOTPDigits != 0 {
		digitsStr = strconv.Itoa(e.TOTPDigits)
	}
	digits, err := totp.ParseDigits(digitsStr)
	if err != nil {
		return "", err
	}
	label := e.TOTPLabel
	if label == "" {
		label = ItemName(e)
	}
	return totp.BuildURI(totp.Entry{
		Seed:      e.Password,
		Issuer:    e.TOTPIssuer,
		Label:     label,
		Algorithm: alg,
		Digits:    digits,
		Period:    uint(e.TOTPPeriod),
	}), nil
}

// BuildExport assembles the full unencrypted export payload. Folders
// are derived from the entries' orgs and emitted sorted by name; items
// keep the caller's (path-sorted) order.
func BuildExport(entries []*store.Entry) (Export, error) {
	exp := Export{
		Encrypted: false,
		Folders:   []Folder{},
		Items:     make([]Item, 0, len(entries)),
	}
	seen := map[string]bool{}
	for _, e := range entries {
		it, err := ItemFromEntry(e)
		if err != nil {
			return Export{}, err
		}
		name := FolderName(orgOf(e))
		if !seen[name] {
			seen[name] = true
			exp.Folders = append(exp.Folders, Folder{ID: FolderID(name), Name: name})
		}
		exp.Items = append(exp.Items, it)
	}
	sort.Slice(exp.Folders, func(i, j int) bool { return exp.Folders[i].Name < exp.Folders[j].Name })
	return exp, nil
}
