package bw

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/totp"
)

// PathForItem returns the store path a namespace item maps to: the
// mys-path match key when present, otherwise (item created on the
// phone) the path derived from its folder and name — "mys/zuhause" +
// "router" → "zuhause/router"; the "mys" root folder maps to a
// top-level path.
func PathForItem(it Item, folderName string) string {
	if p := PathOf(it); p != "" {
		return p
	}
	org := strings.TrimPrefix(folderName, FolderPrefix+"/")
	if org == folderName { // bare "mys" root — no org prefix
		return it.Name
	}
	return org + "/" + it.Name
}

// EntryFromItem reconstructs a store entry from a mirrored Bitwarden
// item — the inverse of ItemFromEntry, including the metadata custom
// fields and the otpauth TOTP URI. folderName is the item's folder,
// used for path derivation when the mys-path field is missing.
func EntryFromItem(it Item, folderName string) (*store.Entry, error) {
	if it.Type != TypeLogin {
		return nil, fmt.Errorf("item %q is not a login item (type %d)", it.Name, it.Type)
	}
	e := &store.Entry{Path: PathForItem(it, folderName), Notes: it.Notes}
	login := loginOrEmpty(it.Login)
	e.Username = login.Username
	if len(login.URIs) > 0 {
		e.URL = login.URIs[0].URI
	}
	for _, f := range it.Fields {
		switch {
		case f.Name == FieldPath:
			// Match key — already consumed for the path.
		case f.Name == "org":
			e.Org = f.Value
		case f.Name == "kind":
			e.Kind = f.Value
		case f.Name == "rotate_after":
			e.RotateAfter = f.Value
		case f.Name == "tags":
			if f.Value != "" {
				e.Tags = strings.Split(f.Value, ",")
			}
		case f.Name == "domain":
			e.Domain = f.Value
		case f.Name == "github_project":
			e.GitHubProject = f.Value
		case strings.HasPrefix(f.Name, "field."):
			if e.Fields == nil {
				e.Fields = map[string]string{}
			}
			e.Fields[strings.TrimPrefix(f.Name, "field.")] = f.Value
		default:
			// Custom field added by hand in Bitwarden — keep it as a
			// structured extra rather than dropping user data.
			if e.Fields == nil {
				e.Fields = map[string]string{}
			}
			e.Fields[f.Name] = f.Value
		}
	}
	if e.Org == "" {
		e.Org = store.OrgOf(e.Path)
	}
	if login.TOTP != "" {
		t, err := totp.ParseURI(login.TOTP)
		if err != nil {
			// The parse error may embed the raw otpauth uri — seed
			// included — and callers print these errors as warnings.
			// Never propagate the original error text.
			return nil, fmt.Errorf("%s: login.totp is not a valid otpauth uri", e.Path)
		}
		e.Kind = store.KindTOTP
		e.Password = t.Seed
		e.TOTPIssuer = t.Issuer
		e.TOTPLabel = t.Label
		e.TOTPAlgorithm = totp.AlgorithmString(t.Algorithm)
		e.TOTPDigits = totp.DigitsInt(t.Digits)
		e.TOTPPeriod = int(t.Period)
	} else {
		e.Password = login.Password
		if e.Kind == store.KindTOTP {
			// The kind metadata field is stale when the item no longer
			// carries an otpauth uri — the credential is a password now.
			e.Kind = store.KindPassword
		}
	}
	if e.Kind == "" {
		e.Kind = store.KindPassword
	}
	return e, nil
}

// MergeEntry applies exactly the changed field names from incoming onto
// a copy of existing. Anything Bitwarden does not carry (or the user
// did not touch) keeps its store value — the reverse channel never
// overwrites more than what the diff showed.
func MergeEntry(existing, incoming *store.Entry, changed []string) *store.Entry {
	out := *existing
	if existing.Fields != nil {
		out.Fields = make(map[string]string, len(existing.Fields))
		for k, v := range existing.Fields {
			out.Fields[k] = v
		}
	}
	for _, name := range changed {
		switch {
		case name == "username":
			out.Username = incoming.Username
		case name == "password":
			out.Password = incoming.Password
		case name == "url":
			out.URL = incoming.URL
		case name == "notes":
			out.Notes = incoming.Notes
		case name == "totp":
			// A kind switch travels with the totp diff: the phone may
			// have replaced the password with an authenticator seed —
			// or dropped the seed again in favour of a plain password
			// (incoming then carries KindPassword and empty parameters).
			out.Kind = incoming.Kind
			out.Password = incoming.Password
			out.TOTPIssuer = incoming.TOTPIssuer
			out.TOTPLabel = incoming.TOTPLabel
			out.TOTPAlgorithm = incoming.TOTPAlgorithm
			out.TOTPDigits = incoming.TOTPDigits
			out.TOTPPeriod = incoming.TOTPPeriod
		case strings.HasPrefix(name, "field."):
			key := strings.TrimPrefix(name, "field.")
			if v, ok := incoming.Fields[key]; ok {
				if out.Fields == nil {
					out.Fields = map[string]string{}
				}
				out.Fields[key] = v
			} else {
				delete(out.Fields, key)
			}
		}
	}
	return &out
}

// ChangedFields compares the reverse-mapped Bitwarden state against the
// store entry and returns the sorted names of fields that differ —
// names only, never values, so the result is safe to print and audit.
// Deliberately compared are only the credential surfaces a phone edit
// can legitimately change (username/password/url/notes/totp/field.*);
// store metadata mirrored into custom fields (kind, rotate_after, tags,
// domain, github_project) stays under the store's authority — the
// reverse channel never imports metadata edits.
func ChangedFields(stored, incoming *store.Entry) []string {
	var changed []string
	if stored.Username != incoming.Username {
		changed = append(changed, "username")
	}
	if stored.URL != incoming.URL {
		changed = append(changed, "url")
	}
	if stored.Notes != incoming.Notes {
		changed = append(changed, "notes")
	}
	if incoming.Kind == store.KindTOTP || stored.Kind == store.KindTOTP {
		if stored.Password != incoming.Password ||
			stored.TOTPIssuer != incoming.TOTPIssuer ||
			normLabel(stored) != normLabel(incoming) ||
			normAlg(stored.TOTPAlgorithm) != normAlg(incoming.TOTPAlgorithm) ||
			normDigits(stored.TOTPDigits) != normDigits(incoming.TOTPDigits) ||
			normPeriod(stored.TOTPPeriod) != normPeriod(incoming.TOTPPeriod) {
			changed = append(changed, "totp")
		}
	} else if stored.Password != incoming.Password {
		changed = append(changed, "password")
	}
	keys := map[string]bool{}
	for k := range stored.Fields {
		keys[k] = true
	}
	for k := range incoming.Fields {
		keys[k] = true
	}
	for k := range keys {
		if stored.Fields[k] != incoming.Fields[k] {
			changed = append(changed, "field."+k)
		}
	}
	sort.Strings(changed)
	return changed
}

// normLabel resolves the TOTP label the mirror would render: ItemFromEntry
// defaults an empty label to the item name, so an unset store label and
// its round-tripped explicit form must compare equal.
func normLabel(e *store.Entry) string {
	if e.TOTPLabel == "" {
		return ItemName(e)
	}
	return e.TOTPLabel
}

// TOTP parameter zero values mean "default" (SHA1 / 6 digits / 30s) —
// normalise before comparing so an explicit default is not a change.
func normAlg(a string) string {
	if a == "" {
		return "SHA1"
	}
	return strings.ToUpper(a)
}

func normDigits(d int) int {
	if d == 0 {
		return 6
	}
	return d
}

func normPeriod(p int) int {
	if p == 0 {
		return 30
	}
	return p
}
