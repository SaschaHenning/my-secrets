package bw

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// Diff classes of one bw-import comparison.
const (
	// ClassNew: exists in the mys/* namespace but not in the store —
	// typically created on the phone. Applying creates the store entry.
	ClassNew = "NEW"
	// ClassChanged: exists on both sides with differing content.
	// Applying overwrites exactly the changed fields in the store.
	ClassChanged = "CHANGED"
	// ClassStoreOnly: exists only in the store. Informational — the
	// reverse channel never deletes store entries.
	ClassStoreOnly = "STORE-ONLY"
)

// ImportDiff is one row of the bw-import comparison. It carries field
// NAMES only in Changed — values stay out of every printable surface.
type ImportDiff struct {
	Path    string
	Class   string
	Changed []string
	// Incoming is the reverse-mapped Bitwarden state (nil for
	// STORE-ONLY rows).
	Incoming *store.Entry
}

// BuildImportDiff classifies the mys/* namespace items against the
// store entries. storeEntries must hold the decrypted entries within
// the org scope; org additionally filters which remote items are
// considered. Returns the diff rows (NEW/CHANGED first by path, then
// STORE-ONLY), the count of in-sync pairs, and warnings for items that
// could not be mapped.
func BuildImportDiff(storeEntries map[string]*store.Entry, remote RemoteState, org string) (diffs []ImportDiff, inSync int, warnings []string) {
	diffs, inSync, warnings, _ = BuildImportDiffForTarget(
		storeEntries, remote, org, "")
	return diffs, inSync, warnings
}

// BuildImportDiffForTarget is BuildImportDiff with an optional namespace
// rebase for shared mounts. When targetMount is non-empty, only canonical
// paths below sourceOrg are considered and "sourceOrg/relative" becomes
// "targetMount/relative". Store lookup, duplicate detection, output paths,
// and Incoming entries all use the rebased target path.
func BuildImportDiffForTarget(
	storeEntries map[string]*store.Entry,
	remote RemoteState,
	sourceOrg, targetMount string,
) (diffs []ImportDiff, inSync int, warnings []string, err error) {
	if targetMount != "" {
		if err := validateImportTopLevel(sourceOrg, "source org"); err != nil {
			return nil, 0, nil, err
		}
		if err := validateImportTopLevel(targetMount, "target mount"); err != nil {
			return nil, 0, nil, err
		}
	}

	type candidate struct {
		item       Item
		folder     string
		targetPath string
	}
	candidates := make([]candidate, 0, len(remote.Items))
	seen := map[string]int{}
	for _, it := range remote.Items {
		folder := remote.FolderNames[it.FolderID]
		sourcePath := PathForItem(it, folder)
		// A phone-created item in the bare mys root folder derives its
		// FULL path from its name — a "/" in the name would smuggle the
		// item into an org the folder placement never named.
		if PathOf(it) == "" && folder == FolderPrefix && strings.Contains(it.Name, "/") {
			warnings = append(warnings,
				"skip item in the mys root folder: item name must not contain '/'")
			continue
		}
		if sourceOrg != "" && !strings.HasPrefix(sourcePath, sourceOrg+"/") {
			continue
		}
		targetPath, mapErr := RebaseImportPath(sourcePath, sourceOrg, targetMount)
		if mapErr != nil {
			// The raw path is intentionally omitted: a malicious vault
			// item can contain terminal controls or newlines.
			warnings = append(warnings, "skip item with non-canonical source path")
			continue
		}
		candidates = append(candidates, candidate{
			item:       it,
			folder:     folder,
			targetPath: targetPath,
		})
		seen[targetPath]++
	}

	matched := map[string]bool{}
	for _, item := range candidates {
		if seen[item.targetPath] > 1 {
			// Mark the path as matched anyway: an existing store entry
			// behind an ambiguous remote pair must not be reported as
			// STORE-ONLY — it has vault counterparts, just too many.
			matched[item.targetPath] = true
			warnings = append(warnings, fmt.Sprintf(
				"skip %s: %d Bitwarden items map to this path — resolve the duplicates first",
				item.targetPath, seen[item.targetPath]))
			continue
		}
		incoming, entryErr := EntryFromItem(item.item, item.folder)
		if entryErr != nil {
			warnings = append(warnings, fmt.Sprintf(
				"skip %s: %v", item.targetPath, entryErr))
			continue
		}
		incoming.Path = item.targetPath
		incoming.Org = store.OrgOf(item.targetPath)
		stored, ok := storeEntries[item.targetPath]
		if !ok {
			diffs = append(diffs, ImportDiff{
				Path: item.targetPath, Class: ClassNew, Incoming: incoming,
			})
			continue
		}
		matched[item.targetPath] = true
		changed := ChangedFields(stored, incoming)
		if len(changed) == 0 {
			inSync++
			continue
		}
		diffs = append(diffs, ImportDiff{
			Path: item.targetPath, Class: ClassChanged,
			Changed: changed, Incoming: incoming,
		})
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].Path < diffs[j].Path })
	var storeOnly []ImportDiff
	for p := range storeEntries {
		if !matched[p] {
			storeOnly = append(storeOnly, ImportDiff{Path: p, Class: ClassStoreOnly})
		}
	}
	sort.Slice(storeOnly, func(i, j int) bool { return storeOnly[i].Path < storeOnly[j].Path })
	return append(diffs, storeOnly...), inSync, warnings, nil
}

// RebaseImportPath validates sourcePath and optionally maps it from a
// Bitwarden source org into a shared gopass mount. It never cleans or
// rewrites malformed input: non-canonical paths are rejected so policy,
// store, and audit always judge identical bytes.
func RebaseImportPath(sourcePath, sourceOrg, targetMount string) (string, error) {
	if err := validateCanonicalImportPath(sourcePath); err != nil {
		return "", err
	}
	if targetMount == "" {
		return sourcePath, nil
	}
	if err := validateImportTopLevel(sourceOrg, "source org"); err != nil {
		return "", err
	}
	if err := validateImportTopLevel(targetMount, "target mount"); err != nil {
		return "", err
	}
	prefix := sourceOrg + "/"
	if !strings.HasPrefix(sourcePath, prefix) {
		return "", fmt.Errorf("source path is outside source org")
	}
	relative := strings.TrimPrefix(sourcePath, prefix)
	if err := validateCanonicalImportPath(relative); err != nil {
		return "", err
	}
	return targetMount + "/" + relative, nil
}

func validateImportTopLevel(value, label string) error {
	if value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, `/\`+"\x00\r\n") ||
		value == "." || value == ".." {
		return fmt.Errorf("%s must be one canonical top-level segment", label)
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateCanonicalImportPath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, `\`) {
		return fmt.Errorf("path is not canonical")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("path is not canonical")
		}
		for _, char := range segment {
			if unicode.IsControl(char) {
				return fmt.Errorf("path contains a control character")
			}
		}
	}
	return nil
}
