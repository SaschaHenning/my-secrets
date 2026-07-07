package bw

import (
	"fmt"
	"sort"

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
	seen := map[string]int{}
	for _, it := range remote.Items {
		seen[PathForItem(it, remote.FolderNames[it.FolderID])]++
	}
	matched := map[string]bool{}
	for _, it := range remote.Items {
		folder := remote.FolderNames[it.FolderID]
		path := PathForItem(it, folder)
		if org != "" && store.OrgOf(path) != org {
			continue
		}
		if seen[path] > 1 {
			warnings = append(warnings, fmt.Sprintf("skip %s: %d Bitwarden items map to this path — resolve the duplicates first", path, seen[path]))
			continue
		}
		incoming, err := EntryFromItem(it, folder)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", path, err))
			continue
		}
		stored, ok := storeEntries[path]
		if !ok {
			diffs = append(diffs, ImportDiff{Path: path, Class: ClassNew, Incoming: incoming})
			continue
		}
		matched[path] = true
		changed := ChangedFields(stored, incoming)
		if len(changed) == 0 {
			inSync++
			continue
		}
		diffs = append(diffs, ImportDiff{Path: path, Class: ClassChanged, Changed: changed, Incoming: incoming})
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].Path < diffs[j].Path })
	var storeOnly []ImportDiff
	for p := range storeEntries {
		if !matched[p] {
			storeOnly = append(storeOnly, ImportDiff{Path: p, Class: ClassStoreOnly})
		}
	}
	sort.Slice(storeOnly, func(i, j int) bool { return storeOnly[i].Path < storeOnly[j].Path })
	return append(diffs, storeOnly...), inSync, warnings
}
