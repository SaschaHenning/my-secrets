package bw

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// InNamespace reports whether a folder name belongs to the dedicated
// mirror namespace ("mys" or "mys/<org>"). Everything outside is
// invisible to push and import.
func InNamespace(folderName string) bool {
	return folderName == FolderPrefix || strings.HasPrefix(folderName, FolderPrefix+"/")
}

// PathOf extracts the mys-path match key from an item's custom fields.
// Empty means the item was not created by the mirror (e.g. added on the
// phone) — push leaves such items alone; import classifies them as NEW.
func PathOf(it Item) string {
	for _, f := range it.Fields {
		if f.Name == FieldPath {
			return f.Value
		}
	}
	return ""
}

// RemoteState is the mys/* slice of the vault: the namespace folders
// plus the items inside them. Nothing else is ever fetched.
type RemoteState struct {
	Folders []Folder
	Items   []Item
	// FolderNames maps folder id → name for the fetched folders.
	FolderNames map[string]string
}

// FetchRemoteState lists the vault folders, keeps only the mys
// namespace (restricted further to mys/<org> — plus the shared "mys"
// root for org == "" — when org is set), and fetches items folder by
// folder. Items outside the namespace are never read.
func FetchRemoteState(ctx context.Context, c *Client, org string) (RemoteState, error) {
	all, err := c.ListFolders(ctx)
	if err != nil {
		return RemoteState{}, err
	}
	rs := RemoteState{FolderNames: map[string]string{}}
	for _, f := range all {
		if !InNamespace(f.Name) {
			continue
		}
		if org != "" && f.Name != FolderName(org) {
			continue
		}
		rs.Folders = append(rs.Folders, f)
		rs.FolderNames[f.ID] = f.Name
		items, err := c.ListItemsInFolder(ctx, f.ID)
		if err != nil {
			return RemoteState{}, err
		}
		rs.Items = append(rs.Items, items...)
	}
	return rs, nil
}

// PlannedWrite is one create/update decision: the desired item plus the
// folder it belongs in. FolderID is left empty on the item and resolved
// against the live vault at execution time, because server folder ids
// are random (the deterministic export ids do not exist there).
type PlannedWrite struct {
	Path   string
	Folder string
	Item   Item
	// ID is the existing item's id — set for updates, empty for creates.
	ID string
}

// PlannedPrune is one soft-delete decision.
type PlannedPrune struct {
	ID   string
	Path string
}

// PushPlan is the full decision set of one push run. It carries paths
// and item names only — never secret values — so it is safe to print.
type PushPlan struct {
	CreateFolders []string
	Creates       []PlannedWrite
	Updates       []PlannedWrite
	Prunes        []PlannedPrune
	Unchanged     int
	// Foreign counts namespace items without a mys-path field. Push
	// never touches them; they are bw-import material.
	Foreign int
	// Warnings lists per-entry anomalies (unmappable entries, duplicate
	// match keys). Path + cause only.
	Warnings []string
}

// HasWrites reports whether executing the plan would change the vault.
func (p PushPlan) HasWrites() bool {
	return len(p.CreateFolders) > 0 || len(p.Creates) > 0 || len(p.Updates) > 0 || len(p.Prunes) > 0
}

// BuildPushPlan diffs the desired store state against the remote
// namespace. storePaths must contain every path that exists in the
// store (unfiltered by --org) — it is the safety net that keeps prune
// from trashing mirror items whose entry still exists but fell outside
// the current filter.
func BuildPushPlan(entries []*store.Entry, storePaths map[string]bool, remote RemoteState, prune bool) PushPlan {
	var plan PushPlan
	byPath := map[string][]Item{}
	for _, it := range remote.Items {
		p := PathOf(it)
		if p == "" {
			plan.Foreign++
			continue
		}
		byPath[p] = append(byPath[p], it)
	}
	remoteFolders := map[string]bool{}
	for _, f := range remote.Folders {
		remoteFolders[f.Name] = true
	}

	neededFolders := map[string]bool{}
	for _, e := range entries {
		desired, err := ItemFromEntry(e)
		if err != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("skip %s: %v", e.Path, err))
			continue
		}
		folder := FolderName(orgOf(e))
		desired.FolderID = "" // resolved against the live vault at execution
		matches := byPath[e.Path]
		switch len(matches) {
		case 0:
			plan.Creates = append(plan.Creates, PlannedWrite{Path: e.Path, Folder: folder, Item: desired})
			neededFolders[folder] = true
		case 1:
			existing := matches[0]
			if existing.Type != TypeLogin {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("skip %s: existing Bitwarden item %q is not a login item", e.Path, existing.Name))
				continue
			}
			if contentEqual(desired, existing) && remote.FolderNames[existing.FolderID] == folder {
				plan.Unchanged++
				continue
			}
			plan.Updates = append(plan.Updates, PlannedWrite{Path: e.Path, Folder: folder, Item: desired, ID: existing.ID})
			neededFolders[folder] = true
		default:
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("skip %s: %d Bitwarden items share this mys-path — resolve the duplicates first", e.Path, len(matches)))
		}
	}
	for name := range neededFolders {
		if !remoteFolders[name] {
			plan.CreateFolders = append(plan.CreateFolders, name)
		}
	}
	sort.Strings(plan.CreateFolders)

	if prune {
		for _, it := range remote.Items {
			p := PathOf(it)
			if p == "" || storePaths[p] {
				continue
			}
			plan.Prunes = append(plan.Prunes, PlannedPrune{ID: it.ID, Path: p})
		}
		sort.Slice(plan.Prunes, func(i, j int) bool { return plan.Prunes[i].Path < plan.Prunes[j].Path })
	}
	return plan
}

// contentEqual compares the mirror-managed content of two items: name,
// notes, login payload, and custom fields. Folder placement is compared
// separately by the caller (ids differ per vault, names are canonical).
func contentEqual(a, b Item) bool {
	if a.Name != b.Name || a.Notes != b.Notes {
		return false
	}
	al, bl := loginOrEmpty(a.Login), loginOrEmpty(b.Login)
	if al.Username != bl.Username || al.Password != bl.Password || al.TOTP != bl.TOTP {
		return false
	}
	if len(al.URIs) != len(bl.URIs) {
		return false
	}
	for i := range al.URIs {
		if al.URIs[i].URI != bl.URIs[i].URI {
			return false
		}
	}
	if len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i] != b.Fields[i] {
			return false
		}
	}
	return true
}

func loginOrEmpty(l *Login) Login {
	if l == nil {
		return Login{}
	}
	return *l
}

// PushResult counts the writes actually performed.
type PushResult struct {
	CreatedFolders int
	Created        int
	Updated        int
	Pruned         int
}

// ExecutePush applies a plan: create missing folders, then create,
// update and prune items. Folder ids are resolved from the live remote
// state plus the folders created here. The first error aborts the run —
// the partial result is returned so the caller can audit exactly how
// far the push got.
func ExecutePush(ctx context.Context, c *Client, plan PushPlan, remote RemoteState) (PushResult, error) {
	var res PushResult
	folderIDs := map[string]string{}
	for _, f := range remote.Folders {
		folderIDs[f.Name] = f.ID
	}
	for _, name := range plan.CreateFolders {
		f, err := c.CreateFolder(ctx, name)
		if err != nil {
			return res, fmt.Errorf("create folder %s: %w", name, err)
		}
		folderIDs[name] = f.ID
		res.CreatedFolders++
	}
	place := func(w PlannedWrite) (Item, error) {
		id, ok := folderIDs[w.Folder]
		if !ok {
			return Item{}, fmt.Errorf("%s: folder %s missing from plan", w.Path, w.Folder)
		}
		it := w.Item
		it.FolderID = id
		return it, nil
	}
	for _, w := range plan.Creates {
		it, err := place(w)
		if err != nil {
			return res, err
		}
		if _, err := c.CreateItem(ctx, it); err != nil {
			return res, fmt.Errorf("create %s: %w", w.Path, err)
		}
		res.Created++
	}
	for _, w := range plan.Updates {
		it, err := place(w)
		if err != nil {
			return res, err
		}
		it.ID = w.ID
		if err := c.EditItem(ctx, w.ID, it); err != nil {
			return res, fmt.Errorf("update %s: %w", w.Path, err)
		}
		res.Updated++
	}
	for _, p := range plan.Prunes {
		if err := c.DeleteItem(ctx, p.ID); err != nil {
			return res, fmt.Errorf("prune %s: %w", p.Path, err)
		}
		res.Pruned++
	}
	return res, nil
}
