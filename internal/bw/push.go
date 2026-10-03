package bw

import (
	"context"
	"fmt"
	"maps"
	"slices"
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
// namespace, and fetches items folder by folder. The whole namespace is
// always fetched — even for an --org-filtered push — so mys-path
// matching sees an item that was hand-moved into another mys/* folder
// instead of creating a duplicate next to it.
//
// The organizations in targets are fetched as well: folders are per
// user, so a shared mirror item can sit outside every mys/* folder of
// this account. Apart from these organizations, items outside the
// namespace are never read.
func FetchRemoteState(ctx context.Context, c *Client, targets map[string]OrgTarget) (RemoteState, error) {
	all, err := c.ListFolders(ctx)
	if err != nil {
		return RemoteState{}, err
	}
	rs := RemoteState{FolderNames: map[string]string{}}
	for _, f := range all {
		if !InNamespace(f.Name) {
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
	seen := map[string]bool{}
	for _, it := range rs.Items {
		seen[it.ID] = true
	}
	orgIDs := map[string]bool{}
	for _, t := range targets {
		orgIDs[t.OrganizationID] = true
	}
	for _, orgID := range slices.Sorted(maps.Keys(orgIDs)) {
		items, err := c.ListItemsInOrganization(ctx, orgID)
		if err != nil {
			return RemoteState{}, err
		}
		for _, it := range items {
			if seen[it.ID] {
				continue
			}
			// Any collection member can write any mys-path. Only a path
			// whose org is mapped to exactly this organization may match,
			// or a forged "zuhause/x" item would pull a private secret
			// into the shared collection on the next push.
			p := PathOf(it)
			t, mapped := targets[store.OrgOf(p)]
			if p == "" || !mapped || !strings.EqualFold(t.OrganizationID, orgID) {
				continue
			}
			seen[it.ID] = true
			rs.Items = append(rs.Items, it)
		}
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

// PlannedMove is one personal-to-organization move decision.
type PlannedMove struct {
	ID             string
	Path           string
	OrganizationID string
	CollectionIDs  []string
}

// PlannedPrune is one soft-delete decision. A non-empty OrganizationID
// marks a shared item: trashing it removes it for the whole collection.
type PlannedPrune struct {
	ID             string
	Path           string
	OrganizationID string
}

// PushPlan is the full decision set of one push run. It carries paths
// and item names only — never secret values — so it is safe to print.
type PushPlan struct {
	CreateFolders []string
	Creates       []PlannedWrite
	Updates       []PlannedWrite
	Moves         []PlannedMove
	Prunes        []PlannedPrune
	Unchanged     int
	// Foreign counts namespace items without a mys-path field. Push
	// never touches them; they are bw-import material.
	Foreign int
	// SharedPruneSkipped counts stale organization items left alone
	// because shared pruning was not requested.
	SharedPruneSkipped int
	// Warnings lists per-entry anomalies (unmappable entries, duplicate
	// match keys). Path + cause only.
	Warnings []string
}

// SharedPrunes counts the planned prunes of organization items.
func (p PushPlan) SharedPrunes() int {
	n := 0
	for _, pr := range p.Prunes {
		if pr.OrganizationID != "" {
			n++
		}
	}
	return n
}

// PlanOptions steers BuildPushPlan.
type PlanOptions struct {
	// Prune trashes personal mirror items whose mys-path left the store.
	Prune bool
	// PruneShared extends Prune to items inside an organization.
	PruneShared bool
	// Org restricts prunes to items whose mys-path belongs to this org.
	Org string
	// Targets maps a mys org to its Bitwarden organization placement:
	// new items are created there, existing personal items are moved
	// there. Items already inside an organization keep it.
	Targets map[string]OrgTarget
}

// HasWrites reports whether executing the plan would change the vault.
func (p PushPlan) HasWrites() bool {
	return len(p.CreateFolders) > 0 || len(p.Creates) > 0 || len(p.Updates) > 0 || len(p.Moves) > 0 || len(p.Prunes) > 0
}

// BuildPushPlan diffs the desired store state against the remote
// namespace. storePaths must contain every path that exists in the
// store (unfiltered by --org) — it is the safety net that keeps prune
// from trashing mirror items whose entry still exists but fell outside
// the current filter. A non-empty opts.Org additionally restricts prunes
// to items whose mys-path belongs to that org: a filtered push must not
// touch other orgs' stale items.
func BuildPushPlan(entries []*store.Entry, storePaths map[string]bool, remote RemoteState, opts PlanOptions) PushPlan {
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
		target, mapped := opts.Targets[orgOf(e)]
		matches := byPath[e.Path]
		switch len(matches) {
		case 0:
			if mapped {
				desired.OrganizationID = target.OrganizationID
				desired.CollectionIDs = target.CollectionIDs
			}
			plan.Creates = append(plan.Creates, PlannedWrite{Path: e.Path, Folder: folder, Item: desired})
			neededFolders[folder] = true
		case 1:
			existing := matches[0]
			if existing.Type != TypeLogin {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("skip %s: existing Bitwarden item %q is not a login item", e.Path, existing.Name))
				continue
			}
			move := false
			switch {
			case existing.OrganizationID != "" && !mapped:
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("skip %s: Bitwarden item sits in organization %s, but %s is not mapped to it — not writing a personal secret into a shared collection",
						e.Path, existing.OrganizationID, orgOf(e)))
				continue
			case existing.OrganizationID != "" && !strings.EqualFold(existing.OrganizationID, target.OrganizationID):
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("skip %s: Bitwarden item sits in organization %s, but %s is mapped to %s",
						e.Path, existing.OrganizationID, orgOf(e), target.OrganizationID))
				continue
			case existing.OrganizationID != "":
				desired.OrganizationID = existing.OrganizationID
				desired.CollectionIDs = existing.CollectionIDs
			case mapped:
				move = true
				desired.OrganizationID = target.OrganizationID
				desired.CollectionIDs = target.CollectionIDs
				plan.Moves = append(plan.Moves, PlannedMove{
					ID: existing.ID, Path: e.Path,
					OrganizationID: target.OrganizationID, CollectionIDs: target.CollectionIDs,
				})
			}
			if contentEqual(desired, existing) && remote.FolderNames[existing.FolderID] == folder {
				if !move {
					plan.Unchanged++
				}
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

	if opts.Prune {
		for _, it := range remote.Items {
			p := PathOf(it)
			if p == "" || storePaths[p] {
				continue
			}
			if opts.Org != "" && store.OrgOf(p) != opts.Org {
				continue
			}
			if it.OrganizationID != "" && !opts.PruneShared {
				plan.SharedPruneSkipped++
				continue
			}
			plan.Prunes = append(plan.Prunes, PlannedPrune{ID: it.ID, Path: p, OrganizationID: it.OrganizationID})
		}
		sort.Slice(plan.Prunes, func(i, j int) bool { return plan.Prunes[i].Path < plan.Prunes[j].Path })
	}
	return plan
}

// contentEqual compares the mirror-managed content of two items: name,
// notes, login payload, and custom fields. Folder placement is compared
// separately by the caller (ids differ per vault, names are canonical).
// Fields and URIs are compared in order: the mirror writes them
// deterministically and Bitwarden stores both as plain JSON arrays, so
// order survives the round trip (pinned by the idempotent-re-push E2E
// against a real server). Worst case on a server that reorders would be
// a redundant update — never data loss.
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
	Moved          int
	Pruned         int
}

// ExecutePush applies a plan: create missing folders, then create,
// move, update and prune items. Folder ids are resolved from the live remote
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
	// Moves must run before updates: an update of a moved item already
	// carries the organization id, and bw edit on a still-personal item
	// with an organization id re-encrypts it under the org key without
	// moving it on the server.
	for _, m := range plan.Moves {
		if err := c.MoveItem(ctx, m.ID, m.OrganizationID, m.CollectionIDs); err != nil {
			return res, fmt.Errorf("move %s: %w", m.Path, err)
		}
		res.Moved++
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
