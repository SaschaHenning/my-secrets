package bw

import (
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// mirrorItem renders an entry exactly the way a previous push would
// have left it in the vault: mapped item + server ids.
func mirrorItem(t *testing.T, e *store.Entry, id, folderID string) Item {
	t.Helper()
	it, err := ItemFromEntry(e)
	if err != nil {
		t.Fatalf("ItemFromEntry(%s): %v", e.Path, err)
	}
	it.ID = id
	it.FolderID = folderID
	return it
}

func pathsOf(entries ...*store.Entry) map[string]bool {
	m := map[string]bool{}
	for _, e := range entries {
		m[e.Path] = true
	}
	return m
}

func TestBuildPushPlan_EmptyVaultCreatesEverything(t *testing.T) {
	entries := []*store.Entry{
		{Path: "jasp/a", Org: "jasp", Password: "x"},
		{Path: "zuhause/b", Org: "zuhause", Password: "y"},
	}
	plan := BuildPushPlan(entries, pathsOf(entries...), RemoteState{FolderNames: map[string]string{}}, false)
	if len(plan.Creates) != 2 || len(plan.Updates) != 0 || len(plan.Prunes) != 0 || plan.Unchanged != 0 {
		t.Fatalf("plan = %+v, want 2 creates only", plan)
	}
	if len(plan.CreateFolders) != 2 || plan.CreateFolders[0] != "mys/jasp" || plan.CreateFolders[1] != "mys/zuhause" {
		t.Fatalf("CreateFolders = %v, want sorted mys/jasp + mys/zuhause", plan.CreateFolders)
	}
	if plan.Creates[0].Item.FolderID != "" {
		t.Error("planned item must leave FolderID empty for execution-time resolution")
	}
}

func TestBuildPushPlan_IdempotentSecondRun(t *testing.T) {
	e := &store.Entry{Path: "jasp/a", Org: "jasp", Username: "u", URL: "https://a.example", Password: "x"}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{mirrorItem(t, e, "i1", "f1")},
	}
	plan := BuildPushPlan([]*store.Entry{e}, pathsOf(e), remote, true)
	if plan.HasWrites() {
		t.Fatalf("plan = %+v, want no writes on identical state", plan)
	}
	if plan.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", plan.Unchanged)
	}
}

func TestBuildPushPlan_ChangedContentUpdates(t *testing.T) {
	old := &store.Entry{Path: "jasp/a", Org: "jasp", Password: "old"}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{mirrorItem(t, old, "i1", "f1")},
	}
	rotated := &store.Entry{Path: "jasp/a", Org: "jasp", Password: "new"}
	plan := BuildPushPlan([]*store.Entry{rotated}, pathsOf(rotated), remote, false)
	if len(plan.Updates) != 1 || plan.Updates[0].ID != "i1" || plan.Updates[0].Path != "jasp/a" {
		t.Fatalf("plan = %+v, want exactly one update of i1", plan)
	}
	if len(plan.Creates) != 0 || plan.Unchanged != 0 {
		t.Errorf("plan = %+v, want no creates/unchanged", plan)
	}
}

func TestBuildPushPlan_FolderMoveUpdates(t *testing.T) {
	// Item content identical, but the vault item sits in the wrong
	// folder (e.g. moved by hand in the app) — the mirror moves it back.
	e := &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}, {ID: "f2", Name: "mys/zuhause"}},
		FolderNames: map[string]string{"f1": "mys/jasp", "f2": "mys/zuhause"},
		Items:       []Item{mirrorItem(t, e, "i1", "f2")},
	}
	plan := BuildPushPlan([]*store.Entry{e}, pathsOf(e), remote, false)
	if len(plan.Updates) != 1 {
		t.Fatalf("plan = %+v, want folder move as update", plan)
	}
}

func TestBuildPushPlan_PruneOnlyTrulyGonePaths(t *testing.T) {
	kept := &store.Entry{Path: "jasp/keep", Org: "jasp", Password: "x"}
	goneItem := mirrorItem(t, &store.Entry{Path: "jasp/gone", Org: "jasp", Password: "y"}, "i-gone", "f1")
	// Exists in the store but outside the current --org slice: must
	// survive a filtered prune run.
	elsewhereItem := mirrorItem(t, &store.Entry{Path: "zuhause/other", Org: "zuhause", Password: "z"}, "i-other", "f1")
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{mirrorItem(t, kept, "i-keep", "f1"), goneItem, elsewhereItem},
	}
	storePaths := map[string]bool{"jasp/keep": true, "zuhause/other": true}
	plan := BuildPushPlan([]*store.Entry{kept}, storePaths, remote, true)
	if len(plan.Prunes) != 1 || plan.Prunes[0].ID != "i-gone" || plan.Prunes[0].Path != "jasp/gone" {
		t.Fatalf("Prunes = %+v, want exactly jasp/gone", plan.Prunes)
	}
}

func TestBuildPushPlan_NoPruneWithoutFlag(t *testing.T) {
	gone := mirrorItem(t, &store.Entry{Path: "jasp/gone", Org: "jasp", Password: "y"}, "i1", "f1")
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{gone},
	}
	plan := BuildPushPlan(nil, map[string]bool{}, remote, false)
	if len(plan.Prunes) != 0 {
		t.Fatalf("Prunes = %+v, want none without --prune", plan.Prunes)
	}
}

func TestBuildPushPlan_ForeignItemsUntouched(t *testing.T) {
	// An item created on the phone (no mys-path) must never be pruned —
	// it is bw-import material.
	foreign := Item{ID: "i-phone", Type: TypeLogin, Name: "new-on-phone", FolderID: "f1",
		Login: &Login{Password: "p"}}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{foreign},
	}
	plan := BuildPushPlan(nil, map[string]bool{}, remote, true)
	if len(plan.Prunes) != 0 {
		t.Fatalf("Prunes = %+v, foreign item must not be pruned", plan.Prunes)
	}
	if plan.Foreign != 1 {
		t.Errorf("Foreign = %d, want 1", plan.Foreign)
	}
}

func TestBuildPushPlan_DuplicateMatchKeySkipsWithWarning(t *testing.T) {
	e := &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{mirrorItem(t, e, "i1", "f1"), mirrorItem(t, e, "i2", "f1")},
	}
	plan := BuildPushPlan([]*store.Entry{e}, pathsOf(e), remote, false)
	if plan.HasWrites() {
		t.Fatalf("plan = %+v, want no writes on ambiguous match", plan)
	}
	if len(plan.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want one duplicate warning", plan.Warnings)
	}
}

func TestBuildPushPlan_UnmappableEntryWarnsAndSkips(t *testing.T) {
	bad := &store.Entry{Path: "jasp/legacy", Org: "jasp", Kind: store.KindTOTP,
		Password: "JBSWY3DPEHPK3PXP", TOTPAlgorithm: "MD5"}
	plan := BuildPushPlan([]*store.Entry{bad}, pathsOf(bad), RemoteState{FolderNames: map[string]string{}}, false)
	if plan.HasWrites() {
		t.Fatalf("plan = %+v, want no writes for unmappable entry", plan)
	}
	if len(plan.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want one skip warning", plan.Warnings)
	}
}

func TestBuildPushPlan_NonLoginMatchSkipsWithWarning(t *testing.T) {
	e := &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"}
	note := Item{ID: "i1", Type: 2, Name: "a", FolderID: "f1",
		Fields: []Field{{Name: FieldPath, Value: "jasp/a", Type: FieldText}}}
	remote := RemoteState{
		Folders:     []Folder{{ID: "f1", Name: "mys/jasp"}},
		FolderNames: map[string]string{"f1": "mys/jasp"},
		Items:       []Item{note},
	}
	plan := BuildPushPlan([]*store.Entry{e}, pathsOf(e), remote, false)
	if plan.HasWrites() || len(plan.Warnings) != 1 {
		t.Fatalf("plan = %+v, want warning-only for non-login match", plan)
	}
}

func TestInNamespace(t *testing.T) {
	for name, want := range map[string]bool{
		"mys":           true,
		"mys/jasp":      true,
		"mystery":       false,
		"private":       false,
		"work/mys":      false,
		"mys2/whatever": false,
	} {
		if got := InNamespace(name); got != want {
			t.Errorf("InNamespace(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestContentEqual_NilLogin(t *testing.T) {
	a := Item{Name: "x", Login: nil}
	b := Item{Name: "x", Login: &Login{}}
	if !contentEqual(a, b) {
		t.Error("nil login must equal empty login")
	}
	c := Item{Name: "x", Login: &Login{Password: "p"}}
	if contentEqual(a, c) {
		t.Error("nil login must differ from populated login")
	}
}
