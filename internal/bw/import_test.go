package bw

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// remoteWith builds a RemoteState with one mys/<org> folder and the
// items placed inside it.
func remoteWith(t *testing.T, org string, items ...Item) RemoteState {
	t.Helper()
	folder := Folder{ID: "f-" + org, Name: FolderName(org)}
	rs := RemoteState{
		Folders:     []Folder{folder},
		FolderNames: map[string]string{folder.ID: folder.Name},
	}
	for _, it := range items {
		it.FolderID = folder.ID
		rs.Items = append(rs.Items, it)
	}
	return rs
}

func TestBuildImportDiff_Classification(t *testing.T) {
	stored := map[string]*store.Entry{
		"jasp/changed": {Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword, Password: "old"},
		"jasp/synced":  {Path: "jasp/synced", Org: "jasp", Kind: store.KindPassword, Password: "same"},
		"jasp/only":    {Path: "jasp/only", Org: "jasp", Kind: store.KindPassword, Password: "x"},
	}
	remote := remoteWith(t, "jasp",
		mirrorItem(t, &store.Entry{Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword, Password: "new"}, "i1", "f-jasp"),
		mirrorItem(t, &store.Entry{Path: "jasp/synced", Org: "jasp", Kind: store.KindPassword, Password: "same"}, "i2", "f-jasp"),
		// Phone-created item: no mys-path field, matched by folder+name.
		Item{Type: TypeLogin, Name: "phone", Login: &Login{Password: "p"}},
	)
	diffs, inSync, warnings := BuildImportDiff(stored, remote, "")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if inSync != 1 {
		t.Errorf("inSync = %d, want 1", inSync)
	}
	want := []struct {
		path, class string
		changed     []string
	}{
		{"jasp/changed", ClassChanged, []string{"password"}},
		{"jasp/phone", ClassNew, nil},
		{"jasp/only", ClassStoreOnly, nil},
	}
	if len(diffs) != len(want) {
		t.Fatalf("diffs = %+v, want %d rows", diffs, len(want))
	}
	for i, w := range want {
		d := diffs[i]
		if d.Path != w.path || d.Class != w.class || !reflect.DeepEqual(d.Changed, w.changed) {
			t.Errorf("row %d = %+v, want %+v", i, d, w)
		}
	}
	if diffs[1].Incoming == nil || diffs[1].Incoming.Password != "p" {
		t.Errorf("NEW row must carry the reverse-mapped entry: %+v", diffs[1].Incoming)
	}
	if diffs[2].Incoming != nil {
		t.Errorf("STORE-ONLY row must not carry an incoming entry")
	}
}

func TestBuildImportDiff_DuplicateMysPathWarnsAndSkips(t *testing.T) {
	e := &store.Entry{Path: "jasp/dup", Org: "jasp", Kind: store.KindPassword, Password: "a"}
	remote := remoteWith(t, "jasp", mirrorItem(t, e, "i1", "f-jasp"), mirrorItem(t, e, "i2", "f-jasp"))
	// The store entry behind the ambiguous pair must not surface as
	// STORE-ONLY — it has vault counterparts, just too many.
	diffs, _, warnings := BuildImportDiff(map[string]*store.Entry{e.Path: e}, remote, "")
	if len(diffs) != 0 {
		t.Errorf("duplicate items must not produce diff rows: %+v", diffs)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "jasp/dup") {
		t.Errorf("warnings = %v, want duplicate warning per item", warnings)
	}
}

func TestBuildImportDiff_BareRootItemWithSlashNameWarns(t *testing.T) {
	// In the bare "mys" root folder the item NAME becomes the full store
	// path — a "/" in it would pick an org the folder never named.
	rootFolder := Folder{ID: "f0", Name: FolderPrefix}
	remote := RemoteState{
		Folders:     []Folder{rootFolder},
		FolderNames: map[string]string{"f0": FolderPrefix},
		Items: []Item{{
			Type: TypeLogin, Name: "jasp/smuggled", FolderID: "f0",
			Login: &Login{Password: "p"},
		}},
	}
	diffs, _, warnings := BuildImportDiff(map[string]*store.Entry{}, remote, "")
	if len(diffs) != 0 {
		t.Errorf("slash-named root item must not produce diff rows: %+v", diffs)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "must not contain '/'") {
		t.Errorf("warnings = %v, want slash-name warning", warnings)
	}
}

func TestBuildImportDiff_NonLoginItemWarns(t *testing.T) {
	remote := remoteWith(t, "jasp", Item{Type: 2, Name: "secure-note"})
	diffs, _, warnings := BuildImportDiff(map[string]*store.Entry{}, remote, "")
	if len(diffs) != 0 {
		t.Errorf("non-login item must not produce a diff row: %+v", diffs)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not a login item") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestBuildImportDiff_OrgFilter(t *testing.T) {
	remote := RemoteState{
		Folders: []Folder{{ID: "f1", Name: "mys/jasp"}, {ID: "f2", Name: "mys/zuhause"}},
		FolderNames: map[string]string{
			"f1": "mys/jasp",
			"f2": "mys/zuhause",
		},
	}
	remote.Items = []Item{
		mirrorItem(t, &store.Entry{Path: "jasp/a", Org: "jasp", Kind: store.KindPassword, Password: "x"}, "i1", "f1"),
		mirrorItem(t, &store.Entry{Path: "zuhause/b", Org: "zuhause", Kind: store.KindPassword, Password: "y"}, "i2", "f2"),
	}
	diffs, _, warnings := BuildImportDiff(map[string]*store.Entry{}, remote, "zuhause")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if len(diffs) != 1 || diffs[0].Path != "zuhause/b" || diffs[0].Class != ClassNew {
		t.Errorf("diffs = %+v, want exactly the zuhause NEW row", diffs)
	}
}

func TestBuildImportDiffForTarget_RebasesSourceIntoSharedMount(t *testing.T) {
	stored := map[string]*store.Entry{
		"jasp-shared/changed": {
			Path: "jasp-shared/changed", Org: "jasp-shared",
			Kind: store.KindPassword, Password: "old",
		},
		"jasp-shared/only": {
			Path: "jasp-shared/only", Org: "jasp-shared",
			Kind: store.KindPassword, Password: "store-only",
		},
	}
	remote := remoteWith(t, "jasp",
		mirrorItem(t, &store.Entry{
			Path: "jasp/changed", Org: "jasp",
			Kind: store.KindPassword, Password: "new",
		}, "i1", "f-jasp"),
		Item{Type: TypeLogin, Name: "phone", Login: &Login{Password: "phone-secret"}},
	)

	diffs, inSync, warnings, err := BuildImportDiffForTarget(
		stored, remote, "jasp", "jasp-shared")
	if err != nil {
		t.Fatalf("BuildImportDiffForTarget: %v", err)
	}
	if inSync != 0 || len(warnings) != 0 {
		t.Fatalf("inSync=%d warnings=%v, want zero and none", inSync, warnings)
	}
	if len(diffs) != 3 {
		t.Fatalf("diffs = %+v, want CHANGED, NEW, STORE-ONLY", diffs)
	}
	want := []struct {
		path, class string
	}{
		{"jasp-shared/changed", ClassChanged},
		{"jasp-shared/phone", ClassNew},
		{"jasp-shared/only", ClassStoreOnly},
	}
	for i, expected := range want {
		if diffs[i].Path != expected.path || diffs[i].Class != expected.class {
			t.Errorf("diff %d = %+v, want path=%q class=%q",
				i, diffs[i], expected.path, expected.class)
		}
		if diffs[i].Incoming != nil {
			if diffs[i].Incoming.Path != expected.path {
				t.Errorf("incoming path = %q, want %q",
					diffs[i].Incoming.Path, expected.path)
			}
			if diffs[i].Incoming.Org != "jasp-shared" {
				t.Errorf("incoming org = %q, want jasp-shared", diffs[i].Incoming.Org)
			}
		}
	}
}

func TestBuildImportDiffForTarget_IdentityMappingDoesNotDoublePrefix(t *testing.T) {
	remote := remoteWith(t, "jasp",
		Item{Type: TypeLogin, Name: "phone", Login: &Login{Password: "value"}})
	diffs, _, warnings, err := BuildImportDiffForTarget(
		map[string]*store.Entry{}, remote, "jasp", "jasp")
	if err != nil {
		t.Fatalf("BuildImportDiffForTarget: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if len(diffs) != 1 || diffs[0].Path != "jasp/phone" {
		t.Fatalf("diffs = %+v, want jasp/phone", diffs)
	}
}

func TestBuildImportDiffForTarget_RejectsNonCanonicalSourcePaths(t *testing.T) {
	paths := []string{
		"jasp/../private",
		"jasp/./secret",
		"jasp//secret",
		"jasp/secret\ninjected",
	}
	items := make([]Item, 0, len(paths))
	for _, sourcePath := range paths {
		items = append(items, Item{
			Type: TypeLogin,
			Name: "malformed",
			Fields: []Field{{
				Name: FieldPath, Value: sourcePath,
			}},
			Login: &Login{Password: "must-not-leak"},
		})
	}
	remote := remoteWith(t, "jasp", items...)
	diffs, _, warnings, err := BuildImportDiffForTarget(
		map[string]*store.Entry{}, remote, "jasp", "jasp-shared")
	if err != nil {
		t.Fatalf("BuildImportDiffForTarget: %v", err)
	}
	if len(diffs) != 0 {
		t.Fatalf("malformed paths produced diffs: %+v", diffs)
	}
	if len(warnings) != len(paths) {
		t.Fatalf("warnings = %v, want %d sanitized warnings", warnings, len(paths))
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "must-not-leak") ||
			strings.ContainsAny(warning, "\r\n") {
			t.Fatalf("warning is not sanitized: %q", warning)
		}
	}
}

func TestRebaseImportPath_RequiresSourceOrgForTarget(t *testing.T) {
	if _, err := RebaseImportPath("jasp/item", "", "jasp-shared"); err == nil {
		t.Fatal("RebaseImportPath should reject a target mount without source org")
	}
}
