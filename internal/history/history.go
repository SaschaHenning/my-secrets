// Package history reads git commit history for individual gopass store
// entries. Like internal/sync, this is an explicit, documented exception
// to the project's library-only rule for the store: gopass's own
// api.Gopass.Revisions is unimplemented upstream (returns
// ErrNotImplemented), so there is no library path to per-entry history.
// This package shells out to `git log` directly against the store's own
// on-disk git repository instead. Strictly read-only and metadata-only —
// it never touches secret content, only commit hash/timestamp/message.
package history

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/gopassinit"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// Revision is one commit that touched a single entry's encrypted file.
type Revision struct {
	Hash    string
	When    time.Time
	Message string
}

// fieldSep is ASCII Unit Separator (0x1F) — chosen because gopass commit
// messages are free text and could contain any printable delimiter
// (comma, pipe, tab); an unprintable control character is safe to split
// on unconditionally.
const fieldSep = "\x1f"

// defaultLimit caps history when callers pass limit<=0.
const defaultLimit = 20

// mountPathLookup shells out to `gopass config mounts.<org>.path`. A
// package-level var (same indirection pattern as internal/web's
// requireTouchIDFunc) so tests can stub the mount-aware branch of
// resolveDir without needing a real gopass installation with a
// configured mount.
var mountPathLookup = func(ctx context.Context, org string) (string, error) {
	if _, err := exec.LookPath("gopass"); err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, "gopass", "config",
		fmt.Sprintf("mounts.%s.path", org)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// resolveDir returns the on-disk git repo root that holds path, plus
// whether that repo is a per-org mount. Mount-awareness matters because
// gopass's root.Store strips the mount alias from the on-disk relative
// path before writing files: an entry at logical path "acme/aws/root"
// lives at "aws/root.gpg" relative to the "acme" mount's own repo root,
// not "acme/aws/root.gpg" relative to the top-level store. An empty
// mountPathLookup result means org has no dedicated mount, so the entry
// lives in the default (root) store.
func resolveDir(ctx context.Context, org string) (dir string, orgPrefixStripped bool, err error) {
	if org != "" {
		if p, lookErr := mountPathLookup(ctx, org); lookErr == nil && p != "" {
			return p, true, nil
		}
	}
	dir, err = gopassinit.DefaultStoreDir()
	return dir, false, err
}

// Log returns up to limit revisions for path, most recent first. Fails
// soft — a nil slice and no error — when git is missing, the store
// directory can't be resolved, or the path simply has no history yet.
// History is a nice-to-have display on the entry detail page, not
// something that should turn into a page error; the caller (App.History)
// still distinguishes "no history" from a real policy denial upstream of
// this function.
func Log(ctx context.Context, path string, limit int) ([]Revision, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	org := store.OrgOf(path)
	dir, stripped, err := resolveDir(ctx, org)
	if err != nil || dir == "" {
		return nil, nil
	}
	rel := path
	if stripped {
		rel = strings.TrimPrefix(path, org+"/")
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "log", "--follow",
		"--format=%H"+fieldSep+"%aI"+fieldSep+"%s",
		"-n", strconv.Itoa(limit),
		"--", rel+".gpg").Output()
	if err != nil {
		return nil, nil
	}
	return parseLog(out), nil
}

func parseLog(out []byte) []Revision {
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	revs := make([]Revision, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, fieldSep, 3)
		if len(parts) != 3 {
			continue
		}
		when, perr := time.Parse(time.RFC3339, parts[1])
		if perr != nil {
			continue
		}
		revs = append(revs, Revision{Hash: parts[0], When: when, Message: parts[2]})
	}
	return revs
}
