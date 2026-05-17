// Package sync manages the optional git-backed sync configuration for
// my-secrets. It persists the list of configured gopass stores and their
// remotes to a YAML state file under ~/.config/my-secrets/sync.yaml and
// provides helpers to run `gopass sync`/`gopass git pull` as subprocesses.
//
// SCOPE ANCHOR: my-secrets is a personal credential manager. Git sync is
// intended to keep a single user's secrets redundant across their own
// devices. It is NOT a sharing mechanism for teams — gopass cannot
// distinguish between humans who share a GPG key. For team credentials,
// use Bitwarden or a hosted vault with per-user identity.
//
// The `gopass` and `gh` binaries are invoked as subprocesses in this
// package. This is an explicit, documented exception to the project's
// library-only rule: the setup/push/pull flows are administrative
// actions that happen outside of normal secret access and do not read
// or write decrypted secret values.
package sync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultStoreMount is the logical name of the primary (root) gopass
// store when the user chose the single-repo layout.
const DefaultStoreMount = "root"

// Layout describes how the user's secrets are split across remotes.
type Layout string

const (
	// LayoutSingle: one git repo holds the entire gopass store.
	LayoutSingle Layout = "single"
	// LayoutPerOrg: every top-level org folder lives in its own repo,
	// attached to the root store as a gopass mount.
	LayoutPerOrg Layout = "per-org"
)

// StoreRemote describes one configured gopass store's git remote.
type StoreRemote struct {
	// Mount is the gopass mount name. For LayoutSingle this is
	// DefaultStoreMount. For LayoutPerOrg this is the org name
	// (e.g. "jasp", "zuhause").
	Mount string `yaml:"mount"`
	// URL is the git remote URL (git@github.com:owner/name.git or
	// https://github.com/owner/name.git).
	URL string `yaml:"url"`
	// LastSync records the last successful push/pull timestamp. Zero
	// value means „never synced".
	LastSync time.Time `yaml:"last_sync,omitempty"`
}

// Config is the persisted sync state.
type Config struct {
	Version int           `yaml:"version"`
	Layout  Layout        `yaml:"layout"`
	Owner   string        `yaml:"owner,omitempty"` // GitHub login used when the repos were created
	Remotes []StoreRemote `yaml:"remotes"`
}

// DefaultPath returns the usual sync-state path:
// ~/.config/my-secrets/sync.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "my-secrets", "sync.yaml"), nil
}

// Load reads the state file. Returns an empty config and no error if the
// file does not exist — a missing file simply means „sync not set up yet".
func Load(path string) (*Config, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Version: 1}, nil
		}
		return nil, fmt.Errorf("read sync config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse sync config: %w", err)
	}
	if c.Version == 0 {
		c.Version = 1
	}
	return &c, nil
}

// Save writes the state file with 0o600 permissions. Creates the parent
// directory with 0o700 if needed.
func Save(path string, c *Config) error {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir sync config dir: %w", err)
	}
	if c.Version == 0 {
		c.Version = 1
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal sync config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write sync config: %w", err)
	}
	return nil
}

// RemoteStyle picks the URL flavour the wizard should emit.
type RemoteStyle string

const (
	// RemoteSSH uses git@github.com:owner/name.git. Preferred when the
	// user has an SSH key on file.
	RemoteSSH RemoteStyle = "ssh"
	// RemoteHTTPS uses https://github.com/owner/name.git. Works without
	// SSH keys but requires a token/credential helper for pushes.
	RemoteHTTPS RemoteStyle = "https"
)

// DetectRemoteStyle asks `gh auth status` which protocol the user's
// GitHub login is configured for and returns a matching RemoteStyle.
// Falls back to HTTPS (the safer default) when gh is missing or the
// output does not contain a protocol line — most corporate setups
// block outbound port 22, so HTTPS is the less surprising default.
func DetectRemoteStyle(ctx context.Context, r Runner) RemoteStyle {
	if r == nil {
		r = ExecRunner{}
	}
	out, err := r.Run(ctx, "gh", "auth", "status")
	if err != nil && len(out) == 0 {
		return RemoteHTTPS
	}
	// gh prints "  - Git operations protocol: https" (or ssh). Scan
	// case-insensitively so formatting changes do not bite us.
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "git operations protocol: ssh") {
		return RemoteSSH
	}
	if strings.Contains(lower, "git operations protocol: https") {
		return RemoteHTTPS
	}
	return RemoteHTTPS
}

// BuildRemoteURL assembles a GitHub repo URL in the requested style.
// Owner and name are normalised (trimmed, no trailing .git).
func BuildRemoteURL(style RemoteStyle, owner, name string) (string, error) {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSuffix(strings.TrimSpace(name), ".git")
	if owner == "" {
		return "", fmt.Errorf("remote url: owner required")
	}
	if name == "" {
		return "", fmt.Errorf("remote url: repo name required")
	}
	switch style {
	case RemoteSSH:
		return fmt.Sprintf("git@github.com:%s/%s.git", owner, name), nil
	case RemoteHTTPS:
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, name), nil
	default:
		return "", fmt.Errorf("remote url: unknown style %q", style)
	}
}

// SingleRepoDefaultName is the default name for the single-repo layout.
const SingleRepoDefaultName = "my-secrets-store"

// PerOrgRepoName returns the default per-org repo name, e.g. "jasp" →
// "jasp-secrets".
func PerOrgRepoName(org string) string {
	return strings.TrimSpace(org) + "-secrets"
}

// UpdateRemote replaces (or appends) the remote entry for the given mount.
func (c *Config) UpdateRemote(mount, url string) {
	for i := range c.Remotes {
		if c.Remotes[i].Mount == mount {
			c.Remotes[i].URL = url
			return
		}
	}
	c.Remotes = append(c.Remotes, StoreRemote{Mount: mount, URL: url})
}

// MarkSynced stamps LastSync=now on the remote for the given mount.
// No-op if the mount is unknown.
func (c *Config) MarkSynced(mount string, at time.Time) {
	for i := range c.Remotes {
		if c.Remotes[i].Mount == mount {
			c.Remotes[i].LastSync = at.UTC()
			return
		}
	}
}

// Runner abstracts subprocess execution so tests can substitute a stub.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner is the production Runner, backed by os/exec.
type ExecRunner struct{}

// Run executes name with args, capturing combined stdout+stderr.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// LoadConfig is a convenience wrapper around Load("") that always reads
// the default sync config path. Returns an empty *Config (no remotes) if
// the file does not exist — callers can treat „no remotes" as „sync not
// set up".
func LoadConfig() (*Config, error) {
	return Load("")
}

// PushAll iterates over every configured remote and runs `gopass sync`
// against it. The context controls timeout/cancellation for the whole
// batch; if one remote fails, the error is returned immediately and
// subsequent remotes are skipped. Output is discarded — this function
// is intended for automated hooks, not interactive reporting.
func PushAll(ctx context.Context, r Runner) error {
	if r == nil {
		r = ExecRunner{}
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Remotes) == 0 {
		return nil
	}
	for _, rem := range cfg.Remotes {
		if _, err := GopassSync(ctx, r, rem.Mount); err != nil {
			return fmt.Errorf("sync %s: %w", rem.Mount, err)
		}
	}
	return nil
}

// IsAutoSyncDisabled reports whether the MYS_AUTO_SYNC env var is set to
// a value that means „off": "0", "false", "no", "off" (case-insensitive).
// Any other value — including the empty string (unset) — means enabled.
func IsAutoSyncDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MYS_AUTO_SYNC")))
	switch v {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

// AutoSync performs a best-effort `gopass sync` for every configured
// remote. The context MUST already carry the caller's timeout (5 s in
// the App layer).
//
// Returns:
//   - skipped=true, err=nil when no sync should happen (no config file,
//     no remotes configured, or MYS_AUTO_SYNC=0/false/off). Callers
//     should NOT write an audit row in the skipped case.
//   - skipped=false, err=nil on a successful push of every remote.
//   - skipped=false, err!=nil if any remote failed (timeout, network,
//     auth). The local gopass commit has already happened — the caller
//     is expected to surface a warning and record an audit row with
//     result=error but keep the CLI exit code at 0.
//
// The trigger argument is a free-form label ("add jasp/github",
// "rotate zuhause/router") that the App layer uses to build the audit
// reason; AutoSync itself does not consume it but accepting it keeps the
// call site readable.
func AutoSync(ctx context.Context, r Runner, trigger string) (skipped bool, err error) {
	_ = trigger // used by callers for audit reason construction
	if IsAutoSyncDisabled() {
		return true, nil
	}
	cfg, cerr := LoadConfig()
	if cerr != nil {
		// A corrupt config is a real error — surface it. A missing file
		// is handled inside Load() and returns an empty Config.
		return false, cerr
	}
	if cfg == nil || len(cfg.Remotes) == 0 {
		return true, nil
	}
	if err := PushAll(ctx, r); err != nil {
		return false, err
	}
	return false, nil
}

// GopassSync runs `gopass sync` (push + pull) for every configured store.
// When mount is empty, syncs all mounts. Returns the combined output.
func GopassSync(ctx context.Context, r Runner, mount string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	args := []string{"sync"}
	if mount != "" && mount != DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	return r.Run(ctx, "gopass", args...)
}

// GopassGitPull runs `gopass git pull` for the given mount.
//
// A bare `git pull` requires upstream tracking on the current branch.
// A store cloned or `gopass git init`-ed without `--set-upstream` (or
// one whose branch.<name>.* config was lost) has none, and git then
// aborts with „There is no tracking information for the current
// branch" → exit 1, which surfaces to the user as a bare
// „Error: exit status 1". To stay robust regardless of tracking
// config we resolve the current branch and pull explicitly from
// `origin <branch>`.
func GopassGitPull(ctx context.Context, r Runner, mount string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	branch := currentGitBranch(ctx, r, mount)
	if branch == "" {
		// Detached HEAD or branch lookup failed. A bare `git pull`
		// here would reproduce the exact opaque „exit status 1" this
		// function exists to eliminate, so fail with a descriptive
		// error instead of re-hitting the same wall.
		m := mount
		if m == "" {
			m = DefaultStoreMount
		}
		return nil, fmt.Errorf("gopass store %q has no checked-out branch (detached HEAD) — cannot pull; check out a branch or set upstream tracking", m)
	}
	return GopassGit(ctx, r, mount, "pull", "origin", branch)
}

// currentGitBranch returns the checked-out branch name of the mount's
// embedded git repo, or "" if HEAD is detached or the lookup fails.
func currentGitBranch(ctx context.Context, r Runner, mount string) string {
	out, err := GopassGit(ctx, r, mount, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return ""
	}
	// gopass prefixes git subcommand output with a „⚠ Running '<cmd>'
	// in <path>..." banner on stdout (same quirk handled in
	// internal/doctor). Strip those banner lines and take the last
	// real line as the branch name — otherwise the banner text leaks
	// into the refspec and `git pull origin <banner>` fails with
	// „fatal: invalid refspec".
	var branch string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.Contains(l, "Running '") && strings.Contains(l, "' in ") {
			continue
		}
		branch = l
	}
	if branch == "" || branch == "HEAD" {
		return ""
	}
	return branch
}

// GopassGitInit runs `gopass git init` on the given mount.
func GopassGitInit(ctx context.Context, r Runner, mount string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	args := []string{"git"}
	if mount != "" && mount != DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, "init")
	return r.Run(ctx, "gopass", args...)
}

// GopassGit forwards arbitrary arguments to `gopass git` for the given
// mount. Needed by the reconcile flow, which issues fetch / rev-parse /
// merge / reset / push against the mount's embedded git repo.
func GopassGit(ctx context.Context, r Runner, mount string, gitArgs ...string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	args := []string{"git"}
	if mount != "" && mount != DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, gitArgs...)
	return r.Run(ctx, "gopass", args...)
}

// GopassRecipientsAdd runs `gopass recipients add --store <mount> <fpr>`.
// Used by the reconcile flow to re-assert the current key as a reader
// after adopting an existing remote store.
func GopassRecipientsAdd(ctx context.Context, r Runner, mount, fingerprint string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	args := []string{"recipients", "add"}
	if mount != "" && mount != DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, fingerprint)
	return r.Run(ctx, "gopass", args...)
}

// GopassGitRemoteAdd runs `gopass git remote add <name> <url>` on the
// given mount.
//
// Older gopass versions exposed `--remote` and `--url` flags; current
// releases forward everything after `gopass git` straight to `git`,
// which expects positional `<name> <url>`. Using the flag form against
// a recent gopass fails with "unknown option `remote'" from git itself,
// so we build the positional form here.
func GopassGitRemoteAdd(ctx context.Context, r Runner, mount, url string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	args := []string{"git"}
	if mount != "" && mount != DefaultStoreMount {
		args = append(args, "--store", mount)
	}
	args = append(args, "remote", "add", "origin", url)
	return r.Run(ctx, "gopass", args...)
}

// ReconcileWithRemote brings a freshly-initialised local mount into a
// state where the subsequent `git push` will succeed, regardless of
// whether the remote is empty, in sync, ahead, or has a divergent
// history (the „unrelated histories" case).
//
// The four possible states and their treatment:
//
//	(a) Remote has no main branch yet               → nothing to do.
//	(b) origin/main is an ancestor of HEAD          → nothing to do.
//	(c) HEAD is an ancestor of origin/main          → fast-forward merge.
//	(d) Divergent histories                         → see below.
//
// For divergent histories we distinguish two sub-cases based on whether
// the local mount is „pristine" (nothing but the files a `gopass git
// init` leaves behind):
//
//	(d1) pristine → adopt the remote: `reset --hard origin/main`, then
//	     `gopass recipients add <fingerprint>` so that subsequent
//	     `gopass insert` calls encrypt to the current key as well.
//	(d2) non-pristine → merge with `--allow-unrelated-histories`. If
//	     the merge conflicts, a clear error is returned and the caller
//	     must resolve manually — we refuse to silently discard user
//	     content.
//
// fingerprint is required in the adopt path (d1). The other paths
// ignore it; pass "" if it is not available and no adopt will happen
// because the local mount already has user content.
func ReconcileWithRemote(ctx context.Context, r Runner, mount, fingerprint string) error {
	if r == nil {
		r = ExecRunner{}
	}
	// `gopass git fetch origin` is a no-op if the remote has no refs.
	if _, err := GopassGit(ctx, r, mount, "fetch", "origin"); err != nil {
		return fmt.Errorf("git fetch origin: %w", err)
	}
	// Does origin/main exist?
	if _, err := GopassGit(ctx, r, mount, "rev-parse", "--quiet", "--verify", "origin/main"); err != nil {
		// (a) empty remote — nothing to reconcile.
		return nil
	}
	// (b) origin/main is ancestor of HEAD → local already carries the
	// remote content, push will fast-forward.
	if _, err := GopassGit(ctx, r, mount, "merge-base", "--is-ancestor", "origin/main", "HEAD"); err == nil {
		return nil
	}
	// (c) HEAD is ancestor of origin/main → remote is ahead, fast-forward.
	if _, err := GopassGit(ctx, r, mount, "merge-base", "--is-ancestor", "HEAD", "origin/main"); err == nil {
		if _, err := GopassGit(ctx, r, mount, "merge", "--ff-only", "origin/main"); err != nil {
			return fmt.Errorf("fast-forward to origin/main: %w", err)
		}
		return nil
	}
	// (d) divergent. Pristine or not?
	pristine, err := isMountPristine(ctx, r, mount)
	if err != nil {
		return fmt.Errorf("check pristine state: %w", err)
	}
	if pristine {
		// (d1) adopt remote — we have nothing locally worth keeping.
		if _, err := GopassGit(ctx, r, mount, "reset", "--hard", "origin/main"); err != nil {
			return fmt.Errorf("reset to origin/main: %w", err)
		}
		if fingerprint != "" {
			// Add this key as a reader on top of whatever recipients
			// the remote store already had. gopass writes a commit
			// for this, so the push below has fresh local content.
			if _, err := GopassRecipientsAdd(ctx, r, mount, fingerprint); err != nil {
				return fmt.Errorf("add recipient %s after adopt: %w", fingerprint, err)
			}
		}
		return nil
	}
	// (d2) non-pristine divergence — try an unrelated-histories merge.
	// Conflicts remain in the working tree; surface them so the user
	// can resolve manually rather than losing data to a reset.
	if _, err := GopassGit(ctx, r, mount, "merge", "--allow-unrelated-histories", "--no-edit",
		"-m", "Merge remote store into local (mys reconcile)", "origin/main"); err != nil {
		return fmt.Errorf("merge remote with local content: %w "+
			"(resolve conflicts in the gopass store, then re-run `mys sync setup`)", err)
	}
	return nil
}

// isMountPristine reports whether the mount contains only the files a
// fresh `gopass git init` produces: .gpg-id, .gitattributes, and
// entries under .public-keys/. Any .gpg file or extra top-level
// directory means the user has started adding real secrets and we
// must NOT adopt the remote via reset --hard.
func isMountPristine(ctx context.Context, r Runner, mount string) (bool, error) {
	out, err := GopassGit(ctx, r, mount, "ls-files")
	if err != nil {
		return false, err
	}
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.HasSuffix(f, ".gpg") {
			return false, nil
		}
		switch {
		case f == ".gpg-id", f == ".gitattributes":
			continue
		case strings.HasPrefix(f, ".public-keys/"):
			continue
		default:
			return false, nil
		}
	}
	return true, nil
}

// GopassMountAdd adds a new gopass mount at <path> under <name>.
func GopassMountAdd(ctx context.Context, r Runner, name, path string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	return r.Run(ctx, "gopass", "mounts", "add", name, path)
}

// GhRepoCreate creates a private GitHub repo owned by <owner>/<name> via
// the `gh` CLI. If `gh` is missing or unauthenticated, an error with a
// clear install hint is returned.
func GhRepoCreate(ctx context.Context, r Runner, owner, name string) ([]byte, error) {
	if r == nil {
		r = ExecRunner{}
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return nil, fmt.Errorf("gh CLI not found — install via `brew install gh` and run `gh auth login`")
	}
	slug := owner + "/" + name
	return r.Run(ctx, "gh", "repo", "create", slug, "--private", "--confirm")
}

// GhCurrentUser returns the login name of the authenticated `gh` user.
func GhCurrentUser(ctx context.Context, r Runner) (string, error) {
	if r == nil {
		r = ExecRunner{}
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return "", fmt.Errorf("gh CLI not found — install via `brew install gh` and run `gh auth login`")
	}
	out, err := r.Run(ctx, "gh", "api", "user", "--jq", ".login")
	if err != nil {
		return "", fmt.Errorf("gh api user: %w (run `gh auth login`)", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GhRepoExists checks whether <owner>/<name> already exists and is
// reachable by the authenticated user. A non-nil error distinguishes
// „repo not found" from „gh unavailable".
func GhRepoExists(ctx context.Context, r Runner, owner, name string) (bool, error) {
	if r == nil {
		r = ExecRunner{}
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return false, fmt.Errorf("gh CLI not found — install via `brew install gh`")
	}
	slug := owner + "/" + name
	_, err := r.Run(ctx, "gh", "repo", "view", slug, "--json", "name")
	if err != nil {
		// `gh repo view` exits non-zero for „not found"; treat that as
		// „does not exist" but surface other errors (auth, network).
		msg := err.Error()
		if strings.Contains(msg, "Could not resolve") || strings.Contains(msg, "not found") || strings.Contains(msg, "HTTP 404") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
