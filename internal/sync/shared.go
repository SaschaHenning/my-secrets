package sync

import (
	"context"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
)

const defaultSharedRepoName = "mys-store-shared"

// SharedProvisionOptions describes one convergent shared-mount setup.
// TeamKeysPath is the normal CLI source. Fingerprints supports callers
// whose public keys are already imported.
type SharedProvisionOptions struct {
	Config       *Config
	Mount        string
	StorePath    string
	TeamKeysPath string
	Fingerprints []string
	RemoteURL    string
	Owner        string
	Repo         string
	RemoteStyle  RemoteStyle
	Runner       Runner
	Now          func() time.Time
}

// SharedProvisionResult is returned only after the mount has been pushed
// successfully. Config is a copy; the input config is never mutated.
type SharedProvisionResult struct {
	Config       *Config
	Mount        string
	StorePath    string
	RemoteURL    string
	TeamKeysPath string
	Fingerprints []string
}

type publicKeyAsset struct {
	relativePath string
	data         []byte
}

// DefaultSharedStorePath returns the conventional sibling of gopass's
// root store under the XDG data directory.
func DefaultSharedStorePath(mount string) (string, error) {
	if err := ValidateSharedMountName(mount); err != nil {
		return "", err
	}
	base := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Abs(filepath.Join(base, "gopass", "stores", mount))
}

// ProvisionSharedMount creates or resumes a shared mount, reconciles it
// with its remote, converges the exact team recipient set, commits the
// team-key manifest, and pushes main. It never saves sync.yaml itself.
func ProvisionSharedMount(ctx context.Context, opts SharedProvisionOptions) (*SharedProvisionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateSharedMountName(opts.Mount); err != nil {
		return nil, err
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	cfg := cloneConfig(opts.Config)
	if previous, ok := cfg.Remote(opts.Mount); ok && !previous.Shared {
		return nil, fmt.Errorf("mount %q is already configured as personal", opts.Mount)
	}

	manifest, assets, targets, err := loadSharedIdentity(ctx, runner, opts)
	if err != nil {
		return nil, err
	}
	ownerFingerprint, err := preflightTeamKeys(ctx, runner, targets)
	if err != nil {
		return nil, err
	}
	targets = ownerFirst(targets, ownerFingerprint)

	release, err := AcquireMountLock(ctx, opts.Mount)
	if err != nil {
		return nil, err
	}
	defer func() { _ = release() }()

	remoteURL, err := ensureSharedRemote(ctx, runner, opts)
	if err != nil {
		return nil, err
	}
	storePath, mounted, err := resolveSharedStorePath(ctx, runner, opts.Mount, opts.StorePath)
	if err != nil {
		return nil, err
	}
	if err := rejectRootStoreCollision(ctx, runner, opts.Mount, storePath); err != nil {
		return nil, err
	}
	if err := prepareSharedStore(storePath, targets[0], mounted); err != nil {
		return nil, err
	}
	if !mounted {
		if _, err := GopassMountAdd(ctx, runner, opts.Mount, storePath); err != nil {
			return nil, fmt.Errorf("attach shared mount %q: %w", opts.Mount, err)
		}
	}
	livePath, err := GopassMountPath(ctx, runner, opts.Mount)
	if err != nil {
		return nil, err
	}
	if !samePath(livePath, storePath) {
		return nil, fmt.Errorf("gopass mount %q resolved to %q, expected %q", opts.Mount, livePath, storePath)
	}
	storePath = livePath

	if err := initialiseSharedGit(ctx, runner, opts.Mount, storePath); err != nil {
		return nil, err
	}
	if err := convergeOrigin(ctx, runner, opts.Mount, remoteURL); err != nil {
		return nil, err
	}
	if err := ReconcileWithRemote(ctx, runner, opts.Mount, targets[0]); err != nil {
		return nil, fmt.Errorf("reconcile shared mount %q: %w", opts.Mount, err)
	}
	if err := reconcileSharedRecipients(ctx, runner, opts.Mount, storePath, targets); err != nil {
		return nil, err
	}
	tracked, manifestPath, err := materializeTeamKeys(storePath, manifest, assets)
	if err != nil {
		return nil, err
	}
	if err := commitSharedMetadata(ctx, runner, opts.Mount, tracked); err != nil {
		return nil, err
	}
	if err := pushSharedWithRetry(ctx, runner, opts.Mount, storePath, targets,
		manifest, assets, tracked); err != nil {
		return nil, err
	}

	if err := cfg.UpdateSharedRemote(opts.Mount, remoteURL); err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	cfg.MarkSynced(opts.Mount, now())
	return &SharedProvisionResult{
		Config:       cfg,
		Mount:        opts.Mount,
		StorePath:    storePath,
		RemoteURL:    remoteURL,
		TeamKeysPath: manifestPath,
		Fingerprints: append([]string(nil), targets...),
	}, nil
}

func cloneConfig(in *Config) *Config {
	if in == nil {
		return &Config{Version: 1}
	}
	out := *in
	out.Remotes = append([]StoreRemote(nil), in.Remotes...)
	if out.Version == 0 {
		out.Version = 1
	}
	return &out
}

func loadSharedIdentity(ctx context.Context, runner Runner, opts SharedProvisionOptions) (*teamkeys.File, []publicKeyAsset, []string, error) {
	if opts.TeamKeysPath != "" && len(opts.Fingerprints) > 0 {
		return nil, nil, nil, fmt.Errorf("use either team-keys.yaml or explicit fingerprints, not both")
	}
	if opts.TeamKeysPath == "" {
		targets, err := normalizeFingerprints(opts.Fingerprints)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(targets) == 0 {
			return nil, nil, nil, fmt.Errorf("shared mount requires team-keys.yaml or at least one fingerprint")
		}
		return nil, nil, targets, nil
	}

	manifestPath, err := filepath.Abs(opts.TeamKeysPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve team key manifest: %w", err)
	}
	manifest, err := teamkeys.Load(manifestPath)
	if err != nil {
		return nil, nil, nil, err
	}
	targets := manifest.Fingerprints()
	assets := make([]publicKeyAsset, 0)
	for _, member := range manifest.Members {
		if member.PublicKey == "" {
			continue
		}
		data, err := teamkeys.ResolvePublicKey(manifestPath, member)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("resolve public key for %s: %w", member.Name, err)
		}
		sourcePath := filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(member.PublicKey))
		fingerprints, err := inspectArmoredPublicKey(ctx, runner, sourcePath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("inspect public key for %s: %w", member.Name, err)
		}
		if len(fingerprints) != 1 || fingerprints[0] != member.Fingerprint {
			return nil, nil, nil, fmt.Errorf(
				"public key for %s contains fingerprints %v, expected only %s",
				member.Name, fingerprints, member.Fingerprint)
		}
		if _, err := runner.Run(ctx, "gpg", "--batch", "--import", sourcePath); err != nil {
			return nil, nil, nil, fmt.Errorf("import public key for %s: %w", member.Name, err)
		}
		assets = append(assets, publicKeyAsset{
			relativePath: member.PublicKey,
			data:         data,
		})
	}
	return manifest, assets, targets, nil
}

func inspectArmoredPublicKey(ctx context.Context, runner Runner, path string) ([]string, error) {
	out, err := runner.Run(ctx, "gpg", "--batch", "--with-colons", "--show-keys", path)
	if err != nil {
		return nil, err
	}
	var fingerprints []string
	expectPrimary := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub":
			expectPrimary = true
		case "sub":
			expectPrimary = false
		case "fpr":
			if expectPrimary && len(fields) > 9 {
				fingerprint, normErr := normalizeFullFingerprint(fields[9])
				if normErr != nil {
					return nil, normErr
				}
				fingerprints = append(fingerprints, fingerprint)
				expectPrimary = false
			}
		}
	}
	if len(fingerprints) == 0 {
		return nil, fmt.Errorf("no primary fingerprint found")
	}
	return fingerprints, nil
}

func normalizeFingerprints(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		fingerprint, err := normalizeFullFingerprint(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		out = append(out, fingerprint)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeFullFingerprint(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 40 {
		return "", fmt.Errorf("fingerprint %q must contain exactly 40 hexadecimal characters", value)
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')) {
			return "", fmt.Errorf("fingerprint %q contains non-hexadecimal characters", value)
		}
	}
	return value, nil
}

func preflightTeamKeys(ctx context.Context, runner Runner, targets []string) (string, error) {
	var ownerFingerprint string
	for _, fingerprint := range targets {
		out, err := runner.Run(ctx, "gpg", "--batch", "--with-colons", "--list-keys", fingerprint)
		if err != nil || !gpgOutputContainsFingerprint(out, fingerprint) {
			if err == nil {
				err = fmt.Errorf("fingerprint not present in gpg output")
			}
			return "", fmt.Errorf("team public key %s is unavailable: %w", fingerprint, err)
		}
		secretOut, secretErr := runner.Run(ctx, "gpg", "--batch", "--with-colons", "--list-secret-keys", fingerprint)
		if ownerFingerprint == "" && secretErr == nil && gpgOutputContainsFingerprint(secretOut, fingerprint) {
			ownerFingerprint = fingerprint
		}
	}
	if ownerFingerprint == "" {
		return "", fmt.Errorf("none of the shared recipients has a local secret key; refusing to create a mount the operator cannot use")
	}
	return ownerFingerprint, nil
}

func ownerFirst(targets []string, owner string) []string {
	out := make([]string, 0, len(targets))
	out = append(out, owner)
	for _, target := range targets {
		if target != owner {
			out = append(out, target)
		}
	}
	return out
}

func gpgOutputContainsFingerprint(out []byte, fingerprint string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" && strings.EqualFold(fields[9], fingerprint) {
			return true
		}
	}
	return false
}

func ensureSharedRemote(ctx context.Context, runner Runner, opts SharedProvisionOptions) (string, error) {
	if remote := strings.TrimSpace(opts.RemoteURL); remote != "" {
		return remote, nil
	}
	owner := strings.TrimSpace(opts.Owner)
	if owner == "" {
		return "", fmt.Errorf("shared remote owner is required when --remote is omitted")
	}
	repo := strings.TrimSpace(opts.Repo)
	if repo == "" {
		repo = defaultSharedRepoName
	}
	style := opts.RemoteStyle
	if style == "" {
		style = DetectRemoteStyle(ctx, runner)
	}
	url, err := BuildRemoteURL(style, owner, repo)
	if err != nil {
		return "", err
	}
	exists, err := GhRepoExists(ctx, runner, owner, repo)
	if err != nil {
		return "", fmt.Errorf("check shared repo %s/%s: %w", owner, repo, err)
	}
	if !exists {
		if _, err := GhRepoCreate(ctx, runner, owner, repo); err != nil {
			return "", fmt.Errorf("create shared repo %s/%s: %w", owner, repo, err)
		}
	}
	return url, nil
}

func resolveSharedStorePath(ctx context.Context, runner Runner, mount, requested string) (string, bool, error) {
	if live, err := GopassMountPath(ctx, runner, mount); err == nil {
		if requested != "" {
			wanted, resolveErr := resolveStorePath(requested)
			if resolveErr != nil {
				return "", false, resolveErr
			}
			if !samePath(live, wanted) {
				return "", false, fmt.Errorf("mount %q already points to %q, not %q", mount, live, wanted)
			}
		}
		return live, true, nil
	}
	if requested == "" {
		var err error
		requested, err = DefaultSharedStorePath(mount)
		if err != nil {
			return "", false, err
		}
	}
	resolved, err := resolveStorePath(requested)
	return resolved, false, err
}

func resolveStorePath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve shared store path: %w", err)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("shared store path must not be a symlink")
		}
		if !info.IsDir() {
			return "", fmt.Errorf("shared store path is not a directory")
		}
		return filepath.EvalSymlinks(absolute)
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("stat shared store path: %w", statErr)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolve shared store parent: %w", err)
		}
		parent = filepath.Dir(absolute)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func rejectRootStoreCollision(ctx context.Context, runner Runner, mount, storePath string) error {
	rootPath, err := GopassMountPath(ctx, runner, DefaultStoreMount)
	if err != nil {
		return fmt.Errorf("resolve personal root store before adding shared mount: %w", err)
	}
	if samePath(rootPath, storePath) || pathContains(rootPath, storePath) {
		return fmt.Errorf("shared store path %q must not be the personal root store or live inside it", storePath)
	}
	rootOrg := filepath.Join(rootPath, mount)
	if _, err := os.Lstat(rootOrg); err == nil {
		return fmt.Errorf("personal root store already contains top-level path %q; refusing to shadow it with a shared mount", mount)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check personal root path %q: %w", mount, err)
	}
	return nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(leftAbs); err == nil {
		leftAbs = resolved
	}
	if resolved, err := filepath.EvalSymlinks(rightAbs); err == nil {
		rightAbs = resolved
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

func prepareSharedStore(storePath, ownerFingerprint string, mounted bool) error {
	if err := os.MkdirAll(storePath, 0o700); err != nil {
		return fmt.Errorf("create shared store: %w", err)
	}
	gpgIDPath := filepath.Join(storePath, ".gpg-id")
	if _, err := os.Stat(gpgIDPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat shared .gpg-id: %w", err)
	}
	if mounted {
		return fmt.Errorf("mounted shared store %q has no .gpg-id", storePath)
	}
	entries, err := os.ReadDir(storePath)
	if err != nil {
		return fmt.Errorf("inspect shared store: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("new shared store path %q is not empty and has no .gpg-id", storePath)
	}
	return atomicWriteFile(gpgIDPath, []byte(ownerFingerprint+"\n"), 0o600)
}

func initialiseSharedGit(ctx context.Context, runner Runner, mount, storePath string) error {
	if _, err := GopassGitInit(ctx, runner, mount); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "already") {
		return fmt.Errorf("initialize git for shared mount %q: %w", mount, err)
	}
	if _, err := GopassGit(ctx, runner, mount, "rev-parse", "--verify", "HEAD"); err != nil {
		files := []string{".gpg-id"}
		if _, statErr := os.Stat(filepath.Join(storePath, ".gitattributes")); statErr == nil {
			files = append(files, ".gitattributes")
		}
		args := append([]string{"add", "--"}, files...)
		if _, err := GopassGit(ctx, runner, mount, args...); err != nil {
			return fmt.Errorf("stage initial shared store files: %w", err)
		}
		if _, err := GopassGit(ctx, runner, mount, "commit", "-m", "Initialize shared store"); err != nil {
			return fmt.Errorf("commit initial shared store: %w", err)
		}
	}
	if _, err := GopassGit(ctx, runner, mount, "branch", "-M", "main"); err != nil {
		return fmt.Errorf("normalize shared store branch: %w", err)
	}
	return nil
}

func convergeOrigin(ctx context.Context, runner Runner, mount, url string) error {
	current, err := GopassGit(ctx, runner, mount, "remote", "get-url", "origin")
	if err == nil {
		if strings.TrimSpace(string(current)) == url {
			return nil
		}
		if _, err := GopassGit(ctx, runner, mount, "remote", "set-url", "origin", url); err != nil {
			return fmt.Errorf("update shared origin: %w", err)
		}
		return nil
	}
	if _, err := GopassGitRemoteAdd(ctx, runner, mount, url); err != nil {
		return fmt.Errorf("add shared origin: %w", err)
	}
	return nil
}

func reconcileSharedRecipients(ctx context.Context, runner Runner, mount, storePath string, targets []string) error {
	current, err := readGPGID(filepath.Join(storePath, ".gpg-id"))
	if err != nil {
		return err
	}
	for _, target := range targets {
		if recipientSetContains(current, target) {
			continue
		}
		if _, err := GopassRecipientsAddConfirmed(ctx, runner, mount, target); err != nil {
			return fmt.Errorf("add shared recipient %s: %w", target, err)
		}
	}
	for _, existing := range current {
		if targetSetContains(targets, existing) {
			continue
		}
		if _, err := GopassRecipientsRemoveConfirmed(ctx, runner, mount, existing); err != nil {
			return fmt.Errorf("remove stale shared recipient %s: %w", existing, err)
		}
	}
	final, err := readGPGID(filepath.Join(storePath, ".gpg-id"))
	if err != nil {
		return err
	}
	for _, target := range targets {
		if !recipientSetContains(final, target) {
			return fmt.Errorf("shared recipient reconciliation did not persist %s", target)
		}
	}
	for _, existing := range final {
		if !targetSetContains(targets, existing) {
			return fmt.Errorf("shared recipient reconciliation left unexpected recipient %s", existing)
		}
	}
	return nil
}

func readGPGID(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read shared .gpg-id: %w", err)
	}
	seen := make(map[string]struct{})
	var recipients []string
	for lineNo, line := range strings.Split(string(data), "\n") {
		value := strings.TrimSpace(line)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
		value = strings.ToUpper(value)
		if len(value) != 16 && len(value) != 40 {
			return nil, fmt.Errorf("invalid recipient on .gpg-id line %d", lineNo+1)
		}
		for _, r := range value {
			if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')) {
				return nil, fmt.Errorf("invalid recipient on .gpg-id line %d", lineNo+1)
			}
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			recipients = append(recipients, value)
		}
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("shared .gpg-id has no recipients")
	}
	return recipients, nil
}

func recipientSetContains(current []string, target string) bool {
	for _, existing := range current {
		if fingerprintIDsMatch(existing, target) {
			return true
		}
	}
	return false
}

func targetSetContains(targets []string, existing string) bool {
	for _, target := range targets {
		if fingerprintIDsMatch(existing, target) {
			return true
		}
	}
	return false
}

func fingerprintIDsMatch(left, right string) bool {
	left = strings.ToUpper(strings.TrimPrefix(left, "0X"))
	right = strings.ToUpper(strings.TrimPrefix(right, "0X"))
	if left == right {
		return true
	}
	if len(left) == 16 && len(right) == 40 {
		return strings.HasSuffix(right, left)
	}
	if len(left) == 40 && len(right) == 16 {
		return strings.HasSuffix(left, right)
	}
	return false
}

func materializeTeamKeys(storePath string, manifest *teamkeys.File, assets []publicKeyAsset) ([]string, string, error) {
	if manifest == nil {
		return nil, "", nil
	}
	tracked := make([]string, 0, len(assets)+1)
	for _, asset := range assets {
		if err := writeSharedRepoFile(storePath, asset.relativePath, asset.data, 0o644); err != nil {
			return nil, "", fmt.Errorf("write shared public key %s: %w", asset.relativePath, err)
		}
		tracked = append(tracked, filepath.ToSlash(asset.relativePath))
	}
	manifestPath := filepath.Join(storePath, teamkeys.Filename)
	if err := teamkeys.Save(manifestPath, manifest); err != nil {
		return nil, "", err
	}
	tracked = append(tracked, teamkeys.Filename)
	sort.Strings(tracked)
	return tracked, manifestPath, nil
}

func writeSharedRepoFile(storePath, relativePath string, data []byte, mode os.FileMode) error {
	root, err := os.OpenRoot(storePath)
	if err != nil {
		return fmt.Errorf("open shared store root: %w", err)
	}
	defer root.Close()

	parent := pathpkg.Dir(relativePath)
	if parent != "." {
		var current string
		for _, segment := range strings.Split(parent, "/") {
			current = pathpkg.Join(current, segment)
			currentPath := filepath.FromSlash(current)
			info, err := root.Lstat(currentPath)
			if os.IsNotExist(err) {
				if err := root.Mkdir(currentPath, 0o700); err != nil && !os.IsExist(err) {
					return fmt.Errorf("create repository-relative directory: %w", err)
				}
				info, err = root.Lstat(currentPath)
			}
			if err != nil {
				return fmt.Errorf("inspect repository-relative directory: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("repository-relative path %q traverses a non-directory or symbolic link", relativePath)
			}
		}
	}

	target := filepath.FromSlash(relativePath)
	if info, err := root.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("repository-relative path %q is not a regular file", relativePath)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect repository-relative file: %w", err)
	}
	file, err := root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open repository-relative file: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func commitSharedMetadata(ctx context.Context, runner Runner, mount string, tracked []string) error {
	if len(tracked) == 0 {
		return nil
	}
	addArgs := append([]string{"add", "--"}, tracked...)
	if _, err := GopassGit(ctx, runner, mount, addArgs...); err != nil {
		return fmt.Errorf("stage shared team keys: %w", err)
	}
	diffArgs := append([]string{"diff", "--cached", "--name-only", "--"}, tracked...)
	out, err := GopassGit(ctx, runner, mount, diffArgs...)
	if err != nil {
		return fmt.Errorf("inspect staged shared team keys: %w", err)
	}
	if len(gopassPayloadLines(out)) == 0 {
		return nil
	}
	if _, err := GopassGit(ctx, runner, mount, "commit", "-m", "Update shared team keys"); err != nil {
		return fmt.Errorf("commit shared team keys: %w", err)
	}
	return nil
}

func gopassPayloadLines(out []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Running '") && strings.Contains(line, "' in ") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func pushSharedWithRetry(ctx context.Context, runner Runner, mount, storePath string,
	targets []string, manifest *teamkeys.File, assets []publicKeyAsset, tracked []string) error {
	if _, err := GopassGit(ctx, runner, mount, "push", "origin", "main"); err == nil {
		return nil
	} else if !isNonFastForward(err) {
		return fmt.Errorf("push shared mount %q: %w", mount, err)
	}

	if err := ReconcileWithRemote(ctx, runner, mount, targets[0]); err != nil {
		return fmt.Errorf("reconcile concurrent shared update: %w", err)
	}
	if err := reconcileSharedRecipients(ctx, runner, mount, storePath, targets); err != nil {
		return err
	}
	if _, _, err := materializeTeamKeys(storePath, manifest, assets); err != nil {
		return err
	}
	if err := commitSharedMetadata(ctx, runner, mount, tracked); err != nil {
		return err
	}
	if _, err := GopassGit(ctx, runner, mount, "push", "origin", "main"); err != nil {
		return fmt.Errorf("push shared mount %q after one reconcile retry: %w", mount, err)
	}
	return nil
}

func isNonFastForward(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "non-fast-forward") ||
		strings.Contains(message, "fetch first") ||
		strings.Contains(message, "rejected")
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
