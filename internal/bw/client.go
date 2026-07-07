package bw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The `bw` binary is invoked as a subprocess in this file. Like
// internal/sync this is an explicit, documented exception to the
// project's library-only rule: Bitwarden has no supported Go client
// library, and the CLI is the sanctioned automation surface of the
// official clients. Secret material (item payloads, session token,
// master password) travels exclusively via stdin and environment
// variables — never via argv, which is ps-visible.

// Runner abstracts bw subprocess execution so tests can substitute a
// stub. It differs from sync.Runner on purpose: bw calls need a stdin
// payload and per-call environment additions.
type Runner interface {
	Run(ctx context.Context, stdin []byte, extraEnv []string, args ...string) ([]byte, error)
}

// ExecRunner is the production Runner, backed by os/exec. Stdout and
// stderr are captured separately: stdout must stay parseable JSON, and
// stderr (progress notices, error text) is only surfaced on failure.
type ExecRunner struct{}

// Run executes `bw args...` with the process environment plus extraEnv.
func (ExecRunner) Run(ctx context.Context, stdin []byte, extraEnv []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "bw", args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("bw %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Vault lock states reported by `bw status`.
const (
	StatusUnauthenticated = "unauthenticated"
	StatusLocked          = "locked"
	StatusUnlocked        = "unlocked"
)

// Status is the JSON payload of `bw status`.
type Status struct {
	ServerURL string `json:"serverUrl"`
	UserEmail string `json:"userEmail"`
	Status    string `json:"status"`
}

// Client wraps the bw CLI. The session token lives only in process
// memory and is handed to every call via the BW_SESSION environment
// variable.
type Client struct {
	r       Runner
	session string
}

// NewClient returns a Client backed by r, falling back to the exec
// runner when r is nil.
func NewClient(r Runner) *Client {
	if r == nil {
		r = ExecRunner{}
	}
	return &Client{r: r}
}

func (c *Client) env() []string {
	if c.session == "" {
		return nil
	}
	return []string{"BW_SESSION=" + c.session}
}

// Status reports the CLI's server and vault lock state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	out, err := c.r.Run(ctx, nil, c.env(), "status")
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(bytes.TrimSpace(out), &st); err != nil {
		return Status{}, fmt.Errorf("parse bw status: %w", err)
	}
	return st, nil
}

// Unlock derives a session token from the master password. The password
// travels via the BW_PASSWORD environment variable of the child process
// only; the resulting token stays in memory.
func (c *Client) Unlock(ctx context.Context, masterPassword string) error {
	out, err := c.r.Run(ctx, nil, []string{"BW_PASSWORD=" + masterPassword},
		"unlock", "--passwordenv", "BW_PASSWORD", "--raw")
	if err != nil {
		return err
	}
	session := strings.TrimSpace(string(out))
	if session == "" {
		return fmt.Errorf("bw unlock returned an empty session token")
	}
	c.session = session
	return nil
}

// EnsureSession makes the client usable: a caller-supplied session
// token (from the BW_SESSION environment) wins when it is still valid;
// otherwise the vault is unlocked with the master password from
// getPassword. Login itself is never automated — it may involve 2FA and
// is a one-time manual setup step.
func (c *Client) EnsureSession(ctx context.Context, envSession string, getPassword func(context.Context) (string, error)) error {
	if envSession != "" {
		c.session = envSession
		st, err := c.Status(ctx)
		if err != nil {
			return err
		}
		if st.Status == StatusUnlocked {
			return nil
		}
		c.session = "" // stale or foreign token — fall through to unlock
	}
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	switch st.Status {
	case StatusUnlocked:
		return nil
	case StatusUnauthenticated:
		return fmt.Errorf("bw is not logged in on this machine — run `bw login` once (server: %s)", st.ServerURL)
	}
	pw, err := getPassword(ctx)
	if err != nil {
		return fmt.Errorf("read bitwarden master password: %w", err)
	}
	return c.Unlock(ctx, pw)
}

// Sync pulls the latest vault state into the CLI's local cache.
func (c *Client) Sync(ctx context.Context) error {
	_, err := c.r.Run(ctx, nil, c.env(), "sync")
	return err
}

// ListFolders returns every folder in the vault (names + ids only — no
// item content).
func (c *Client) ListFolders(ctx context.Context) ([]Folder, error) {
	out, err := c.r.Run(ctx, nil, c.env(), "list", "folders")
	if err != nil {
		return nil, err
	}
	var fs []Folder
	if err := json.Unmarshal(bytes.TrimSpace(out), &fs); err != nil {
		return nil, fmt.Errorf("parse bw folders: %w", err)
	}
	return fs, nil
}

// ListItemsInFolder returns the items of one folder. Push/import only
// ever call this for folders inside the mys namespace, which is what
// keeps the rest of the personal vault unread.
func (c *Client) ListItemsInFolder(ctx context.Context, folderID string) ([]Item, error) {
	out, err := c.r.Run(ctx, nil, c.env(), "list", "items", "--folderid", folderID)
	if err != nil {
		return nil, err
	}
	var its []Item
	if err := json.Unmarshal(bytes.TrimSpace(out), &its); err != nil {
		return nil, fmt.Errorf("parse bw items: %w", err)
	}
	return its, nil
}

// CreateFolder creates a folder and returns it with the server-assigned
// id. Folder ids on the server are random — the deterministic UUIDv5
// ids from FolderID exist only for file exports.
func (c *Client) CreateFolder(ctx context.Context, name string) (Folder, error) {
	payload, err := encodePayload(Folder{Name: name})
	if err != nil {
		return Folder{}, err
	}
	out, err := c.r.Run(ctx, payload, c.env(), "create", "folder")
	if err != nil {
		return Folder{}, err
	}
	var f Folder
	if err := json.Unmarshal(bytes.TrimSpace(out), &f); err != nil {
		return Folder{}, fmt.Errorf("parse bw folder: %w", err)
	}
	return f, nil
}

// CreateItem creates a vault item. The payload goes through stdin.
func (c *Client) CreateItem(ctx context.Context, it Item) (Item, error) {
	payload, err := encodePayload(it)
	if err != nil {
		return Item{}, err
	}
	out, err := c.r.Run(ctx, payload, c.env(), "create", "item")
	if err != nil {
		return Item{}, err
	}
	var created Item
	if err := json.Unmarshal(bytes.TrimSpace(out), &created); err != nil {
		return Item{}, fmt.Errorf("parse bw item: %w", err)
	}
	return created, nil
}

// EditItem replaces the item with the given id. Only the (non-secret)
// item id travels via argv.
func (c *Client) EditItem(ctx context.Context, id string, it Item) error {
	payload, err := encodePayload(it)
	if err != nil {
		return err
	}
	_, err = c.r.Run(ctx, payload, c.env(), "edit", "item", id)
	return err
}

// DeleteItem soft-deletes an item (moves it to the Bitwarden trash).
// There is deliberately no hard-delete: prune must stay recoverable.
func (c *Client) DeleteItem(ctx context.Context, id string) error {
	_, err := c.r.Run(ctx, nil, c.env(), "delete", "item", id)
	return err
}

// encodePayload marshals v and base64-encodes it, the wire format
// `bw create`/`bw edit` expect on stdin.
func encodePayload(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}
