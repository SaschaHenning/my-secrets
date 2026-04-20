package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
)

// newAuditOnlyApp returns an app with a temp audit log and default policy —
// enough to exercise the MCP wiring without requiring a real gopass store.
func newAuditOnlyApp(t *testing.T) *app.App {
	t.Helper()
	l, err := audit.Open(t.TempDir() + "/audit.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &app.App{Audit: l, Policy: policy.Default(), Override: "claude-code"}
}

func sendAndReceive(t *testing.T, a *app.App, reqs []string) []string {
	t.Helper()
	in := strings.NewReader(strings.Join(reqs, "\n") + "\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), a, in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	return lines
}

func TestInitializeAndToolsList(t *testing.T) {
	a := newAuditOnlyApp(t)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	})
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses (init + tools/list), got %d: %v", len(lines), lines)
	}

	var initResp map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("init: %v (body=%s)", err, lines[0])
	}
	if _, ok := initResp["result"]; !ok {
		t.Errorf("init has no result: %v", initResp)
	}

	var toolsResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &toolsResp); err != nil {
		t.Fatalf("tools: %v", err)
	}
	names := map[string]bool{}
	for _, t := range toolsResp.Result.Tools {
		names[t.Name] = true
	}
	for _, expected := range []string{"creds_list", "creds_search", "creds_get"} {
		if !names[expected] {
			t.Errorf("tools/list is missing %q (got %v)", expected, names)
		}
	}
}

func TestUnknownMethod(t *testing.T) {
	a := newAuditOnlyApp(t)
	lines := sendAndReceive(t, a, []string{`{"jsonrpc":"2.0","id":9,"method":"does_not_exist"}`})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %d", len(lines))
	}
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("expected method-not-found (-32601), got %+v", r.Error)
	}
}

func TestAuditStartEntry(t *testing.T) {
	a := newAuditOnlyApp(t)
	sendAndReceive(t, a, []string{`{"jsonrpc":"2.0","id":1,"method":"ping"}`})
	entries, err := a.Audit.Tail(context.Background(), audit.Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == audit.ActionMCPStart {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected an mcp_start audit entry")
	}
}
