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
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
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

// newFakeApp wires up an app backed by the in-memory fake store. The default
// policy denies AI callers on private/**, matching production.
func newFakeApp(t *testing.T, entries ...*store.Entry) (*app.App, *fake.Store) {
	t.Helper()
	l, err := audit.Open(t.TempDir() + "/audit.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := fake.NewWithEntries(entries...)
	return &app.App{Store: f, Audit: l, Policy: policy.Default(), Override: "claude-code"}, f
}

func sendAndReceive(t *testing.T, a *app.App, reqs []string) []string {
	t.Helper()
	in := strings.NewReader(strings.Join(reqs, "\n") + "\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), a, in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	trim := strings.TrimSpace(out.String())
	if trim == "" {
		return nil
	}
	return strings.Split(trim, "\n")
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

func TestPing(t *testing.T) {
	a := newAuditOnlyApp(t)
	lines := sendAndReceive(t, a, []string{`{"jsonrpc":"2.0","id":42,"method":"ping"}`})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %d", len(lines))
	}
	var r struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error != nil {
		t.Errorf("unexpected error: %v", r.Error)
	}
	if r.Result == nil {
		t.Error("want result object")
	}
}

func TestParseError(t *testing.T) {
	a := newAuditOnlyApp(t)
	lines := sendAndReceive(t, a, []string{`not-json-at-all`})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %d", len(lines))
	}
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != -32700 {
		t.Errorf("want parse error -32700, got %+v", r.Error)
	}
}

func TestInitializeNotification_NoResponse(t *testing.T) {
	a := newAuditOnlyApp(t)
	// A request with no id is a notification; we should emit no response.
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","method":"initialize"}`,
	})
	if len(lines) != 0 {
		t.Errorf("notification must not get a response, got %v", lines)
	}
}

func TestToolsCall_CredsList(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/github", Password: "p"},
		&store.Entry{Path: "jasp/aws", Password: "p"},
		&store.Entry{Path: "private/bank", Password: "p"},
	)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_list","arguments":{"org":"jasp"}}}`,
	})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %d", len(lines))
	}
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	text := r.Result.Content[0].Text
	if !strings.Contains(text, "jasp/github") || !strings.Contains(text, "jasp/aws") {
		t.Errorf("missing paths in list output: %q", text)
	}
	if strings.Contains(text, "private/bank") {
		t.Errorf("policy-denied path must not appear: %q", text)
	}
}

func TestToolsCall_CredsSearch(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/github", Username: "alice", Password: "p"},
		&store.Entry{Path: "private/bank", Username: "alice", Password: "p"},
	)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_search","arguments":{"query":"alice"}}}`,
	})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %d", len(lines))
	}
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	text := r.Result.Content[0].Text
	if !strings.Contains(text, "jasp/github") {
		t.Errorf("expected jasp/github in search output: %q", text)
	}
	if strings.Contains(text, "private/bank") {
		t.Errorf("policy-denied path must not appear in search: %q", text)
	}
}

func TestToolsCall_CredsSearch_MissingQuery(t *testing.T) {
	a, _ := newFakeApp(t)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_search","arguments":{}}}`,
	})
	var r struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("want invalid-params, got %+v", r.Error)
	}
}

func TestToolsCall_CredsGet_OK(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/github", Username: "alice", URL: "https://github.com", Password: "p1", Tags: []string{"work"}, Notes: "n"},
	)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_get","arguments":{"path":"jasp/github"}}}`,
	})
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	text := r.Result.Content[0].Text
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("get output not JSON: %v (body=%q)", err, text)
	}
	if payload["username"] != "alice" {
		t.Errorf("username = %v", payload["username"])
	}
	if payload["password"] != "p1" {
		t.Errorf("password = %v", payload["password"])
	}
}

func TestToolsCall_CredsGet_Denied(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "private/bank", Password: "p"},
	)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_get","arguments":{"path":"private/bank"}}}`,
	})
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	text := r.Result.Content[0].Text
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("denied output not JSON: %v (body=%q)", err, text)
	}
	if payload["denied"] != true {
		t.Errorf("want denied=true, got %v", payload)
	}
	// The full reason is redacted — only a generic message is returned.
	if reason, _ := payload["reason"].(string); !strings.Contains(reason, "access denied") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestToolsCall_CredsGet_MissingPath(t *testing.T) {
	a, _ := newFakeApp(t)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_get","arguments":{}}}`,
	})
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("want invalid-params, got %+v", r.Error)
	}
}

func TestToolsCall_UnknownTool(t *testing.T) {
	a, _ := newFakeApp(t)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"does_not_exist"}}`,
	})
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("want method-not-found, got %+v", r.Error)
	}
}

func TestToolsCall_BadParams(t *testing.T) {
	a, _ := newFakeApp(t)
	// params is not a valid object → JSON unmarshal fails.
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`,
	})
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("want invalid-params (-32602), got %+v", r.Error)
	}
}

// unmarshalContentJSON extracts and parses the JSON payload out of the
// first content item of an MCP tool response. Both creds_list and
// creds_search return structured JSON wrapped in a text-content envelope.
func unmarshalContentJSON(t *testing.T, line string) map[string]any {
	t.Helper()
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatalf("unmarshal outer: %v (line=%s)", err, line)
	}
	if len(r.Result.Content) == 0 {
		t.Fatalf("no content in response: %s", line)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(r.Result.Content[0].Text), &payload); err != nil {
		t.Fatalf("unmarshal inner: %v (text=%s)", err, r.Result.Content[0].Text)
	}
	return payload
}

func TestToolsCall_CredsSearch_SimilarOnEmptyMatches(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/site", Domain: "jasp.eu", Password: "p"},
		&store.Entry{Path: "jasp/mail", Domain: "mail.jasp.eu", Password: "p"},
	)
	// "jazp.eu" has no direct substring match but should surface jasp.eu
	// in similar[] via MatchDomain's fuzzy tier.
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_search","arguments":{"query":"jazp.eu"}}}`,
	})
	payload := unmarshalContentJSON(t, lines[0])
	// matches may be empty (nothing contains "jazp.eu" as substring).
	similar, ok := payload["similar"].([]any)
	if !ok {
		t.Fatalf("similar field missing or wrong type: %v", payload["similar"])
	}
	var foundFuzzy bool
	for _, item := range similar {
		m := item.(map[string]any)
		if m["path"] == "jasp/site" && m["tier"] == "fuzzy" {
			foundFuzzy = true
			if _, hasPw := m["password"]; hasPw {
				t.Error("similar entry must not contain a password field")
			}
		}
	}
	if !foundFuzzy {
		t.Errorf("expected fuzzy match for jasp/site in similar, got %+v", similar)
	}
}

func TestToolsCall_CredsSearch_NoSimilarWhenMatchesPresent(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/github", Domain: "github.com", Username: "alice", Password: "p"},
	)
	// include_similar defaults to false because matches are non-empty —
	// the payload should then have matches but no similar array.
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_search","arguments":{"query":"alice"}}}`,
	})
	payload := unmarshalContentJSON(t, lines[0])
	if _, ok := payload["similar"]; ok {
		t.Errorf("similar must be absent on non-empty matches, got %v", payload["similar"])
	}
}

func TestToolsCall_CredsList_DomainWithSimilar(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/aws", Domain: "aws.amazon.com", Password: "p"},
		&store.Entry{Path: "jasp/site", Domain: "jasp.eu", Password: "p"},
	)
	// Query "amazon" — substring tier, so it only surfaces in similar.
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_list","arguments":{"domain":"amazon","include_similar":true}}}`,
	})
	payload := unmarshalContentJSON(t, lines[0])
	similar, ok := payload["similar"].([]any)
	if !ok {
		t.Fatalf("similar missing: %v", payload)
	}
	if len(similar) == 0 {
		t.Fatal("expected at least one similar entry")
	}
	// Tier must be set, password must not leak.
	m := similar[0].(map[string]any)
	if m["tier"] != "substring" {
		t.Errorf("tier = %v, want substring", m["tier"])
	}
	if _, has := m["password"]; has {
		t.Error("password must not appear in similar")
	}
}

func TestToolsCall_CredsList_DomainExactMatch(t *testing.T) {
	a, _ := newFakeApp(t,
		&store.Entry{Path: "jasp/site", Domain: "jasp.eu", Password: "p"},
		&store.Entry{Path: "jasp/mail", Domain: "mail.jasp.eu", Password: "p"},
	)
	lines := sendAndReceive(t, a, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"creds_list","arguments":{"domain":"jasp.eu"}}}`,
	})
	payload := unmarshalContentJSON(t, lines[0])
	matches, ok := payload["matches"].([]any)
	if !ok {
		t.Fatalf("matches missing: %v", payload)
	}
	if len(matches) != 2 {
		t.Fatalf("want 2 matches (exact + subdomain), got %d: %+v", len(matches), matches)
	}
	for _, item := range matches {
		m := item.(map[string]any)
		if _, has := m["password"]; has {
			t.Error("password must not appear in matches either")
		}
	}
}

func TestEmptyLinesSkipped(t *testing.T) {
	a := newAuditOnlyApp(t)
	// Interleave blank lines. Only the real request should produce output.
	in := strings.NewReader("\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), a, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected exactly one response, got %d: %v", len(lines), lines)
	}
}
