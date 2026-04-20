// Package mcp implements a minimal Model Context Protocol server over stdio.
// Only the handful of methods needed for credential access are supported:
//
//	initialize        — capability handshake
//	tools/list        — advertise available tools
//	tools/call        — dispatch to creds.list / creds.search / creds.get
//
// This is intentionally tiny (single file, no external MCP SDK) so the MVP
// stays maintainable. It speaks JSON-RPC 2.0 over newline-delimited JSON on
// stdin/stdout.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
)

// Serve blocks, reading JSON-RPC requests from in and writing responses to
// out, until in returns io.EOF or ctx is cancelled.
func Serve(ctx context.Context, a *app.App, in io.Reader, out io.Writer) error {
	a.AuditMCPStart(ctx)
	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(errorResp(nil, -32700, "parse error: "+err.Error()))
			continue
		}
		resp := handle(ctx, a, &req)
		if resp != nil {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func errorResp(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func okResp(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// handle dispatches a single request. Notifications (no id) return nil.
func handle(ctx context.Context, a *app.App, req *rpcRequest) *rpcResponse {
	notification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		if notification {
			return nil
		}
		return okResp(req.ID, map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "my-secrets",
				"version": "0.1.0",
			},
		})

	case "notifications/initialized", "initialized":
		return nil

	case "tools/list":
		if notification {
			return nil
		}
		return okResp(req.ID, map[string]any{
			"tools": toolDefs(),
		})

	case "tools/call":
		if notification {
			return nil
		}
		return handleToolCall(ctx, a, req)

	case "ping":
		if notification {
			return nil
		}
		return okResp(req.ID, map[string]any{})
	}

	if notification {
		return nil
	}
	return errorResp(req.ID, -32601, "method not found: "+req.Method)
}

func toolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "creds_list",
			"description": "List credential paths, optionally filtered by org or by domain. When filtering by domain, the response has a structured { matches, similar } shape so the AI can spot typos and partial-URL queries without seeing any password values.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"org":             map[string]any{"type": "string", "description": "Filter by top-level org folder"},
					"domain":          map[string]any{"type": "string", "description": "Filter by domain; exact+subdomain by default, include similar via include_similar"},
					"include_similar": map[string]any{"type": "boolean", "description": "With domain: also return substring + fuzzy matches as similar[]"},
				},
			},
		},
		{
			"name":        "creds_search",
			"description": "Full-text search over credential paths and metadata (not password values). When matches are empty, similar[] returns domain-adjacent entries with a tier (substring, fuzzy) and a hint so the caller can correct a typo without leaking passwords.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":           map[string]any{"type": "string"},
					"include_similar": map[string]any{"type": "boolean", "description": "Always include similar[]; default is true only when matches is empty"},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "creds_get",
			"description": "Fetch a single credential by path. Returns metadata plus the password value. Subject to scope policy — denied calls return { denied: true, reason }.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
				"required": []string{"path"},
			},
		},
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func handleToolCall(ctx context.Context, a *app.App, req *rpcRequest) *rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errorResp(req.ID, -32602, "invalid params: "+err.Error())
	}
	switch p.Name {
	case "creds_list":
		var args struct {
			Org            string `json:"org"`
			Domain         string `json:"domain"`
			IncludeSimilar *bool  `json:"include_similar,omitempty"`
		}
		_ = json.Unmarshal(p.Arguments, &args)
		if args.Domain != "" {
			return handleDomainQuery(ctx, a, req.ID, args.Domain, args.IncludeSimilar)
		}
		paths, err := a.List(ctx, args.Org)
		if err != nil {
			return errorResp(req.ID, -32000, err.Error())
		}
		payload := map[string]any{
			"matches": paths,
			"count":   len(paths),
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return okResp(req.ID, textContent(string(b)))
	case "creds_search":
		var args struct {
			Query          string `json:"query"`
			IncludeSimilar *bool  `json:"include_similar,omitempty"`
		}
		_ = json.Unmarshal(p.Arguments, &args)
		if args.Query == "" {
			return errorResp(req.ID, -32602, "query is required")
		}
		paths, err := a.Search(ctx, args.Query)
		if err != nil {
			return errorResp(req.ID, -32000, err.Error())
		}
		// include_similar default: true when matches are empty, false otherwise.
		// An AI caller gets a useful "did you mean?" when its literal query
		// came up empty, but we do not fetch similar entries unnecessarily
		// on happy-path queries that already hit.
		wantSimilar := len(paths) == 0
		if args.IncludeSimilar != nil {
			wantSimilar = *args.IncludeSimilar
		}
		payload := map[string]any{
			"matches": paths,
			"count":   len(paths),
		}
		if wantSimilar {
			// Use the query as a domain hint. We do not require that the
			// query IS a domain — if it cannot be normalised or nothing
			// matches, similar is simply an empty array.
			_, sim, derr := a.SearchByDomain(ctx, args.Query, true)
			if derr == nil {
				payload["similar"] = renderSimilar(sim)
			} else {
				payload["similar"] = []any{}
			}
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return okResp(req.ID, textContent(string(b)))
	case "creds_get":
		var args struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(p.Arguments, &args)
		if args.Path == "" {
			return errorResp(req.ID, -32602, "path is required")
		}
		e, err := a.Get(ctx, args.Path)
		if err != nil {
			var denied *app.ErrDenied
			if errors.As(err, &denied) {
				// Return a generic reason to the AI caller so the
				// policy shape cannot be enumerated via denial oracle.
				// The full reason is still recorded in the audit log.
				b, _ := json.Marshal(map[string]any{
					"denied": true,
					"reason": "access denied by scope policy",
					"path":   denied.Path,
				})
				return okResp(req.ID, textContent(string(b)))
			}
			return errorResp(req.ID, -32000, err.Error())
		}
		payload := map[string]any{
			"path":           e.Path,
			"org":            e.Org,
			"kind":           e.Kind,
			"username":       e.Username,
			"url":            e.URL,
			"github_project": e.GitHubProject,
			"tags":           e.Tags,
			"notes":          e.Notes,
			"password":       e.Password,
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return okResp(req.ID, textContent(string(b)))
	}
	return errorResp(req.ID, -32601, "unknown tool: "+p.Name)
}

// textContent wraps a string in MCP's content-array format.
func textContent(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}
}

// handleDomainQuery is shared by creds_list (when a domain arg is passed)
// and creds_search (implicitly). The response is always structured as
// { matches, similar } — matches is exact + subdomain, similar is the
// substring + fuzzy tier with tier + hint attached so the AI caller can
// reason about its near-miss. Passwords never appear in either list.
func handleDomainQuery(ctx context.Context, a *app.App, id json.RawMessage, query string, includeSimilar *bool) *rpcResponse {
	wantSimilar := true
	if includeSimilar != nil {
		wantSimilar = *includeSimilar
	}
	matches, sim, err := a.SearchByDomain(ctx, query, wantSimilar)
	if err != nil {
		return errorResp(id, -32000, err.Error())
	}
	payload := map[string]any{
		"matches": renderMatches(matches),
		"count":   len(matches),
	}
	if wantSimilar {
		payload["similar"] = renderSimilar(sim)
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return okResp(id, textContent(string(b)))
}

// renderMatches turns DomainMatch hits into a minimal, password-free
// representation suitable for AI consumption. We include the path, tier,
// and hint — everything else (username, url, etc.) is available via a
// follow-up creds_get that goes through the full policy + audit pipeline.
func renderMatches(ms []app.DomainMatch) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, map[string]any{
			"path": m.Entry.Path,
			"tier": m.Tier,
			"hint": m.Hint,
		})
	}
	return out
}

// renderSimilar has the same shape as renderMatches but lives in its
// own function so the payload audit trail makes it obvious: similar is
// never allowed to contain password values, period.
func renderSimilar(ms []app.DomainMatch) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, map[string]any{
			"path": m.Entry.Path,
			"tier": m.Tier,
			"hint": m.Hint,
		})
	}
	return out
}
