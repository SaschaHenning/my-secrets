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
	"fmt"
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
			"description": "List credential paths, optionally filtered by org (top-level folder).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"org": map[string]any{"type": "string", "description": "Filter by top-level org folder"},
				},
			},
		},
		{
			"name":        "creds_search",
			"description": "Full-text search over credential paths and metadata (not password values).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
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
			Org string `json:"org"`
		}
		_ = json.Unmarshal(p.Arguments, &args)
		paths, err := a.List(ctx, args.Org)
		if err != nil {
			return errorResp(req.ID, -32000, err.Error())
		}
		return okResp(req.ID, textContent(fmt.Sprintf("%d entries\n%s", len(paths), strings.Join(paths, "\n"))))
	case "creds_search":
		var args struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(p.Arguments, &args)
		if args.Query == "" {
			return errorResp(req.ID, -32602, "query is required")
		}
		paths, err := a.Search(ctx, args.Query)
		if err != nil {
			return errorResp(req.ID, -32000, err.Error())
		}
		return okResp(req.ID, textContent(fmt.Sprintf("%d matches\n%s", len(paths), strings.Join(paths, "\n"))))
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
