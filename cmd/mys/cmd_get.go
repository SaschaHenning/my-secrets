package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// getCmd builds the `mys get` subcommand.
func getCmd(requester *string) *cobra.Command {
	var (
		field  string
		reveal bool
		format string
	)
	c := &cobra.Command{
		Use:   "get <path>",
		Short: "Fetch a secret (password masked by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			e, err := a.Get(ctx, args[0])
			if err != nil {
				return err
			}
			return printEntry(cmd.OutOrStdout(), e, field, reveal, format)
		},
	}
	c.Flags().StringVar(&field, "field", "", "print only one field: password | username | url | notes")
	c.Flags().BoolVar(&reveal, "reveal", false, "reveal password in output (default: masked)")
	c.Flags().StringVar(&format, "format", "text", "output format: text | json | env")
	return c
}

func printEntry(w io.Writer, e *store.Entry, field string, reveal bool, format string) error {
	switch format {
	case "json":
		payload := map[string]any{
			"path":           e.Path,
			"org":            e.Org,
			"kind":           e.Kind,
			"username":       e.Username,
			"url":            e.URL,
			"github_project": e.GitHubProject,
			"tags":           e.Tags,
			"notes":          e.Notes,
		}
		if reveal {
			payload["password"] = e.Password
		} else {
			payload["password"] = store.MaskedPassword(e.Password)
		}
		return json.NewEncoder(w).Encode(payload)
	case "env":
		if e.Username != "" {
			fmt.Fprintf(w, "USERNAME=%s\n", shellQuote(e.Username))
		}
		if reveal {
			fmt.Fprintf(w, "PASSWORD=%s\n", shellQuote(e.Password))
		}
		if e.URL != "" {
			fmt.Fprintf(w, "URL=%s\n", shellQuote(e.URL))
		}
		return nil
	}
	// default: text
	if field != "" {
		switch field {
		case "password":
			if reveal {
				fmt.Fprintln(w, e.Password)
			} else {
				fmt.Fprintln(w, store.MaskedPassword(e.Password))
			}
		case "username":
			fmt.Fprintln(w, e.Username)
		case "url":
			fmt.Fprintln(w, e.URL)
		case "notes":
			fmt.Fprintln(w, e.Notes)
		default:
			return fmt.Errorf("unknown field %q", field)
		}
		return nil
	}
	fmt.Fprintf(w, "path:     %s\n", e.Path)
	fmt.Fprintf(w, "org:      %s\n", e.Org)
	fmt.Fprintf(w, "kind:     %s\n", e.Kind)
	fmt.Fprintf(w, "username: %s\n", e.Username)
	fmt.Fprintf(w, "url:      %s\n", e.URL)
	if e.GitHubProject != "" {
		fmt.Fprintf(w, "github:   %s\n", e.GitHubProject)
	}
	if len(e.Tags) > 0 {
		fmt.Fprintf(w, "tags:     %s\n", strings.Join(e.Tags, ", "))
	}
	if e.Notes != "" {
		fmt.Fprintf(w, "notes:    %s\n", e.Notes)
	}
	if reveal {
		fmt.Fprintf(w, "password: %s\n", e.Password)
	} else {
		fmt.Fprintf(w, "password: %s  (use --reveal to show)\n", store.MaskedPassword(e.Password))
	}
	return nil
}

func shellQuote(s string) string {
	if s == "" {
		return "\"\""
	}
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + "\""
}
