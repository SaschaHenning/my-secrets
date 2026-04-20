package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/rotation"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// fieldKeyRe is the validation rule for custom field keys. We keep the
// allowed shape tight — lowercase alphanumerics plus underscore, ≤ 31
// chars, must start with a letter — so the serialised form on disk and
// in MCP output remains predictable. Users putting emoji or punctuation
// into keys would make later diff review harder for no real win.
var fieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// addCmd builds the `mys add` subcommand.
func addCmd(requester *string) *cobra.Command {
	var (
		kind                                     string
		username, url, domain, githubProj, notes string
		tagsRaw                                  string
		fieldsRaw                                []string
		rotateAfter                              string
	)
	c := &cobra.Command{
		Use:   "add <path>",
		Short: "Add or overwrite an entry; reads the password from stdin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Validate the rotation policy string (if any) before we
			// prompt for the password — refusing a typo early avoids
			// asking the user to retype a long secret.
			if rotateAfter != "" {
				if _, perr := rotation.ParseDuration(rotateAfter); perr != nil {
					return perr
				}
			}
			fields, err := parseFieldFlags(fieldsRaw)
			if err != nil {
				return err
			}
			pw, err := readPasswordStdin(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			e := &store.Entry{
				Path:          args[0],
				Org:           store.OrgOf(args[0]),
				Kind:          kind,
				Username:      username,
				URL:           url,
				Domain:        domain,
				GitHubProject: githubProj,
				Notes:         notes,
				Fields:        fields,
				Password:      pw,
				RotateAfter:   rotateAfter,
			}
			if tagsRaw != "" {
				for _, t := range strings.Split(tagsRaw, ",") {
					e.Tags = append(e.Tags, strings.TrimSpace(t))
				}
			}
			if err := a.Add(ctx, e); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %s\n", e.Path)
			return nil
		},
	}
	c.Flags().StringVar(&kind, "kind", store.KindPassword, "kind of secret")
	c.Flags().StringVar(&username, "user", "", "username")
	c.Flags().StringVar(&url, "url", "", "URL")
	c.Flags().StringVar(&domain, "domain", "", "canonical host (defaults to the host parsed from --url)")
	c.Flags().StringVar(&githubProj, "github", "", "related GitHub project (owner/name)")
	c.Flags().StringVar(&notes, "notes", "", "free-form notes")
	c.Flags().StringVar(&tagsRaw, "tags", "", "comma-separated tags")
	c.Flags().StringVar(&rotateAfter, "rotate-after", "",
		"rotation horizon (e.g. 90d, 6m, 1y) — leave empty to opt out of reminders")
	c.Flags().StringArrayVar(&fieldsRaw, "field", nil,
		"custom field as key=value (repeatable, key must match ^[a-z][a-z0-9_]{0,30}$)")
	return c
}

// parseFieldFlags turns the raw --field key=value strings collected by
// cobra into a validated map. The rules mirror the issue spec:
//   - each flag value must contain exactly one '='
//   - the key must match fieldKeyRe
//   - the value may be empty (callers may want an explicit empty marker)
//   - duplicate keys overwrite — last flag wins — and we emit no error
//     for this, because StringArrayVar already allows repeats and the
//     last-wins semantics match how other CLIs behave.
func parseFieldFlags(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	for _, s := range raw {
		i := strings.Index(s, "=")
		if i <= 0 {
			return nil, fmt.Errorf("invalid --field %q: expected key=value", s)
		}
		k := s[:i]
		v := s[i+1:]
		if !fieldKeyRe.MatchString(k) {
			return nil, fmt.Errorf("invalid --field key %q: must match %s", k, fieldKeyRe.String())
		}
		out[k] = v
	}
	return out, nil
}

func readPasswordStdin(errOut io.Writer) (string, error) {
	fi, _ := os.Stdin.Stat()
	isPiped := (fi.Mode() & os.ModeCharDevice) == 0
	if isPiped {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	// Interactive: prompt
	fmt.Fprint(errOut, "password: ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
