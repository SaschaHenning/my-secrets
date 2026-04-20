package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// addCmd builds the `mys add` subcommand.
func addCmd(requester *string) *cobra.Command {
	var (
		kind                             string
		username, url, githubProj, notes string
		tagsRaw                          string
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
				GitHubProject: githubProj,
				Notes:         notes,
				Password:      pw,
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
	c.Flags().StringVar(&githubProj, "github", "", "related GitHub project (owner/name)")
	c.Flags().StringVar(&notes, "notes", "", "free-form notes")
	c.Flags().StringVar(&tagsRaw, "tags", "", "comma-separated tags")
	return c
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
