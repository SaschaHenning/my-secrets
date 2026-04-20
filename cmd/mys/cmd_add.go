package main

import (
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
	"golang.org/x/term"
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

// readPasswordStdin returns the secret value a user wants to store.
//
//   - Piped stdin (shell heredoc / `echo x | mys add`): read everything,
//     strip only a single trailing CR/LF. Preserves spaces + Unicode.
//   - Interactive TTY: raw mode + echo off + manual UTF-8-safe backspace
//     handling, asked twice to catch typos. Raw mode is required:
//     canonical-mode BS deletes *one byte* from the kernel buffer, so
//     backspacing over a multi-byte codepoint (ä = 0xc3 0xa4) leaves a
//     dangling 0xc3 lead byte that corrupts the stored password. A
//     confirmation mismatch is a hard error — re-run add rather than
//     store something you cannot re-type.
func readPasswordStdin(errOut io.Writer) (string, error) {
	return readPasswordFrom(os.Stdin, errOut)
}

// readPasswordFrom is the testable core. f must be os.Stdin in
// production — the TTY branch needs a real tty fd for term.MakeRaw.
func readPasswordFrom(f *os.File, errOut io.Writer) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	isPiped := (fi.Mode() & os.ModeCharDevice) == 0
	if isPiped {
		b, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}
		s := string(b)
		s = strings.TrimSuffix(s, "\n")
		s = strings.TrimSuffix(s, "\r")
		return s, nil
	}
	fd := int(f.Fd())
	fmt.Fprint(errOut, "password: ")
	first, err := readLineRaw(fd, f)
	fmt.Fprintln(errOut)
	if err != nil {
		return "", err
	}
	fmt.Fprint(errOut, "password (wiederholen): ")
	second, err := readLineRaw(fd, f)
	fmt.Fprintln(errOut)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match — retry")
	}
	return first, nil
}

// readLineRaw puts the terminal into raw mode, reads bytes until CR/LF,
// and handles backspace (0x7f / 0x08) by trimming one UTF-8 codepoint
// at a time — not one byte. Ctrl-C (0x03) and Ctrl-D on an empty line
// abort. All other bytes in the range [0x20, 0xFF] are accepted,
// including the full UTF-8 continuation range.
func readLineRaw(fd int, f *os.File) (string, error) {
	old, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, old)

	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := f.Read(one)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		c := one[0]
		switch {
		case c == '\r' || c == '\n':
			return string(buf), nil
		case c == 0x7f || c == 0x08:
			buf = trimLastRune(buf)
		case c == 0x03 || c == 0x04:
			// Ctrl-C (ETX) or Ctrl-D (EOT) always aborts. In canonical
			// mode Ctrl-D on a non-empty line usually commits the line,
			// but silently committing here would make the semantics
			// surprising during a password prompt — better to force
			// the user to press Enter explicitly.
			return "", errors.New("aborted")
		case c >= 0x20:
			buf = append(buf, c)
		}
	}
}

// trimLastRune drops the final UTF-8 codepoint from b. If b ends with a
// continuation byte (0b10xxxxxx) we peel back until we hit the leading
// byte; this keeps multi-byte characters atomic under backspace.
func trimLastRune(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	i := len(b) - 1
	for i > 0 && (b[i]&0xC0) == 0x80 {
		i--
	}
	return b[:i]
}
