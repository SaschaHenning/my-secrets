package main

import "testing"

func TestNormalizeTTY(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                  "",
		" ? ":               "",
		"??\n":              "",
		"pipe:[123]\n":      "",
		"socket:[123]\n":    "",
		"pts/2\n":           "/dev/pts/2",
		"/dev/pts/4\n":      "/dev/pts/4",
		"tty1":              "/dev/tty1",
		"/private/tmp/tty1": "",
	}

	for raw, want := range tests {
		raw := raw
		want := want
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if got := normalizeTTY(raw); got != want {
				t.Fatalf("normalizeTTY(%q) = %q, want %q", raw, got, want)
			}
		})
	}
}
