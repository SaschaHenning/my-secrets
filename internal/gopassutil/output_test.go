package gopassutil

import (
	"reflect"
	"testing"
)

func TestStripGopassBanner(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{
			name: "emoji banner",
			out:  "⚠ Running 'git status' in /tmp/store...\nmain\n",
			want: []string{"main"},
		},
		{
			name: "plain banner and whitespace",
			out:  "  Running 'git remote -v' in /tmp/store...  \n\n origin fetch \n origin push\n",
			want: []string{"origin fetch", "origin push"},
		},
		{
			name: "similar payload lines remain",
			out:  "Running 'git status'\npath ' in /tmp/store\n",
			want: []string{"Running 'git status'", "path ' in /tmp/store"},
		},
		{
			name: "empty output",
			out:  " \n\t\n",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripGopassBanner(tt.out); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("StripGopassBanner() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
