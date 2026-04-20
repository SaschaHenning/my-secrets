package store

import "testing"

func TestOrgOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"jasp/github", "jasp"},
		{"zuhause/proxmox/root", "zuhause"},
		{"top-level", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := OrgOf(tc.in); got != tc.want {
			t.Errorf("OrgOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskedPassword(t *testing.T) {
	if MaskedPassword("") != "" {
		t.Error("empty input should produce empty masked output")
	}
	if m := MaskedPassword("secret"); m != "******" {
		t.Errorf("MaskedPassword(\"secret\") = %q, want \"******\"", m)
	}
}
