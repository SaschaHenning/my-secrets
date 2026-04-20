package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseFieldFlags_Valid(t *testing.T) {
	in := []string{"account_id=12345", "region=eu-central-1", "empty="}
	got, err := parseFieldFlags(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"account_id": "12345",
		"region":     "eu-central-1",
		"empty":      "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseFieldFlags_Nil(t *testing.T) {
	got, err := parseFieldFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("nil input should yield nil map, got %+v", got)
	}
}

func TestParseFieldFlags_LastWins(t *testing.T) {
	in := []string{"account_id=111", "account_id=222"}
	got, err := parseFieldFlags(in)
	if err != nil {
		t.Fatal(err)
	}
	if got["account_id"] != "222" {
		t.Errorf("last-wins semantics broken, got %q", got["account_id"])
	}
}

func TestParseFieldFlags_RejectsBadKey(t *testing.T) {
	cases := []struct {
		in     string
		reason string
	}{
		{"bad-key=x", "hyphens not allowed"},
		{"BadCase=x", "uppercase not allowed"},
		{"1leading=x", "must start with letter"},
		{"=empty-key", "empty key rejected"},
		{"no-equals-sign", "missing ="},
		{strings.Repeat("a", 32) + "=x", "over 31 chars"},
	}
	for _, tc := range cases {
		_, err := parseFieldFlags([]string{tc.in})
		if err == nil {
			t.Errorf("%s: expected error for %q", tc.reason, tc.in)
		}
	}
}

func TestParseFieldFilters_TolerantKey(t *testing.T) {
	// Filter mode accepts keys the add-time regex would reject — a user
	// may need to filter on a legacy key that was imported from elsewhere.
	got, err := parseFieldFilters([]string{"Legacy-Key=v"})
	if err != nil {
		t.Fatal(err)
	}
	if got["Legacy-Key"] != "v" {
		t.Errorf("filter must keep original key, got %+v", got)
	}
}

func TestParseFieldFilters_EqualsSignRequired(t *testing.T) {
	if _, err := parseFieldFilters([]string{"missing-equals"}); err == nil {
		t.Error("expected error for filter without =")
	}
}
