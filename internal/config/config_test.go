package config

import "testing"

func TestResolveMode(t *testing.T) {
	cases := []struct {
		in        string
		wantMode  string
		wantKnown bool
	}{
		{"full", "full", true},
		{"quick", "quick", true},
		{"", "full", false},
		{"fukl", "full", false},
	}
	for _, c := range cases {
		gotMode, gotKnown := resolveMode(c.in)
		if gotMode != c.wantMode || gotKnown != c.wantKnown {
			t.Errorf("resolveMode(%q) = (%q,%v), want (%q,%v)", c.in, gotMode, gotKnown, c.wantMode, c.wantKnown)
		}
	}
}

func TestOutputJSONDeprecated(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"json", true},
		{"text", false},
		{"", false},
		{"JSON", false}, // case-sensitive: flag default/values are lowercase
	}
	for _, c := range cases {
		if got := outputJSONDeprecated(c.in); got != c.want {
			t.Errorf("outputJSONDeprecated(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
