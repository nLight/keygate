package main

import (
	"strings"
	"testing"
	"time"
)

func TestStripHTMLTags(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Alice", "Alice"},
		{"<b>Alice</b>", "Alice"},
		{"<i><b>Bold Italic</b></i>", "Bold Italic"},
		{"<script>alert(1)</script>", "alert(1)"},
		{"<scr<script>ipt>nested</script>", "nested"},
		{"<a href=\"https://example.com\">Link</a>", "Link"},
		{"Alice <!-- comment --> Bob", "Alice  Bob"},

		// Does not truncate on unclosed or relational '<'
		{"Alice < Bob", "Alice < Bob"},
		{"Alex <3", "Alex <3"},
		{"Score < 5", "Score < 5"},
		{"x < 5 and y > 2", "x < 5 and y > 2"},
		{"John <", "John <"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := stripHTMLTags(tt.in); got != tt.want {
			t.Errorf("stripHTMLTags(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The profile name is checked for length before tags are stripped, so a
// long name of nested tags is refused at once instead of being stripped
// a level at a time.
func TestProfileName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"  Alice  ", "Alice", true},
		{"<b>Alice</b>", "Alice", true},
		{"Alex <3", "Alex <3", true},
		{"", "", true},
		{strings.Repeat("a", 100), strings.Repeat("a", 100), true},
		{strings.Repeat("é", 100), strings.Repeat("é", 100), true},
		{strings.Repeat("a", 101), "", false},
		{"<b>" + strings.Repeat("a", 100) + "</b>", "", false},
		{strings.Repeat("<a", 33) + strings.Repeat(">", 33), "", true},
	}
	for _, tt := range tests {
		got, ok := profileName(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("profileName(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}

	nested := strings.Repeat("<a", 20000) + strings.Repeat(">", 20000)
	start := time.Now()
	if _, ok := profileName(nested); ok {
		t.Fatal("a 60 KB name was accepted")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("refusing a 60 KB name of nested tags took %v", d)
	}
}

// The limit is 100 characters, not bytes: a Cyrillic name of 60
// characters (120 bytes) is accepted, 101 characters is refused.
func TestProfileNameCountsCharactersNotBytes(t *testing.T) {
	if _, ok := profileName(strings.Repeat("Ж", 60)); !ok {
		t.Error("60-character Cyrillic name refused")
	}
	if _, ok := profileName(strings.Repeat("Ж", 101)); ok {
		t.Error("101-character name accepted")
	}
}
