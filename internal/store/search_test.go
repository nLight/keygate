package store

import "testing"

func TestEscapeLike(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"kg_live_ab", `kg\_live\_ab`},
		{"100%", `100\%`},
		{`dir\file`, `dir\\file`},
		{`\_%\\`, `\\\_\%\\\\`},
	} {
		if got := escapeLike(tc.in); got != tc.want {
			t.Errorf("escapeLike(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
