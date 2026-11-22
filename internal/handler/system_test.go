package handler

import "testing"

func TestSemverNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		// Basic comparisons
		{"1.0.1", "1.0.0", true},
		{"1.1.0", "1.0.0", true},
		{"2.0.0", "1.0.0", true},
		{"1.0.0", "1.0.0", false}, // same version
		{"1.0.0", "1.0.1", false}, // current is newer
		{"1.0.0", "2.0.0", false},

		// Multi-digit
		{"1.10.0", "1.9.0", true},
		{"1.0.10", "1.0.9", true},
		{"10.0.0", "9.0.0", true},

		// Pre-release comparisons per SemVer 2.0
		{"1.1.0-beta", "1.0.0", true},
		{"1.0.0", "1.0.0-beta", true}, // stable release ranks above pre-release
		{"1.0.0-rc.2", "1.0.0-rc.1", true},
		{"1.0.0-rc.1", "1.0.0-rc.2", false},

		// Build metadata ignored for precedence
		{"1.0.1+build", "1.0.0", true},
		{"1.0.1", "1.0.1+build", false},
		{"1.0.1+build2", "1.0.1+build1", false},

		// Edge cases
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"1.0.0", "dev", false},
		{"", "", false},

		// Partial versions
		{"1.1", "1.0", true},
		{"1", "0", true},
		{"1.1+build-x", "1.0", true},

		// A build from source: `git describe --tags --dirty` is the
		// tag or later, never a pre-release of it
		{"0.1.19", "0.1.19-3-gabc1234", false},
		{"0.1.19", "0.1.19-dirty", false},
		{"0.1.19", "0.1.19-3-gabc1234-dirty", false},
		{"0.1.19", "0.1.18-12-g0123abc", true},
		{"0.1.20", "0.1.19-3-gabc1234", true},
		{"0.2.0", "0.2.0-rc.1-3-gabc1234", true},
		{"0.1.19", "0.2.0-rc.1-3-gabc1234", false},
		// No tag at all: `--always` gives the bare hash
		{"0.1.19", "abc1234", false},
		{"0.1.19", "abc1234-dirty", false},
	}

	for _, tt := range tests {
		got := semverNewer(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("semverNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestStripV(t *testing.T) {
	tests := []struct{ in, want string }{
		{"v1.0.0", "1.0.0"},
		{"1.0.0", "1.0.0"},
		{"v", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stripV(tt.in); got != tt.want {
			t.Errorf("stripV(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewSystemHandlerUpdateRepo(t *testing.T) {
	for _, tc := range []struct{ in, owner, name string }{
		{"", "tabloy", "keygate"},
		{"nLight/keygate", "nLight", "keygate"},
		{" acme/lic ", "acme", "lic"},
		{"off", "", ""},
		{"NONE", "", ""},
		{"bogus", "tabloy", "keygate"},
		{"a/b/c", "tabloy", "keygate"},
	} {
		h := NewSystemHandler(nil, tc.in)
		if h.RepoOwner != tc.owner || h.RepoName != tc.name {
			t.Errorf("NewSystemHandler(%q) = %s/%s, want %s/%s", tc.in, h.RepoOwner, h.RepoName, tc.owner, tc.name)
		}
	}
}
