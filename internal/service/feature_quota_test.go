package service

import "testing"

// Ported from upstream 60c661e (#62) and 0dec2ba (#117).

func TestFeatureEnabled(t *testing.T) {
	for _, tc := range []struct {
		typ, val string
		want     bool
	}{
		{"bool", "true", true}, {"bool", "false", false}, {"bool", "1", false},
		{"flag", "true", true}, {"flag", "false", false}, {"flag", "1", true}, {"flag", "yes", true},
	} {
		if got := featureEnabled(tc.typ, tc.val); got != tc.want {
			t.Errorf("featureEnabled(%q, %q) = %v, want %v", tc.typ, tc.val, got, tc.want)
		}
	}
}

// Usage past a lowered limit is 0 remaining, never -1, which means unlimited.
func TestQuotaRemaining(t *testing.T) {
	for _, tc := range []struct{ limit, used, want int64 }{
		{0, 5, -1}, {10, 3, 7}, {10, 10, 0}, {10, 11, 0}, {10, 500, 0},
	} {
		if got := quotaRemaining(tc.limit, tc.used); got != tc.want {
			t.Errorf("quotaRemaining(%d, %d) = %d, want %d", tc.limit, tc.used, got, tc.want)
		}
	}
}
