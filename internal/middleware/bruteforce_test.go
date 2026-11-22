package middleware

import (
	"testing"
	"time"
)

// newDefaultBruteForce is the protection main.go builds with the
// default settings: 5 failures in 5 minutes, a 30 second lockout that
// doubles up to 30 minutes.
func newDefaultBruteForce() *BruteForceProtection {
	return NewBruteForceProtection(5, 30*time.Second, 30*time.Minute, 5*time.Minute)
}

// endLockout moves a key's record back in time as if its lockout had
// just run out, so a test need not wait for it.
func endLockout(bf *BruteForceProtection, key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	rec := bf.attempts[key]
	shift := time.Until(rec.lockedUntil) + time.Millisecond
	rec.firstFailure = rec.firstFailure.Add(-shift)
	rec.lockedUntil = rec.lockedUntil.Add(-shift)
}

func remembered(bf *BruteForceProtection, key string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	_, ok := bf.attempts[key]
	return ok
}

// Each further lockout doubles up to the cap, as the API docs promise,
// for a caller who comes back the moment each one ends. A failure after
// a lockout longer than the window used to start a fresh record, which
// dropped the lockout count: the lockouts went 30s, 1m, 2m, 4m, 8m and
// then 30s again.
func TestLockoutsKeepDoubling(t *testing.T) {
	bf := newDefaultBruteForce()
	key := FailureKeyIP("203.0.113.7")
	for i, want := range []time.Duration{
		30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute,
	} {
		for range 5 {
			bf.RecordFailure(key)
		}
		blocked, left := bf.IsBlocked(key)
		if !blocked {
			t.Fatalf("lockout %d: not locked out after 5 failures", i+1)
		}
		if got := left.Round(time.Second); got != want {
			t.Fatalf("lockout %d lasted %v, want %v", i+1, got, want)
		}
		endLockout(bf, key)
	}
}

// A key that was locked out is remembered until it has been quiet for
// as long as the longest lockout. One that never was is forgotten as
// before, four windows after its first failure.
func TestSweepKeepsLockedOutKeys(t *testing.T) {
	bf := newDefaultBruteForce()
	now := time.Now()
	bf.mu.Lock()
	// The cap's 30 minute lockout, which began 31 minutes ago.
	bf.attempts["locked"] = &attemptRecord{
		firstFailure: now.Add(-31 * time.Minute),
		lockedUntil:  now.Add(-time.Minute),
		lockoutCount: 7,
	}
	bf.attempts["failed"] = &attemptRecord{failures: 1, firstFailure: now.Add(-21 * time.Minute)}
	bf.mu.Unlock()

	bf.sweep(now)
	if !remembered(bf, "locked") {
		t.Fatal("forgot a key a minute after its lockout ended: its next lockout would start from 30s again")
	}
	if remembered(bf, "failed") {
		t.Fatal("kept a key that was never locked out, 21 minutes after its only failure")
	}

	bf.sweep(now.Add(24 * time.Minute))
	if !remembered(bf, "locked") {
		t.Fatal("forgot a key 25 minutes after its lockout ended, while its count still applies")
	}

	bf.sweep(now.Add(30 * time.Minute))
	if remembered(bf, "locked") {
		t.Fatal("still remembered a key that has been quiet for longer than the longest lockout")
	}
}

// The lockout count lasts as long as the longest lockout after the last
// one ended, then starts again: a caller back within that time picks up
// where it left off, one back later starts from the shortest lockout.
func TestLockoutCountExpires(t *testing.T) {
	for _, tc := range []struct {
		quiet time.Duration
		want  time.Duration
	}{
		{29 * time.Minute, time.Minute},
		{31 * time.Minute, 30 * time.Second},
	} {
		bf := newDefaultBruteForce()
		key := FailureKeyIP("203.0.113.9")
		for range 5 {
			bf.RecordFailure(key)
		}
		bf.mu.Lock()
		rec := bf.attempts[key]
		shift := time.Until(rec.lockedUntil) + tc.quiet
		rec.firstFailure = rec.firstFailure.Add(-shift)
		rec.lockedUntil = rec.lockedUntil.Add(-shift)
		bf.mu.Unlock()

		for range 5 {
			bf.RecordFailure(key)
		}
		if _, left := bf.IsBlocked(key); left.Round(time.Second) != tc.want {
			t.Errorf("back %v after the first lockout ended: next lockout %v, want %v", tc.quiet, left.Round(time.Second), tc.want)
		}
	}
}

// Failures of requests already past the guard when a lockout begins do
// not count: they would start the next, doubled lockout at once.
func TestFailuresDuringALockoutDoNotCount(t *testing.T) {
	bf := newDefaultBruteForce()
	key := FailureKeyIP("203.0.113.11")
	for range 10 {
		bf.RecordFailure(key)
	}
	if _, left := bf.IsBlocked(key); left.Round(time.Second) != 30*time.Second {
		t.Fatalf("a burst of 10 failures: lockout %v, want 30s", left.Round(time.Second))
	}
	endLockout(bf, key)
	for range 5 {
		bf.RecordFailure(key)
	}
	if _, left := bf.IsBlocked(key); left.Round(time.Second) != time.Minute {
		t.Fatalf("next lockout %v, want 1m", left.Round(time.Second))
	}
}

// With BF_MAX_FAILS=1 the first failure locks, in a fresh record as in
// a new window.
func TestOneFailureAllowed(t *testing.T) {
	bf := NewBruteForceProtection(1, 30*time.Second, 30*time.Minute, 5*time.Minute)
	key := FailureKeyIP("203.0.113.12")
	bf.RecordFailure(key)
	if blocked, _ := bf.IsBlocked(key); !blocked {
		t.Fatal("not locked out after the one failure allowed")
	}
}

// The cap holds for the first lockout too, whatever BF_LOCKOUT_SECONDS
// says.
func TestFirstLockoutIsCapped(t *testing.T) {
	bf := NewBruteForceProtection(5, time.Hour, 30*time.Minute, 5*time.Minute)
	key := FailureKeyIP("203.0.113.13")
	for range 5 {
		bf.RecordFailure(key)
	}
	if _, left := bf.IsBlocked(key); left.Round(time.Second) != 30*time.Minute {
		t.Fatalf("first lockout %v, want the 30m cap", left.Round(time.Second))
	}
}

// BF_LOCKOUT_SECONDS=0 blocks nobody, however many failures pile up,
// and a negative value does not overflow into a lockout.
func TestNoLockoutWhenDisabled(t *testing.T) {
	for _, lockout := range []time.Duration{0, -time.Second} {
		bf := NewBruteForceProtection(5, lockout, 30*time.Minute, 5*time.Minute)
		key := FailureKeyIP("203.0.113.14")
		for range 100000 {
			bf.RecordFailure(key)
		}
		if blocked, _ := bf.IsBlocked(key); blocked {
			t.Fatalf("lockout %v: blocked", lockout)
		}
	}
}
