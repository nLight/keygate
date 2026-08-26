package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type fakeRedisClient struct{ cmd *redis.Cmd }

func (f fakeRedisClient) Eval(context.Context, string, []string, ...interface{}) *redis.Cmd {
	return f.cmd
}

func TestMemoryBackendAllow(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	for i := 0; i < 3; i++ {
		if !mb.Allow("test-key", 3, time.Minute) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if mb.Allow("test-key", 3, time.Minute) {
		t.Fatal("4th request should be denied")
	}
}

func TestMemoryBackendDifferentKeys(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	if !mb.Allow("key-a", 2, time.Minute) {
		t.Fatal("key-a request 1 should be allowed")
	}
	if !mb.Allow("key-a", 2, time.Minute) {
		t.Fatal("key-a request 2 should be allowed")
	}
	if mb.Allow("key-a", 2, time.Minute) {
		t.Fatal("key-a request 3 should be denied")
	}

	if !mb.Allow("key-b", 2, time.Minute) {
		t.Fatal("key-b request 1 should be allowed")
	}
}

func TestMemoryBackendWindowReset(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	mb.Allow("key", 2, 50*time.Millisecond)
	mb.Allow("key", 2, 50*time.Millisecond)
	if mb.Allow("key", 2, 50*time.Millisecond) {
		t.Fatal("should be denied")
	}

	time.Sleep(60 * time.Millisecond)
	if !mb.Allow("key", 2, 50*time.Millisecond) {
		t.Fatal("should be allowed after window reset")
	}
}

func TestMemoryBackendCleanup(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	mb.Allow("old-key", 10, 50*time.Millisecond)

	// Backdate the window so it is long closed.
	mb.mu.Lock()
	mb.visitors["old-key"].windowStart = time.Now().Add(-10 * time.Minute)
	mb.mu.Unlock()

	mb.cleanup()

	mb.mu.Lock()
	_, exists := mb.visitors["old-key"]
	mb.mu.Unlock()

	if exists {
		t.Fatal("old-key should be cleaned up")
	}
}

// The sweep must not delete a counter whose window is still open. It
// used to use a flat 5-minute threshold, which on the hour-long OTP
// budget handed the caller a fresh allowance every five idle minutes.
func TestMemoryBackendCleanupKeepsLiveLongWindow(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	const rate = 3
	for i := 0; i < rate; i++ {
		if !mb.Allow("otp-key", rate, time.Hour) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if mb.Allow("otp-key", rate, time.Hour) {
		t.Fatal("budget should be spent")
	}

	// Ten idle minutes: past the old 5-minute sweep threshold, but far
	// short of the hour the caller was actually budgeted.
	mb.mu.Lock()
	mb.visitors["otp-key"].windowStart = time.Now().Add(-10 * time.Minute)
	mb.mu.Unlock()

	mb.cleanup()

	if mb.Allow("otp-key", rate, time.Hour) {
		t.Fatal("cleanup reopened an hour-long budget after 10 idle minutes")
	}
}

// A caller who keeps trying must still roll over when the window ends.
// Bumping lastSeen on every request made the window slide, so a client
// that retried steadily never got a fresh budget — it stayed locked out
// until it fell silent for a whole window.
func TestMemoryBackendWindowIsFixedNotSliding(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	const window = 60 * time.Millisecond
	mb.Allow("busy", 1, window)
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		mb.Allow("busy", 1, window) // denied, and must not extend the window
		time.Sleep(5 * time.Millisecond)
	}

	if !mb.Allow("busy", 1, window) {
		t.Fatal("window did not reset for a caller that kept trying")
	}
}

// Two limiters on one route must not share a counter.
func TestMemoryBackendScopedKeysAreIndependent(t *testing.T) {
	mb := NewMemoryBackend().(*memoryBackend)

	if !mb.Allow("ip:1.2.3.4", 1, time.Minute) {
		t.Fatal("group budget request 1 should be allowed")
	}
	if !mb.Allow("ip:otp_send:1.2.3.4", 1, time.Hour) {
		t.Fatal("scoped budget must not be spent by the group budget")
	}
	if mb.Allow("ip:otp_send:1.2.3.4", 1, time.Hour) {
		t.Fatal("scoped budget should be spent")
	}
}

func TestRedisBackendFailsClosed(t *testing.T) {
	failed := NewRedisBackend(fakeRedisClient{cmd: redis.NewCmdResult(nil, errors.New("redis down"))})
	if failed.Allow("auth:user", 10, time.Minute) {
		t.Fatal("Redis errors must deny rather than silently disabling the limit")
	}
	allowed := NewRedisBackend(fakeRedisClient{cmd: redis.NewCmdResult(int64(1), nil)})
	if !allowed.Allow("auth:user", 10, time.Minute) {
		t.Fatal("count below limit should be allowed")
	}
}
