// Rate limiting middleware with pluggable backends.
// Supports in-memory (single instance) and Redis (multi-instance) backends.
// Set REDIS_URL to enable Redis backend. Redis errors fail closed so an
// authentication or license-verification path never silently becomes
// unlimited during an outage.
package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitBackend abstracts the rate limiting storage.
type RateLimitBackend interface {
	Allow(key string, rate int, window time.Duration) bool
}

// ─── In-Memory Backend (default) ───

type memoryBackend struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	count int
	// windowStart is when the current window opened and window is the
	// length it opened with. The sweeper needs both: a counter whose
	// window is still running must survive, or deleting it hands the
	// caller a fresh allowance.
	windowStart time.Time
	window      time.Duration
}

func NewMemoryBackend() RateLimitBackend {
	mb := &memoryBackend{visitors: make(map[string]*visitor)}
	go func() {
		for {
			time.Sleep(time.Minute)
			mb.cleanup()
		}
	}()
	return mb
}

func (mb *memoryBackend) Allow(key string, rate int, window time.Duration) bool {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	v, exists := mb.visitors[key]
	now := time.Now()

	// Fixed window, matching the Redis backend's INCR+EXPIRE: the
	// counter resets `window` after it opened, not after the caller
	// falls silent. Resetting on idle meant the two backends disagreed
	// about the same budget, and that a caller who kept trying never
	// rolled over — they stayed locked out until they went quiet for a
	// whole window, which on the hour-long OTP budget is an hour of
	// silence from an entire NATed office.
	if !exists || now.Sub(v.windowStart) >= window {
		mb.visitors[key] = &visitor{count: 1, windowStart: now, window: window}
		return true
	}

	v.count++
	return v.count <= rate
}

// cleanup drops counters whose window has already closed. It has to
// respect each entry's own window: a flat threshold shorter than the
// window deletes counters that are still live, which is not a leak but
// a bypass — the caller comes back to a clean slate. The old fixed
// 5-minute sweep turned an hour-long budget of 30 into "30 sends per
// five idle minutes", roughly twelve times what it advertises.
func (mb *memoryBackend) cleanup() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	now := time.Now()
	for key, v := range mb.visitors {
		// Short windows linger a little so the map is not rebuilt on
		// every sweep. The entry is expired either way, so holding it
		// costs nothing but a map slot.
		ttl := max(v.window, 5*time.Minute)
		if now.Sub(v.windowStart) > ttl {
			delete(mb.visitors, key)
		}
	}
}

// ─── Redis Backend (optional) ───

// RedisClient is a minimal interface for Redis operations needed by rate limiting.
// Compatible with github.com/redis/go-redis/v9.
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

type redisBackend struct {
	client RedisClient
}

// NewRedisBackend creates a Redis-backed rate limiter.
func NewRedisBackend(client RedisClient) RateLimitBackend {
	return &redisBackend{client: client}
}

// Lua script for atomic rate limiting: INCR + EXPIRE in one round trip.
const rateLimitScript = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('EXPIRE', key, window)
end
return current
`

func (rb *redisBackend) Allow(key string, rate int, window time.Duration) bool {
	result := rb.client.Eval(
		context.Background(),
		rateLimitScript,
		[]string{"rl:" + key},
		rate,
		int(window.Seconds()),
	)
	count, err := result.Int64()
	if err != nil {
		RateLimitBackendErrors.Inc()
		return false
	}
	return count <= int64(rate)
}

// ─── Default backend (package-level) ───

var defaultBackend RateLimitBackend = NewMemoryBackend()

// SetRateLimitBackend sets the global rate limit backend (call once at startup).
func SetRateLimitBackend(b RateLimitBackend) {
	defaultBackend = b
}

// ─── Middleware ───

// RateLimit creates a rate limiting middleware using the configured backend.
func RateLimit(rate int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if ak, exists := c.Get("api_key"); exists {
			if apiKey, ok := ak.(interface{ GetID() string }); ok {
				key = "apikey:" + apiKey.GetID()
			}
		}

		if !defaultBackend.Allow(key, rate, window) {
			RateLimitRejections.Inc()
			abortWithError(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
			return
		}
		c.Next()
	}
}

// RateLimitByIP creates a rate limiter keyed by IP only.
func RateLimitByIP(rate int, window time.Duration) gin.HandlerFunc {
	return RateLimitByIPScoped("", rate, window)
}

// RateLimitByIPScoped is RateLimitByIP with a counter of its own.
//
// RateLimitByIP buckets on "ip:<addr>" alone, so two of them on one
// route share a single counter and fight over whose rate and window
// win. A scope gives an endpoint that needs a tighter budget than its
// group — /auth/otp/send, which mails an address the caller chose — a
// bucket of its own instead of eating into the shared one.
func RateLimitByIPScoped(scope string, rate int, window time.Duration) gin.HandlerFunc {
	prefix := "ip:"
	if scope != "" {
		prefix = "ip:" + scope + ":"
	}
	return func(c *gin.Context) {
		if !defaultBackend.Allow(prefix+c.ClientIP(), rate, window) {
			RateLimitRejections.Inc()
			abortWithError(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
			return
		}
		c.Next()
	}
}
