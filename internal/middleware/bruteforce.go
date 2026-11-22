package middleware

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// BruteForceProtection tracks failed authentication attempts and blocks
// IPs/keys that exceed the threshold. Uses exponential backoff.
type BruteForceProtection struct {
	mu         sync.RWMutex
	attempts   map[string]*attemptRecord
	maxFails   int           // max failures before lockout
	lockout    time.Duration // initial lockout duration
	maxLockout time.Duration // maximum lockout (cap for exponential backoff)
	window     time.Duration // window to count failures
}

type attemptRecord struct {
	failures     int
	firstFailure time.Time
	lockedUntil  time.Time
	lockoutCount int // number of times locked out (for exponential backoff)
}

func NewBruteForceProtection(maxFails int, lockout, maxLockout, window time.Duration) *BruteForceProtection {
	bf := &BruteForceProtection{
		attempts:   make(map[string]*attemptRecord),
		maxFails:   maxFails,
		lockout:    lockout,
		maxLockout: maxLockout,
		window:     window,
	}
	go bf.cleanup()
	return bf
}

// RecordFailure records a failed attempt for a key (IP or license key).
func (bf *BruteForceProtection) RecordFailure(key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	rec, exists := bf.attempts[key]
	if !exists {
		bf.attempts[key] = &attemptRecord{failures: 1, firstFailure: now}
		return
	}
	if rec.lockedUntil.After(now) {
		// A request that passed the guard just before this lockout began
		// is paid for by it. Counting it would start the next, doubled
		// lockout at once, and the count now outlives the window.
		return
	}
	if now.Sub(rec.firstFailure) > bf.window {
		// A new window starts the failure count again, but not the
		// lockout count: that count is what doubles each further
		// lockout. Replacing the record here dropped it, and a caller
		// who comes back when a lockout longer than the window ends
		// always lands here. With the defaults the lockouts went 30s,
		// 1m, 2m, 4m, 8m and then 30s again, never reaching the cap.
		rec.failures = 1
		rec.firstFailure = now
		// The count lasts as long as the longest lockout after the last
		// one ended. An address many people share (an office, a school)
		// that was locked out once must not have a stray typo, an hour
		// later, start it at the cap.
		if now.Sub(rec.lockedUntil) > bf.maxLockout {
			rec.lockoutCount = 0
		}
		return
	}

	rec.failures++
	if rec.failures >= bf.maxFails {
		// Exponential backoff: lockout * 2^lockoutCount, capped at maxLockout
		duration := bf.lockout
		for i := 0; i < rec.lockoutCount; i++ {
			duration *= 2
			if duration > bf.maxLockout {
				duration = bf.maxLockout
				break
			}
		}
		rec.lockedUntil = now.Add(duration)
		rec.lockoutCount++
		rec.failures = 0
		rec.firstFailure = now
	}
}

// RecordSuccess clears the failure record for a key.
func (bf *BruteForceProtection) RecordSuccess(key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.attempts, key)
}

// IsBlocked checks if a key is currently locked out.
func (bf *BruteForceProtection) IsBlocked(key string) (bool, time.Duration) {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	rec, exists := bf.attempts[key]
	if !exists {
		return false, 0
	}

	now := time.Now()
	if rec.lockedUntil.After(now) {
		return true, rec.lockedUntil.Sub(now)
	}
	return false, 0
}

func (bf *BruteForceProtection) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		bf.sweep(time.Now())
	}
}

// sweep forgets keys that have gone quiet. A key that was locked out is
// kept until it has been quiet for as long as the longest lockout. The
// sweep used to drop it four windows after its last lockout began,
// which a 30 minute lockout outlasts: a caller who waited a few minutes
// more after it started again from the shortest lockout.
func (bf *BruteForceProtection) sweep(now time.Time) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	for key, rec := range bf.attempts {
		if rec.lockedUntil.After(now) {
			continue
		}
		if rec.lockoutCount > 0 && now.Sub(rec.lockedUntil) <= bf.maxLockout {
			continue
		}
		if now.Sub(rec.firstFailure) > bf.window*4 {
			delete(bf.attempts, key)
		}
	}
}

// RetryAfterSeconds turns what is left of a lockout into the number a
// client is told to wait. It rounds up: truncating 59.9 to 59 sends a
// well-behaved client back a moment early, to another 429.
func RetryAfterSeconds(retryAfter time.Duration) int {
	return max(int(math.Ceil(retryAfter.Seconds())), 1)
}

// FailureKeyIP is how a failed licence attempt is filed: one namespace
// shared by the middleware that blocks and the service that records.
// The guard used to look up the bare address while the service wrote
// "ip:"+address, so the early guard never fired.
func FailureKeyIP(ip string) string { return "ip:" + ip }

// LicenseBruteForceGuard is a middleware that checks brute-force state before processing.
func LicenseBruteForceGuard(bf *BruteForceProtection) gin.HandlerFunc {
	return func(c *gin.Context) {
		blocked, retryAfter := bf.IsBlocked(FailureKeyIP(c.ClientIP()))
		if blocked {
			BruteForceBlocks.Inc()
			// retry_after lives in `error.details` (NOT alongside
			// code/message) so the response shape stays the canonical
			// envelope: { success, error: { code, message, details? } }.
			retrySec := RetryAfterSeconds(retryAfter)
			c.Header("Retry-After", fmt.Sprintf("%d", retrySec))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "LOCKED_OUT",
					"message": "too many failed attempts, please try again later",
					"details": gin.H{"retry_after": retrySec},
				},
			})
			return
		}

		// Also check by license key if present in request body
		// We'll check post-processing via the context
		c.Set("brute_force", bf)
		c.Next()
	}
}
