package middleware

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisRateLimitSharedAcrossInstances(t *testing.T) {
	rawURL := os.Getenv("TEST_REDIS_URL")
	if rawURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	clientA := redis.NewClient(opts)
	clientB := redis.NewClient(opts)
	defer clientA.Close()
	defer clientB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clientA.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	key := "multi-instance-" + uuid.NewString()
	backendA := NewRedisBackend(clientA)
	backendB := NewRedisBackend(clientB)
	if !backendA.Allow(key, 2, time.Minute) || !backendB.Allow(key, 2, time.Minute) {
		t.Fatal("shared Redis budget rejected one of the first two requests")
	}
	if backendA.Allow(key, 2, time.Minute) {
		t.Fatal("third request bypassed the budget by switching instances")
	}
	_ = clientA.Del(ctx, "rl:"+key).Err()
}
