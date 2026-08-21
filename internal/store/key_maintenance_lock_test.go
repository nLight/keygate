package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestWithKeyMaintenanceLock_SerializesReplicas is the regression test for the
// rolling-deploy crash loop. Startup key maintenance rotates ciphertext,
// nulls the legacy plaintext column, and runs an "IF NOT EXISTS … ADD
// CONSTRAINT" block. Each step is individually restart-safe, but two replicas
// booting at once can both pass the catalog check and the loser gets a
// duplicate-object error that main.go treats as fatal.
func TestWithKeyMaintenanceLock_SerializesReplicas(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()

	const replicas = 4
	var (
		mu        sync.Mutex
		inside    int
		maxInside int
		wg        sync.WaitGroup
	)
	wg.Add(replicas)
	for i := 0; i < replicas; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := s.WithKeyMaintenanceLock(ctx, func(context.Context) error {
				mu.Lock()
				inside++
				if inside > maxInside {
					maxInside = inside
				}
				mu.Unlock()

				time.Sleep(50 * time.Millisecond)

				mu.Lock()
				inside--
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("WithKeyMaintenanceLock: %v", err)
			}
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Fatalf("%d replicas ran startup key maintenance concurrently, want 1", maxInside)
	}
}

// The lock must be released when the guarded work fails, otherwise the first
// failed boot wedges every later one until the connection is reaped.
func TestWithKeyMaintenanceLock_ReleasesOnError(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()

	sentinel := errors.New("maintenance failed")
	if err := s.WithKeyMaintenanceLock(ctx, func(context.Context) error {
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to propagate unchanged", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.WithKeyMaintenanceLock(ctx, func(context.Context) error { return nil })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second acquisition: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lock was not released after the guarded work failed")
	}

	var held bool
	if err := s.DB.NewRaw(
		"SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 8675312)",
	).Scan(ctx, &held); err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("advisory lock is still held after both calls returned")
	}
}
