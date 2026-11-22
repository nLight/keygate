package store_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/tabloy/keygate/internal/store"
)

// A statement that failed aborts the transaction, and Postgres turns
// the COMMIT into a rollback that pgdriver reports as success. RunInTx
// says so instead, even when the closure dropped the error.
// (Ported from upstream da630ed.)
func TestAbortedTransactionIsAnError(t *testing.T) {
	s := setupTestDB(t)
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	swallow := func(ctx context.Context, tx bun.Tx) error {
		_, _ = tx.ExecContext(ctx, "SELECT 1/0")
		return nil
	}
	if err := store.RunInTx(ctx, s.DB, swallow); err == nil {
		t.Fatal("RunInTx: an aborted transaction was reported as committed")
	}
	ok := func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT 1")
		return err
	}
	if err := store.RunInTx(ctx, s.DB, ok); err != nil {
		t.Fatalf("RunInTx: %v", err)
	}
}
