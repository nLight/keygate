package store_test

import (
	"context"
	"testing"
)

// SetSettings persists values that only work together (a webhook endpoint
// ID and its signing secret). A failing write must not leave the others
// committed.
func TestSetSettingsIsAtomic(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()

	keys := []string{"test_atomic_a", "test_atomic_b"}
	cleanup := func() {
		for _, k := range keys {
			_, _ = s.DB.NewRaw("DELETE FROM settings WHERE key = ?", k).Exec(ctx)
		}
	}
	cleanup()
	defer cleanup()

	// Fail the upsert of one specific key/value so the second write of a
	// SetSettings call can be made to error deterministically.
	for _, stmt := range []string{
		`CREATE OR REPLACE FUNCTION test_atomic_reject() RETURNS trigger AS $$
		BEGIN
			IF NEW.key = 'test_atomic_b' AND NEW.value = 'fail' THEN
				RAISE EXCEPTION 'rejected by test trigger';
			END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS test_atomic_reject ON settings`,
		`CREATE TRIGGER test_atomic_reject BEFORE INSERT OR UPDATE ON settings
		FOR EACH ROW EXECUTE FUNCTION test_atomic_reject()`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = s.DB.ExecContext(ctx, `DROP TRIGGER IF EXISTS test_atomic_reject ON settings`)
		_, _ = s.DB.ExecContext(ctx, `DROP FUNCTION IF EXISTS test_atomic_reject()`)
	}()

	if err := s.SetSettings(ctx, map[string]string{"test_atomic_a": "old", "test_atomic_b": "old"}); err != nil {
		t.Fatal(err)
	}

	// One of the two upserts fails regardless of map iteration order.
	err := s.SetSettings(ctx, map[string]string{"test_atomic_a": "new", "test_atomic_b": "fail"})
	if err == nil {
		t.Fatal("expected SetSettings to fail")
	}

	for _, k := range keys {
		v, err := s.GetSetting(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if v != "old" {
			t.Fatalf("%s = %q after failed SetSettings, want %q", k, v, "old")
		}
	}
}
