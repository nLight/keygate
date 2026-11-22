package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tabloy/keygate/internal/model"
)

// The activity feed of Analytics Insights, filtered to a product, shows
// that product's events only, not another product's nor installation-wide
// ones (#71). Audit lines are written directly: Store.Audit writes in the
// background, and a check that runs before they land passes for nothing.
func TestGetRecentActivityScopesToProduct(t *testing.T) {
	s := setupTestDB(t)
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()

	licA := createTestLicense(t, s, ctx)
	time.Sleep(2 * time.Millisecond) // createTestLicense slugs carry the time
	licB := createTestLicense(t, s, ctx)
	at := time.Now().Add(time.Hour) // newer than anything else in a shared database
	logs := map[string]*model.AuditLog{
		"product A": {Entity: "product", EntityID: licA.ProductID, Action: "updated"},
		"licence A": {Entity: "license", EntityID: licA.ID, Action: "revoked"},
		"product B": {Entity: "product", EntityID: licB.ProductID, Action: "updated"},
		"licence B": {Entity: "license", EntityID: licB.ID, Action: "revoked"},
		"settings":  {Entity: "settings", EntityID: "smtp", Action: "updated"},
	}
	ids := map[string]string{}
	for name, l := range logs {
		l.ID, l.ActorType, l.CreatedAt = uuid.NewString(), "admin", at
		if _, err := s.DB.NewInsert().Model(l).Exec(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ids[l.ID] = name
	}
	seen := func(productID string) map[string]bool {
		t.Helper()
		acts, err := s.GetRecentActivity(ctx, productID, 50)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, a := range acts {
			if name, ok := ids[a.ID]; ok {
				out[name] = true
			}
		}
		return out
	}

	got := seen(licA.ProductID)
	for name, want := range map[string]bool{"product A": true, "licence A": true, "product B": false, "licence B": false, "settings": false} {
		if got[name] != want {
			t.Errorf("activity of product A: %s shown = %v, want %v", name, got[name], want)
		}
	}
	if all := seen(""); len(all) != len(logs) {
		t.Errorf("unscoped activity shows %d of the %d lines: %v", len(all), len(logs), all)
	}
}
