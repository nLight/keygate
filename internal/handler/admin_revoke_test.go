package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v82"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// fakeStripeAPI answers the subscription cancel call and records which
// subscriptions were cancelled.
type fakeStripeAPI struct {
	mu       sync.Mutex
	canceled []string
	failWith int // HTTP status to answer cancels with, 0 = succeed
}

func (f *fakeStripeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/subscriptions/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
		if f.failWith != 0 {
			w.WriteHeader(f.failWith)
			_, _ = w.Write([]byte(`{"error":{"type":"api_error","message":"unavailable"}}`))
			return
		}
		f.canceled = append(f.canceled, id)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "object": "subscription", "status": "canceled",
		})
		return
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"not found"}}`))
}

func (f *fakeStripeAPI) cancels() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.canceled...)
}

// setupRevokeTest wires an AdminHandler against the test database and a
// fake Stripe API, and returns a seeded license per subscription ID.
func setupRevokeTest(t *testing.T, fake *fakeStripeAPI, subscriptionIDs ...string) (*gin.Engine, *store.Store, []*model.License) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	s, err := store.New(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.RunMigrations("../../db/migrations"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	const email = "revoke@example.com"
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM audit_logs WHERE entity_id IN (SELECT id FROM licenses WHERE email = ?)", email).Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM licenses WHERE email = ?", email).Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM plans WHERE product_id IN (SELECT id FROM products WHERE slug = 'revoke-product')").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM products WHERE slug = 'revoke-product'").Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)

	productID, planID := store.NewID(), store.NewID()
	if _, err := s.DB.NewRaw(
		"INSERT INTO products (id, name, slug, type, created_at) VALUES (?, 'Revoke Product', 'revoke-product', 'desktop', now())",
		productID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.NewRaw(
		"INSERT INTO plans (id, product_id, name, slug, license_type, max_activations, max_seats, grace_days, active, checkout_id, created_at) VALUES (?, ?, 'Pro', 'revoke-pro', 'subscription', 3, 0, 7, true, ?, now())",
		planID, productID, store.ShortID()).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	lics := make([]*model.License, 0, len(subscriptionIDs))
	for i, subID := range subscriptionIDs {
		lic := &model.License{
			ProductID: productID, PlanID: planID, Email: email,
			LicenseKey: "KG-REVOKE-TEST-000" + string(rune('A'+i)),
			Status:     model.StatusActive,
			// "" seeds a license with no subscription behind it.
			StripeSubscriptionID: subID,
			PaymentProvider:      "stripe",
		}
		if err := s.CreateLicense(ctx, lic); err != nil {
			t.Fatal(err)
		}
		lics = append(lics, lic)
	}

	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	prevKey := stripe.Key
	stripe.Key = "sk_test_fake"
	stripe.SetBackend(stripe.APIBackend, stripe.GetBackendWithConfig(stripe.APIBackend, &stripe.BackendConfig{
		URL:               stripe.String(srv.URL),
		MaxNetworkRetries: stripe.Int64(0),
		LeveledLogger:     &stripe.LeveledLogger{Level: stripe.LevelNull},
	}))
	t.Cleanup(func() {
		stripe.Key = prevKey
		stripe.SetBackend(stripe.APIBackend, nil)
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AdminHandler{Store: s}
	r.POST("/admin/licenses/:id/revoke", h.RevokeLicense)
	return r, s, lics
}

func revoke(t *testing.T, r *gin.Engine, id string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/licenses/"+id+"/revoke", nil))
	var body struct {
		Data struct {
			Status         string `json:"status"`
			ProviderResult string `json:"provider_result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode revoke response %q: %v", w.Body.String(), err)
	}
	return w.Code, body.Data.ProviderResult
}

func reload(t *testing.T, s *store.Store, id string) *model.License {
	t.Helper()
	lic, err := s.FindLicenseByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return lic
}

// Revoking takes the customer's access away, so it must also stop the
// money: otherwise the card keeps being charged every month for a product
// that no longer opens.
func TestRevokeCancelsSubscriptionAndDatesTheRevocation(t *testing.T) {
	fake := &fakeStripeAPI{}
	r, s, lics := setupRevokeTest(t, fake, "sub_revoke_test")
	lic := lics[0]

	code, providerResult := revoke(t, r, lic.ID)
	if code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", code)
	}
	if providerResult != "stripe_subscription_canceled" {
		t.Fatalf("provider_result = %q, want stripe_subscription_canceled", providerResult)
	}
	if got := fake.cancels(); len(got) != 1 || got[0] != "sub_revoke_test" {
		t.Fatalf("subscriptions canceled at Stripe = %v, want [sub_revoke_test]", got)
	}

	got := reload(t, s, lic.ID)
	if got.Status != model.StatusRevoked {
		t.Fatalf("status = %s, want revoked", got.Status)
	}
	// Undated, "Revoked" in the admin panel can't be lined up against the
	// provider's timeline — which is how a stray charge goes unexplained.
	if got.RevokedAt == nil {
		t.Fatal("revoked_at not stamped")
	}
	// Revocation is not a subscription ending on its own terms; the two
	// dates answer different questions and must not be conflated.
	if got.CanceledAt != nil {
		t.Fatalf("canceled_at stamped by a revoke: %v", got.CanceledAt)
	}
}

// Stripe being unreachable must not leave the license usable — cutting off
// access is the whole point of revoke — but the admin has to be told that
// billing is still running.
func TestRevokeStillRevokesWhenStripeFails(t *testing.T) {
	fake := &fakeStripeAPI{failWith: http.StatusServiceUnavailable}
	r, s, lics := setupRevokeTest(t, fake, "sub_revoke_fail")
	lic := lics[0]

	code, providerResult := revoke(t, r, lic.ID)
	if code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", code)
	}
	if providerResult != "stripe_cancel_failed" {
		t.Fatalf("provider_result = %q, want stripe_cancel_failed", providerResult)
	}
	if got := reload(t, s, lic.ID); got.Status != model.StatusRevoked || got.RevokedAt == nil {
		t.Fatalf("license after failed provider cancel: status=%s revoked_at=%v", got.Status, got.RevokedAt)
	}
}

// A license with no subscription behind it (one-time purchase, or one
// issued by hand) revokes without going to Stripe at all.
func TestRevokeWithoutSubscriptionSkipsStripe(t *testing.T) {
	fake := &fakeStripeAPI{}
	r, s, lics := setupRevokeTest(t, fake, "")
	lic := lics[0]

	code, providerResult := revoke(t, r, lic.ID)
	if code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", code)
	}
	if providerResult != "no_subscription" {
		t.Fatalf("provider_result = %q, want no_subscription", providerResult)
	}
	if got := fake.cancels(); len(got) != 0 {
		t.Fatalf("Stripe called for a license with no subscription: %v", got)
	}
	if got := reload(t, s, lic.ID); got.Status != model.StatusRevoked || got.RevokedAt == nil {
		t.Fatalf("license after revoke: status=%s revoked_at=%v", got.Status, got.RevokedAt)
	}
}

// Revoking twice must not move the date: it records when access was
// actually pulled, not when someone last clicked the button.
func TestRevokeKeepsTheFirstRevocationDate(t *testing.T) {
	fake := &fakeStripeAPI{}
	r, s, lics := setupRevokeTest(t, fake, "sub_revoke_twice")
	lic := lics[0]

	if code, _ := revoke(t, r, lic.ID); code != http.StatusOK {
		t.Fatalf("first revoke status = %d", code)
	}
	first := reload(t, s, lic.ID).RevokedAt
	if first == nil {
		t.Fatal("revoked_at not stamped")
	}
	if code, _ := revoke(t, r, lic.ID); code != http.StatusOK {
		t.Fatalf("second revoke status = %d", code)
	}
	if second := reload(t, s, lic.ID).RevokedAt; second == nil || !second.Equal(*first) {
		t.Fatalf("revoked_at moved on re-revoke: %v -> %v", first, second)
	}
}
