package payment

import (
	"context"
	"os"
	"testing"
	"time"

	keycrypto "github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// setupFulfillTest returns a handler whose Stripe calls hit a stub that
// knows no subscriptions or customers, so plans resolve from metadata.
func setupFulfillTest(t *testing.T) (*StripeHandler, *store.Store, *model.Plan) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	h, s := setupWebhookTest(t, &fakeStripe{})
	s.LicenseKeyAEAD = keycrypto.MustDeriveAEAD(make([]byte, 32), "license-key")
	ctx := context.Background()

	suffix := time.Now().Format("150405.000000")
	product := &model.Product{Name: "Fulfill Test", Slug: "fulfill-test-" + suffix, Type: "saas"}
	if err := s.CreateProduct(ctx, product); err != nil {
		t.Fatal(err)
	}
	plan := &model.Plan{
		ProductID: product.ID, Name: "Monthly", Slug: "monthly-" + suffix,
		LicenseType: "subscription", LicenseModel: "standard", MaxActivations: 3,
	}
	if err := s.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	return h, s, plan
}

func licensesFor(t *testing.T, s *store.Store, email, productID string) []*model.License {
	t.Helper()
	all, err := s.ListLicensesByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	var out []*model.License
	for _, l := range all {
		if l.ProductID == productID && l.Email == email {
			out = append(out, l)
		}
	}
	return out
}

func checkoutMeta(sessionID, planID string) map[string]string {
	return map[string]string{"session_id": sessionID, "plan_id": planID}
}

// One buyer purchasing the same product twice (e.g. for two employees)
// gets two licenses; replaying either session creates nothing new.
func TestFulfillCheckoutCreatesLicensePerSession(t *testing.T) {
	h, s, plan := setupFulfillTest(t)
	ctx := context.Background()
	email := "buyer-" + plan.Slug + "@example.com"

	h.fulfillCheckout(ctx, email, "", "sub_a_"+plan.Slug, checkoutMeta("cs_a_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, "", "sub_b_"+plan.Slug, checkoutMeta("cs_b_"+plan.Slug, plan.ID), "webhook")
	// Webhook, success page and sync all see the same sessions.
	h.fulfillCheckout(ctx, email, "", "sub_a_"+plan.Slug, checkoutMeta("cs_a_"+plan.Slug, plan.ID), "verify")
	h.fulfillCheckout(ctx, email, "", "sub_b_"+plan.Slug, checkoutMeta("cs_b_"+plan.Slug, plan.ID), "sync")

	lics := licensesFor(t, s, email, plan.ProductID)
	if len(lics) != 2 {
		t.Fatalf("got %d licenses, want 2", len(lics))
	}
	if lics[0].StripeSubscriptionID == lics[1].StripeSubscriptionID {
		t.Fatalf("licenses share subscription %q", lics[0].StripeSubscriptionID)
	}
}

// A subscription that already backs a license is not fulfilled again,
// even under a session ID that was never claimed.
func TestFulfillCheckoutSkipsSubscriptionWithLicense(t *testing.T) {
	h, s, plan := setupFulfillTest(t)
	ctx := context.Background()
	email := "buyer-" + plan.Slug + "@example.com"
	sub := "sub_existing_" + plan.Slug

	h.fulfillCheckout(ctx, email, "", sub, checkoutMeta("cs_first_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, "", sub, checkoutMeta("cs_other_"+plan.Slug, plan.ID), "sync")

	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 1 {
		t.Fatalf("got %d licenses, want 1", n)
	}
}

// A fulfillment that fails before the license exists must not consume the
// session, or later retries (success page, sync) silently skip the purchase.
func TestFulfillCheckoutReleasesClaimOnFailure(t *testing.T) {
	h, s, plan := setupFulfillTest(t)
	ctx := context.Background()
	email := "buyer-" + plan.Slug + "@example.com"
	session := "cs_retry_" + plan.Slug

	// Unknown plan: nothing can be created.
	h.fulfillCheckout(ctx, email, "", "", checkoutMeta(session, "00000000-0000-0000-0000-000000000000"), "webhook")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 0 {
		t.Fatalf("got %d licenses after failed fulfillment, want 0", n)
	}

	h.fulfillCheckout(ctx, email, "", "", checkoutMeta(session, plan.ID), "sync")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 1 {
		t.Fatalf("got %d licenses after retry, want 1", n)
	}
}
