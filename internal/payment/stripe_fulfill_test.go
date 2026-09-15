package payment

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
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
	return setupFulfillTestWith(t, &fakeStripe{})
}

func setupFulfillTestWith(t *testing.T, fake *fakeStripe) (*StripeHandler, *store.Store, *model.Plan) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	h, s := setupWebhookTest(t, fake)
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

	h.fulfillCheckout(ctx, email, "", "sub_a_"+plan.Slug, "", checkoutMeta("cs_a_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, "", "sub_b_"+plan.Slug, "", checkoutMeta("cs_b_"+plan.Slug, plan.ID), "webhook")
	// Webhook, success page and sync all see the same sessions.
	h.fulfillCheckout(ctx, email, "", "sub_a_"+plan.Slug, "", checkoutMeta("cs_a_"+plan.Slug, plan.ID), "verify")
	h.fulfillCheckout(ctx, email, "", "sub_b_"+plan.Slug, "", checkoutMeta("cs_b_"+plan.Slug, plan.ID), "sync")

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

	h.fulfillCheckout(ctx, email, "", sub, "", checkoutMeta("cs_first_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, "", sub, "", checkoutMeta("cs_other_"+plan.Slug, plan.ID), "sync")

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
	h.fulfillCheckout(ctx, email, "", "", "", checkoutMeta(session, "00000000-0000-0000-0000-000000000000"), "webhook")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 0 {
		t.Fatalf("got %d licenses after failed fulfillment, want 0", n)
	}

	h.fulfillCheckout(ctx, email, "", "", "", checkoutMeta(session, plan.ID), "sync")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 1 {
		t.Fatalf("got %d licenses after retry, want 1", n)
	}
}

// The request context is often why fulfillment failed (client disconnect),
// so releasing the claim must not depend on it.
func TestFulfillCheckoutReleasesClaimWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel once the claim is taken, while resolvePlan asks Stripe for
	// the subscription.
	fake := &fakeStripe{onRequest: func(r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/subscriptions/") {
			cancel()
		}
	}}
	h, s, plan := setupFulfillTestWith(t, fake)
	email := "buyer-" + plan.Slug + "@example.com"
	session := "cs_cancel_" + plan.Slug
	sub := "sub_cancel_" + plan.Slug

	h.fulfillCheckout(ctx, email, "", sub, "", checkoutMeta(session, plan.ID), "verify")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 0 {
		t.Fatalf("got %d licenses with canceled context, want 0", n)
	}

	h.fulfillCheckout(context.Background(), email, "", sub, "", checkoutMeta(session, plan.ID), "sync")
	if n := len(licensesFor(t, s, email, plan.ProductID)); n != 1 {
		t.Fatalf("got %d licenses after retry, want 1", n)
	}
}

// Two purchases by the same Stripe customer: refunding the older one must
// revoke its license, not the customer's newest.
func TestChargeRefundRevokesPurchasedLicense(t *testing.T) {
	fake := &fakeStripe{}
	h, s, plan := setupFulfillTestWith(t, fake)
	ctx := context.Background()
	email := "buyer-" + plan.Slug + "@example.com"
	customer := "cus_shared_" + plan.Slug
	subOld, subNew := "sub_old_"+plan.Slug, "sub_new_"+plan.Slug
	fake.invoicePaymentSubs = map[string]string{"pi_old": subOld, "pi_new": subNew}

	h.fulfillCheckout(ctx, email, customer, subOld, "", checkoutMeta("cs_old_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, customer, subNew, "", checkoutMeta("cs_new_"+plan.Slug, plan.ID), "webhook")

	refund := func(pi string) {
		raw, _ := json.Marshal(map[string]any{
			"id": "ch_" + pi, "customer": customer, "payment_intent": pi,
			"amount": 1299, "amount_refunded": 1299, "refunded": true,
		})
		h.onChargeRefunded(ctx, raw)
	}
	statuses := func() map[string]string {
		out := map[string]string{}
		for _, l := range licensesFor(t, s, email, plan.ProductID) {
			out[l.StripeSubscriptionID] = l.Status
		}
		return out
	}

	refund("pi_old")
	if got := statuses(); got[subOld] != model.StatusRevoked || got[subNew] != model.StatusActive {
		t.Fatalf("after refunding the older purchase: %v", got)
	}

	// Without a subscription to trace, a customer with several licenses is
	// ambiguous: nothing is revoked.
	refund("pi_unknown")
	if got := statuses(); got[subNew] != model.StatusActive {
		t.Fatalf("ambiguous refund changed licenses: %v", got)
	}
}

// One-time purchases have no subscription to trace: each license stores
// its payment intent, so a refund revokes the purchase it belongs to even
// when the customer bought several lifetime licenses.
func TestChargeRefundRevokesOneTimePurchase(t *testing.T) {
	h, s, plan := setupFulfillTestWith(t, &fakeStripe{})
	ctx := context.Background()
	email := "buyer-" + plan.Slug + "@example.com"
	customer := "cus_lifetime_" + plan.Slug
	piOld, piNew := "pi_old_"+plan.Slug, "pi_new_"+plan.Slug

	h.fulfillCheckout(ctx, email, customer, "", piOld, checkoutMeta("cs_old_"+plan.Slug, plan.ID), "webhook")
	h.fulfillCheckout(ctx, email, customer, "", piNew, checkoutMeta("cs_new_"+plan.Slug, plan.ID), "webhook")
	// Same payment under another session ID (e.g. replayed) adds nothing.
	h.fulfillCheckout(ctx, email, customer, "", piNew, checkoutMeta("cs_dup_"+plan.Slug, plan.ID), "sync")

	statuses := func() map[string]string {
		out := map[string]string{}
		for _, l := range licensesFor(t, s, email, plan.ProductID) {
			out[l.StripePaymentIntentID] = l.Status
		}
		return out
	}
	if got := statuses(); len(got) != 2 {
		t.Fatalf("licenses by payment intent = %v, want 2 purchases", got)
	}

	raw, _ := json.Marshal(map[string]any{
		"id": "ch_" + piOld, "customer": customer, "payment_intent": piOld,
		"amount": 9900, "amount_refunded": 9900, "refunded": true,
	})
	h.onChargeRefunded(ctx, raw)

	if got := statuses(); got[piOld] != model.StatusRevoked || got[piNew] != model.StatusActive {
		t.Fatalf("after refunding the older purchase: %v", got)
	}
}
