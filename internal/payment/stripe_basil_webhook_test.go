package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"

	keycrypto "github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

const basilTestSecret = "whsec_basil_test"

// setupBasilWebhookTest returns a handler wired to Postgres and a
// subscription license keyed by a unique Stripe subscription ID.
func setupBasilWebhookTest(t *testing.T, status string) (*StripeHandler, *store.Store, *model.License) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	s, err := store.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.RunMigrations("../../db/migrations"); err != nil {
		t.Fatal(err)
	}
	s.LicenseKeyAEAD = keycrypto.MustDeriveAEAD(make([]byte, 32), "license-key")
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	prod := &model.Product{Name: "Basil Test", Slug: "basil-" + suffix, Type: "hybrid"}
	if err := s.CreateProduct(ctx, prod); err != nil {
		t.Fatal(err)
	}
	plan := &model.Plan{
		ProductID: prod.ID, Name: "Pro", Slug: "pro-" + suffix,
		LicenseType: "subscription", LicenseModel: "standard",
	}
	if err := s.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	oldUntil := time.Unix(invoicePeriodEnd, 0)
	lic := &model.License{
		ProductID: prod.ID, PlanID: plan.ID,
		Email:                "basil-" + suffix + "@example.com",
		LicenseKey:           "KEY-basil-" + suffix,
		Status:               status,
		StripeCustomerID:     "cus_" + suffix,
		StripeSubscriptionID: "sub_" + suffix,
		ValidUntil:           &oldUntil,
	}
	if status == model.StatusPastDue {
		pastDue := time.Now().Add(-48 * time.Hour)
		lic.PastDueAt = &pastDue
	}
	if err := s.CreateLicense(ctx, lic); err != nil {
		t.Fatal(err)
	}

	h := &StripeHandler{Store: s}
	h.SetWebhookSecret(basilTestSecret)
	return h, s, lic
}

// deliverEvent signs a basil event wrapping object and runs it through
// the real Webhook entry point.
func deliverEvent(t *testing.T, h *StripeHandler, eventType string, object []byte) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":          fmt.Sprintf("evt_basil_%d", time.Now().UnixNano()),
		"object":      "event",
		"api_version": stripe.APIVersion,
		"created":     time.Now().Unix(),
		"livemode":    false,
		"type":        eventType,
		"data":        map[string]json.RawMessage{"object": object},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: basilTestSecret})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/stripe", h.Webhook)
	req := httptest.NewRequest(http.MethodPost, "/stripe", bytes.NewReader(payload))
	req.Header.Set("Stripe-Signature", signed.Header)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "skipped") {
		t.Fatalf("webhook %s: status=%d body=%s", eventType, w.Code, w.Body.String())
	}
}

// fixtureFor rewrites the fixture's subscription/customer IDs to the
// test license's.
func fixtureFor(t *testing.T, name string, lic *model.License) []byte {
	raw := string(readFixture(t, name))
	raw = strings.ReplaceAll(raw, renewalSubID, lic.StripeSubscriptionID)
	raw = strings.ReplaceAll(raw, "cus_Basil123", lic.StripeCustomerID)
	return []byte(raw)
}

func reloadLicense(t *testing.T, s *store.Store, lic *model.License) *model.License {
	t.Helper()
	got, err := s.FindLicenseByStripeSubscription(context.Background(), lic.StripeSubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertValidUntil(t *testing.T, lic *model.License, want int64) {
	t.Helper()
	if lic.ValidUntil == nil || lic.ValidUntil.Unix() != want {
		t.Fatalf("valid_until = %v, want %v", lic.ValidUntil, time.Unix(want, 0).UTC())
	}
}

func TestBasilInvoicePaidRenewalExtendsValidUntil(t *testing.T) {
	h, s, lic := setupBasilWebhookTest(t, model.StatusPastDue)

	deliverEvent(t, h, "invoice.paid", fixtureFor(t, "invoice_paid_renewal.json", lic))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusActive || got.PastDueAt != nil {
		t.Fatalf("status=%q past_due_at=%v, want active with past_due_at cleared", got.Status, got.PastDueAt)
	}
	assertValidUntil(t, got, renewalPeriodEnd)
}

func TestBasilInvoicePaidWithoutLinesKeepsValidUntil(t *testing.T) {
	h, s, lic := setupBasilWebhookTest(t, model.StatusActive)

	obj := fmt.Sprintf(`{"id":"in_nolines","object":"invoice","period_end":1,
		"parent":{"type":"subscription_details","subscription_details":{"subscription":%q}},
		"lines":{"object":"list","data":[],"has_more":false}}`, lic.StripeSubscriptionID)
	deliverEvent(t, h, "invoice.paid", []byte(obj))

	assertValidUntil(t, reloadLicense(t, s, lic), invoicePeriodEnd)
}

func TestBasilSubscriptionUpdatedUsesItemPeriod(t *testing.T) {
	h, s, lic := setupBasilWebhookTest(t, model.StatusPastDue)

	deliverEvent(t, h, "customer.subscription.updated", fixtureFor(t, "subscription_updated.json", lic))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusActive || got.PastDueAt != nil {
		t.Fatalf("status=%q past_due_at=%v, want active with past_due_at cleared", got.Status, got.PastDueAt)
	}
	assertValidUntil(t, got, renewalPeriodEnd)
}

func TestBasilInvoicePaymentFailedMarksPastDue(t *testing.T) {
	h, s, lic := setupBasilWebhookTest(t, model.StatusActive)

	obj := strings.Replace(string(fixtureFor(t, "invoice_paid_renewal.json", lic)),
		`"status": "paid"`, `"status": "open"`, 1)
	deliverEvent(t, h, "invoice.payment_failed", []byte(obj))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusPastDue || got.PastDueAt == nil {
		t.Fatalf("status=%q past_due_at=%v, want past_due with anchor set", got.Status, got.PastDueAt)
	}
}

func TestBasilInvoiceUpcomingAndActionRequiredResolveLicense(t *testing.T) {
	h, s, lic := setupBasilWebhookTest(t, model.StatusActive)
	obj := fixtureFor(t, "invoice_paid_renewal.json", lic)

	deliverEvent(t, h, "invoice.upcoming", obj)
	deliverEvent(t, h, "invoice.payment_action_required", obj)

	// Store.Audit writes asynchronously.
	want := "invoice_upcoming,payment_action_required"
	var actions []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		actions = nil
		if err := s.DB.NewRaw(
			`SELECT action FROM audit_logs WHERE entity = 'license' AND entity_id = ? ORDER BY action`, lic.ID,
		).Scan(context.Background(), &actions); err != nil {
			t.Fatal(err)
		}
		if strings.Join(actions, ",") == want {
			return
		}
	}
	t.Fatalf("audit actions = %v, want %s", actions, want)
}
