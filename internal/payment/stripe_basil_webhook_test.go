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
	"sync"
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

// fakeSubscriptionItems serves GET /v1/subscription_items for one
// subscription, paginating pageSize items at a time.
type fakeSubscriptionItems struct {
	subID      string
	periodEnds []int64
	pageSize   int
	status     int // non-200 fails every request

	mu       sync.Mutex
	requests int
}

func (f *fakeSubscriptionItems) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet || r.URL.Path != "/v1/subscription_items" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.status != 0 && f.status != http.StatusOK {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"error":{"type":"api_error","message":"unavailable"}}`))
		return
	}
	if got := r.URL.Query().Get("subscription"); got != f.subID {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"wrong subscription"}}`))
		return
	}
	start := 0
	if after := r.URL.Query().Get("starting_after"); after != "" {
		_, _ = fmt.Sscanf(after, "si_%d", &start)
		start++
	}
	size := f.pageSize
	if size <= 0 {
		size = len(f.periodEnds)
	}
	end := min(start+size, len(f.periodEnds))
	data := []map[string]any{}
	for i := start; i < end; i++ {
		data = append(data, map[string]any{
			"id": fmt.Sprintf("si_%d", i), "object": "subscription_item",
			"subscription": f.subID, "current_period_end": f.periodEnds[i],
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list", "url": "/v1/subscription_items", "data": data, "has_more": end < len(f.periodEnds),
	})
}

// setupBasilWebhookTest returns a handler wired to Postgres, a
// subscription license keyed by a unique Stripe subscription ID, and a
// stubbed Stripe API whose subscription items end at renewalPeriodEnd.
func setupBasilWebhookTest(t *testing.T, status string) (*StripeHandler, *store.Store, *model.License, *fakeSubscriptionItems) {
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

	fake := &fakeSubscriptionItems{subID: lic.StripeSubscriptionID, periodEnds: []int64{renewalPeriodEnd}}
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

	h := &StripeHandler{Store: s}
	h.SetWebhookSecret(basilTestSecret)
	return h, s, lic, fake
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
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusPastDue)

	deliverEvent(t, h, "invoice.paid", fixtureFor(t, "invoice_paid_renewal.json", lic))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusActive || got.PastDueAt != nil {
		t.Fatalf("status=%q past_due_at=%v, want active with past_due_at cleared", got.Status, got.PastDueAt)
	}
	assertValidUntil(t, got, renewalPeriodEnd)
}

// invoiceWithLines builds a subscription invoice for lic whose embedded
// line list is lines (each a JSON object) with the given has_more.
func invoiceWithLines(lic *model.License, hasMore bool, lines ...string) []byte {
	return []byte(fmt.Sprintf(`{"id":"in_test","object":"invoice","status":"paid","period_end":%d,
		"parent":{"type":"subscription_details","subscription_details":{"subscription":%q}},
		"lines":{"object":"list","data":[%s],"has_more":%t}}`,
		invoicePeriodEnd, lic.StripeSubscriptionID, strings.Join(lines, ","), hasMore))
}

func invoiceLine(lic *model.License, amount, start, end int64, proration bool) string {
	return fmt.Sprintf(`{"object":"line_item","amount":%d,"period":{"start":%d,"end":%d},
		"parent":{"type":"subscription_item_details","subscription_item_details":{"proration":%t,"subscription":%q,"subscription_item":"si_0"}}}`,
		amount, start, end, proration, lic.StripeSubscriptionID)
}

// Annual → monthly with prorations: the invoice credits the unused
// annual term (ending 2027-01-01) and charges the new month. The credit
// period must not become the paid-through date.
func TestBasilInvoicePaidIgnoresCreditProration(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)

	deliverEvent(t, h, "customer.subscription.updated", fixtureFor(t, "subscription_updated.json", lic))
	assertValidUntil(t, reloadLicense(t, s, lic), renewalPeriodEnd)

	const annualEnd = int64(1798761600) // 2027-01-01
	deliverEvent(t, h, "invoice.paid", invoiceWithLines(lic, false,
		invoiceLine(lic, -22000, invoicePeriodEnd, annualEnd, true),
		invoiceLine(lic, 1900, invoicePeriodEnd, renewalPeriodEnd, false),
	))

	assertValidUntil(t, reloadLicense(t, s, lic), renewalPeriodEnd)
}

// The embedded line list is truncated to prorations that end at the
// previous cycle boundary; the renewal line is on a later page.
func TestBasilInvoicePaidTruncatedLinesKeepsRenewal(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)

	deliverEvent(t, h, "customer.subscription.updated", fixtureFor(t, "subscription_updated.json", lic))

	lines := make([]string, 10)
	for i := range lines {
		lines[i] = invoiceLine(lic, 100, invoicePeriodEnd-86400, invoicePeriodEnd, true)
	}
	deliverEvent(t, h, "invoice.paid", invoiceWithLines(lic, true, lines...))

	assertValidUntil(t, reloadLicense(t, s, lic), renewalPeriodEnd)
}

func TestBasilInvoicePaidStripeUnavailableKeepsValidUntil(t *testing.T) {
	h, s, lic, fake := setupBasilWebhookTest(t, model.StatusPastDue)
	fake.status = http.StatusInternalServerError

	deliverEvent(t, h, "invoice.paid", fixtureFor(t, "invoice_paid_renewal.json", lic))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusActive {
		t.Fatalf("status=%q, want active", got.Status)
	}
	assertValidUntil(t, got, invoicePeriodEnd)
}

func TestBasilSubscriptionUpdatedUsesItemPeriod(t *testing.T) {
	h, s, lic, fake := setupBasilWebhookTest(t, model.StatusPastDue)

	deliverEvent(t, h, "customer.subscription.updated", fixtureFor(t, "subscription_updated.json", lic))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusActive || got.PastDueAt != nil {
		t.Fatalf("status=%q past_due_at=%v, want active with past_due_at cleared", got.Status, got.PastDueAt)
	}
	assertValidUntil(t, got, renewalPeriodEnd)
	if fake.requests != 0 {
		t.Fatalf("complete embedded items should not hit the API, got %d requests", fake.requests)
	}
}

func TestBasilSubscriptionUpdatedTruncatedItemsPaginates(t *testing.T) {
	h, s, lic, fake := setupBasilWebhookTest(t, model.StatusActive)
	const laterEnd = int64(1798761600)
	fake.periodEnds = []int64{renewalPeriodEnd, renewalPeriodEnd, laterEnd}
	fake.pageSize = 2

	obj := strings.Replace(string(fixtureFor(t, "subscription_updated.json", lic)),
		`"has_more": false`, `"has_more": true`, 1)
	deliverEvent(t, h, "customer.subscription.updated", []byte(obj))

	assertValidUntil(t, reloadLicense(t, s, lic), laterEnd)
	if fake.requests != 2 {
		t.Fatalf("expected 2 paginated requests, got %d", fake.requests)
	}
}

func TestBasilInvoicePaymentFailedMarksPastDue(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)

	obj := strings.Replace(string(fixtureFor(t, "invoice_paid_renewal.json", lic)),
		`"status": "paid"`, `"status": "open"`, 1)
	deliverEvent(t, h, "invoice.payment_failed", []byte(obj))

	got := reloadLicense(t, s, lic)
	if got.Status != model.StatusPastDue || got.PastDueAt == nil {
		t.Fatalf("status=%q past_due_at=%v, want past_due with anchor set", got.Status, got.PastDueAt)
	}
}

func TestBasilInvoiceUpcomingAndActionRequiredResolveLicense(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)
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
