package payment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stripe/stripe-go/v82"

	"github.com/tabloy/keygate/internal/store"
)

const testBaseURL = "https://keygate.example"

// fakeStripe serves the webhook endpoint API. existing is the endpoint
// returned for GET; createStatus != 200 makes creation fail.
// invoicePaymentSubs maps a payment intent to the subscription whose
// invoice it paid; onRequest, if set, runs before every request.
type fakeStripe struct {
	existing           map[string]any
	createStatus       int
	invoicePaymentSubs map[string]string
	onRequest          func(*http.Request)

	mu       sync.Mutex
	created  []string // raw form bodies of create requests
	deleted  []string // endpoint IDs
	getCount int
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if f.onRequest != nil {
		f.onRequest(r)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/invoice_payments":
		data := []any{}
		if sub := f.invoicePaymentSubs[r.URL.Query().Get("payment[payment_intent]")]; sub != "" {
			data = append(data, map[string]any{
				"id": "inpay_" + sub, "object": "invoice_payment",
				"invoice": map[string]any{
					"id": "in_" + sub, "object": "invoice",
					"parent": map[string]any{
						"type":                 "subscription_details",
						"subscription_details": map[string]any{"subscription": sub},
					},
				},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list", "url": "/v1/invoice_payments", "has_more": false, "data": data,
		})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/webhook_endpoints/"):
		f.getCount++
		_ = json.NewEncoder(w).Encode(f.existing)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/webhook_endpoints":
		_ = r.ParseForm()
		f.created = append(f.created, r.PostForm.Encode())
		if f.createStatus != 0 && f.createStatus != http.StatusOK {
			w.WriteHeader(f.createStatus)
			_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"endpoint limit reached"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "we_new", "object": "webhook_endpoint", "secret": "whsec_new",
			"status": "enabled", "url": r.PostForm.Get("url"), "api_version": r.PostForm.Get("api_version"),
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/webhook_endpoints/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/webhook_endpoints/")
		f.deleted = append(f.deleted, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "object": "webhook_endpoint", "deleted": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func setupWebhookTest(t *testing.T, fake *fakeStripe) (*StripeHandler, *store.Store) {
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
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM settings WHERE key IN (?, ?)", settingWebhookEndpointID, settingWebhookSecret).Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)
	if err := s.SetSettings(ctx, map[string]string{
		settingWebhookEndpointID: "we_old",
		settingWebhookSecret:     "whsec_old",
	}); err != nil {
		t.Fatal(err)
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

	return &StripeHandler{Store: s, BaseURL: testBaseURL}, s
}

func existingEndpoint(apiVersion any) map[string]any {
	return map[string]any{
		"id": "we_old", "object": "webhook_endpoint", "status": "enabled",
		"url": testBaseURL + "/api/v1/webhook/stripe", "api_version": apiVersion,
	}
}

func assertStoredEndpoint(t *testing.T, s *store.Store, wantID, wantSecret string) {
	t.Helper()
	ctx := context.Background()
	id, _ := s.GetSetting(ctx, settingWebhookEndpointID)
	secret, _ := s.GetSetting(ctx, settingWebhookSecret)
	if id != wantID || secret != wantSecret {
		t.Fatalf("stored endpoint = (%q, %q), want (%q, %q)", id, secret, wantID, wantSecret)
	}
}

func TestWebhookSetupKeepsMatchingEndpoint(t *testing.T) {
	fake := &fakeStripe{existing: existingEndpoint(stripe.APIVersion)}
	h, s := setupWebhookTest(t, fake)

	if err := h.ensureWebhookEndpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.GetWebhookSecret(); got != "whsec_old" {
		t.Fatalf("secret = %q, want whsec_old", got)
	}
	if len(fake.created) != 0 || len(fake.deleted) != 0 {
		t.Fatalf("unexpected mutations: created=%v deleted=%v", fake.created, fake.deleted)
	}
	assertStoredEndpoint(t, s, "we_old", "whsec_old")
}

func TestWebhookSetupReplacesVersionMismatch(t *testing.T) {
	fake := &fakeStripe{existing: existingEndpoint(nil)}
	h, s := setupWebhookTest(t, fake)

	if err := h.ensureWebhookEndpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.created) != 1 || !strings.Contains(fake.created[0], "api_version="+stripe.APIVersion) {
		t.Fatalf("create requests = %v, want one pinned to %s", fake.created, stripe.APIVersion)
	}
	if got := h.GetWebhookSecret(); got != "whsec_new" {
		t.Fatalf("secret = %q, want whsec_new", got)
	}
	assertStoredEndpoint(t, s, "we_new", "whsec_new")
	if len(fake.deleted) != 1 || fake.deleted[0] != "we_old" {
		t.Fatalf("deleted = %v, want [we_old]", fake.deleted)
	}
}

// A failed replacement must leave the existing endpoint fully usable:
// the handler keeps verifying its deliveries and nothing is deleted.
func TestWebhookSetupKeepsOldSecretWhenReplacementFails(t *testing.T) {
	fake := &fakeStripe{existing: existingEndpoint(nil), createStatus: http.StatusBadRequest}
	h, s := setupWebhookTest(t, fake)

	if err := h.ensureWebhookEndpoint(context.Background()); err == nil {
		t.Fatal("expected error when endpoint creation fails")
	}
	if got := h.GetWebhookSecret(); got != "whsec_old" {
		t.Fatalf("secret = %q, want whsec_old", got)
	}
	if len(fake.deleted) != 0 {
		t.Fatalf("deleted = %v, want none", fake.deleted)
	}
	assertStoredEndpoint(t, s, "we_old", "whsec_old")
}
