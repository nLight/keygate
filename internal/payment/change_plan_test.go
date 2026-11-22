package payment

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v82"

	keycrypto "github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// A plan change in the portal is always prorated. The customer could
// once send "prorate": false and move to a dearer plan for the rest of
// the period without paying the difference, then move back before the
// renewal. (Ported from upstream fe9519e.)
func TestChangePlan_AlwaysProrates(t *testing.T) {
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

	suffix := time.Now().Format("150405.000000")
	prod := &model.Product{Name: "Prorate", Slug: "prorate-" + suffix, Type: "saas"}
	if err := s.CreateProduct(ctx, prod); err != nil {
		t.Fatalf("create product: %v", err)
	}
	mkPlan := func(name string) *model.Plan {
		p := &model.Plan{ProductID: prod.ID, Name: name, Slug: "pr-" + name + "-" + suffix, LicenseType: "subscription",
			LicenseModel: "standard", StripePriceID: "price_pr_" + name + "_" + suffix, Active: true}
		if err := s.CreatePlan(ctx, p); err != nil {
			t.Fatalf("create plan %s: %v", name, err)
		}
		return p
	}
	basic, business := mkPlan("basic"), mkPlan("business")
	subID := "sub_pr_" + suffix
	lic := &model.License{ProductID: prod.ID, PlanID: basic.ID, Email: "prorate-" + suffix + "@example.com",
		LicenseKey: "KEY-pr-" + suffix, Status: "active", PaymentProvider: "stripe", StripeSubscriptionID: subID}
	if err := s.CreateLicense(ctx, lic); err != nil {
		t.Fatalf("create licence: %v", err)
	}

	var mu sync.Mutex
	var behaviours []string
	subJSON := fmt.Sprintf(`{"id":%q,"object":"subscription","status":"active","items":{"object":"list","data":[{"id":"si_pr","object":"subscription_item"}]}}`, subID)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions/"+subID {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			mu.Lock()
			behaviours = append(behaviours, r.PostForm.Get("proration_behavior"))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, subJSON)
	}))
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
	for _, body := range []string{
		fmt.Sprintf(`{"license_id":%q,"new_price_id":%q,"prorate":false}`, lic.ID, business.StripePriceID),
		fmt.Sprintf(`{"license_id":%q,"new_price_id":%q}`, lic.ID, basic.StripePriceID),
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/portal/subscription/change-plan", bytes.NewBufferString(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("email", lic.Email)
		h := &StripeHandler{Store: s}
		h.ChangePlan(c)
		if w.Code != http.StatusOK {
			t.Fatalf("change plan = %d: %s", w.Code, w.Body.String())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(behaviours) != 2 || behaviours[0] != "create_prorations" || behaviours[1] != "create_prorations" {
		t.Fatalf("proration_behavior sent to Stripe = %v, want create_prorations both times", behaviours)
	}
}

// Cancel at period end with no cancel_at in Stripe's answer leaves
// valid_until alone (the webhook sets it); it used to become 1970-01-01,
// ending the licence at once.
func TestCancelAtPeriodEndWithoutCancelAtKeepsValidUntil(t *testing.T) {
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
	suffix := time.Now().Format("150405.000000")
	prod := &model.Product{Name: "Cancel", Slug: "cancel-" + suffix, Type: "saas"}
	if err := s.CreateProduct(ctx, prod); err != nil {
		t.Fatal(err)
	}
	plan := &model.Plan{ProductID: prod.ID, Name: "p", Slug: "c-" + suffix, LicenseType: "subscription", LicenseModel: "standard", Active: true}
	if err := s.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	subID := "sub_cn_" + suffix
	until := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	lic := &model.License{ProductID: prod.ID, PlanID: plan.ID, Email: "cancel-" + suffix + "@example.com",
		LicenseKey: "KEY-cn-" + suffix, Status: "active", PaymentProvider: "stripe", StripeSubscriptionID: subID, ValidUntil: &until}
	if err := s.CreateLicense(ctx, lic); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(`{"id":%q,"object":"subscription","status":"active","cancel_at_period_end":true,"cancel_at":0}`, subID))
	}))
	t.Cleanup(srv.Close)
	prevKey := stripe.Key
	stripe.Key = "sk_test_fake"
	stripe.SetBackend(stripe.APIBackend, stripe.GetBackendWithConfig(stripe.APIBackend, &stripe.BackendConfig{
		URL: stripe.String(srv.URL), MaxNetworkRetries: stripe.Int64(0),
		LeveledLogger: &stripe.LeveledLogger{Level: stripe.LevelNull},
	}))
	t.Cleanup(func() { stripe.Key = prevKey; stripe.SetBackend(stripe.APIBackend, nil) })

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/portal/subscription/cancel",
		bytes.NewBufferString(fmt.Sprintf(`{"license_id":%q}`, lic.ID)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("email", lic.Email)
	(&StripeHandler{Store: s}).CancelSubscription(c)
	if w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	got, err := s.FindLicenseByID(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ValidUntil == nil || !got.ValidUntil.Equal(until) {
		t.Errorf("valid_until = %v, want unchanged %v", got.ValidUntil, until)
	}
}
