package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/store"
)

// The admin UI loads GET /admin/settings straight into form state and PUTs
// the whole map back. Server-owned keys must therefore never appear in the
// GET response, and must not fail the PUT when an older client returns them.
func TestAdminSettingsIgnoresServerOwnedKeys(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	s, err := store.New(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RunMigrations("../../db/migrations"); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM settings WHERE key IN ('setup_complete', 'setup_bootstrap_consumed_at', 'stripe_webhook_endpoint_id', 'stripe_webhook_secret', 'logo_url')").Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)

	const consumedAt = "2026-08-21T21:00:00Z"
	const webhookSecret = "whsec_live_signing_secret"
	if err := s.SetSettings(ctx, map[string]string{
		"setup_complete":              "true",
		"setup_bootstrap_consumed_at": consumedAt,
		"stripe_webhook_endpoint_id":  "we_123",
		"stripe_webhook_secret":       webhookSecret,
	}); err != nil {
		t.Fatal(err)
	}

	h := &AdminHandler{Store: s}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/admin/settings", h.GetSettings)
	router.PUT("/api/v1/admin/settings", h.UpdateSettings)

	getRecorder := httptest.NewRecorder()
	router.ServeHTTP(getRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings", nil))
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", getRecorder.Code, getRecorder.Body.String())
	}
	var getBody struct {
		Data struct {
			Settings map[string]string `json:"settings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &getBody); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"setup_complete", "setup_bootstrap_consumed_at", "stripe_webhook_endpoint_id", "stripe_webhook_secret"} {
		if _, ok := getBody.Data.Settings[key]; ok {
			t.Fatalf("GET exposed server-owned key %q", key)
		}
	}
	if strings.Contains(getRecorder.Body.String(), webhookSecret) {
		t.Fatal("GET leaked the Stripe webhook signing secret")
	}

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	// A client echoing the server-owned keys back must still save the rest.
	if w := put(`{"settings":{"logo_url":"https://example.com/logo.png","setup_complete":"false","setup_bootstrap_consumed_at":"tampered","stripe_webhook_secret":"whsec_attacker"}}`); w.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", w.Code, w.Body.String())
	}
	if got, err := s.GetSetting(ctx, "logo_url"); err != nil || got != "https://example.com/logo.png" {
		t.Fatalf("logo_url=%q err=%v", got, err)
	}
	// ...without letting them overwrite the audit trail.
	if got, err := s.GetSetting(ctx, "setup_bootstrap_consumed_at"); err != nil || got != consumedAt {
		t.Fatalf("setup_bootstrap_consumed_at=%q err=%v", got, err)
	}
	if got, err := s.GetSetting(ctx, "setup_complete"); err != nil || got != "true" {
		t.Fatalf("setup_complete=%q err=%v", got, err)
	}
	if got, err := s.GetSetting(ctx, "stripe_webhook_secret"); err != nil || got != webhookSecret {
		t.Fatalf("stripe_webhook_secret=%q err=%v", got, err)
	}

	// Genuinely unknown keys are still rejected.
	if w := put(`{"settings":{"not_a_setting":"x"}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown key status=%d body=%s", w.Code, w.Body.String())
	}
}
