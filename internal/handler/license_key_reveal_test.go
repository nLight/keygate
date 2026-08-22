package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// A license key is a credential: it activates the product. It must never ride
// along with the list payload, only be handed out one at a time through an
// audited endpoint.
func TestRevealLicenseKeyIsOnDemandAndAudited(t *testing.T) {
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
	aead, err := crypto.NewAESGCMFromHex(strings.Repeat("ab", crypto.MasterKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	s.LicenseKeyAEAD = aead

	ctx := context.Background()
	cleanup := func() {
		_, _ = s.DB.NewRaw("DELETE FROM audit_logs WHERE entity_id IN (SELECT id FROM licenses WHERE email = 'reveal@example.com')").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM licenses WHERE email = 'reveal@example.com'").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM plans WHERE product_id IN (SELECT id FROM products WHERE slug = 'reveal-product')").Exec(ctx)
		_, _ = s.DB.NewRaw("DELETE FROM products WHERE slug = 'reveal-product'").Exec(ctx)
	}
	cleanup()
	t.Cleanup(cleanup)

	productID, planID := store.NewID(), store.NewID()
	if _, err := s.DB.NewRaw(
		"INSERT INTO products (id, name, slug, type, created_at) VALUES (?, 'Reveal Product', 'reveal-product', 'desktop', now())",
		productID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.NewRaw(
		"INSERT INTO plans (id, product_id, name, slug, license_type, max_activations, max_seats, grace_days, active, checkout_id, created_at) VALUES (?, ?, 'Pro', 'reveal-pro', 'perpetual', 3, 0, 7, true, ?, now())",
		planID, productID, store.ShortID()).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	const plaintextKey = "KG-REVEAL-TEST-A7F3"
	lic := &model.License{
		ProductID: productID, PlanID: planID,
		Email: "reveal@example.com", LicenseKey: plaintextKey, Status: model.StatusActive,
	}
	if err := s.CreateLicense(ctx, lic); err != nil {
		t.Fatal(err)
	}

	h := &AdminHandler{Store: s}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/admin/licenses", h.ListLicenses)
	router.GET("/api/v1/admin/licenses/:id/key", h.RevealLicenseKey)

	// The list carries only the four-character hint, never the key.
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/licenses?search=reveal@example.com", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	if strings.Contains(listRecorder.Body.String(), plaintextKey) {
		t.Fatal("list response leaked the license key")
	}
	var listBody struct {
		Data struct {
			Hints map[string]string `json:"license_key_hints"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listBody); err != nil {
		t.Fatal(err)
	}
	if got := listBody.Data.Hints[lic.ID]; got != "A7F3" {
		t.Fatalf("hint=%q want %q", got, "A7F3")
	}

	// The reveal endpoint hands out the real key.
	revealRecorder := httptest.NewRecorder()
	router.ServeHTTP(revealRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/licenses/"+lic.ID+"/key", nil))
	if revealRecorder.Code != http.StatusOK {
		t.Fatalf("reveal status=%d body=%s", revealRecorder.Code, revealRecorder.Body.String())
	}
	var revealBody struct {
		Data struct {
			LicenseKey string `json:"license_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(revealRecorder.Body.Bytes(), &revealBody); err != nil {
		t.Fatal(err)
	}
	if revealBody.Data.LicenseKey != plaintextKey {
		t.Fatalf("license_key=%q want %q", revealBody.Data.LicenseKey, plaintextKey)
	}
	if cc := revealRecorder.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q want no-store", cc)
	}

	// Every reveal is auditable, and the audit row must not carry the key.
	var action, changes string
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := s.DB.NewRaw(
			"SELECT action, changes::text FROM audit_logs WHERE entity = 'license' AND entity_id = ? AND action = 'key_revealed'",
			lic.ID).Scan(ctx, &action, &changes)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if action != "key_revealed" {
		t.Fatal("no audit entry written for the reveal")
	}
	if strings.Contains(changes, plaintextKey) {
		t.Fatalf("audit entry leaked the license key: %s", changes)
	}

	// Unknown ids stay 404 rather than confirming existence some other way.
	missingRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/licenses/"+store.NewID()+"/key", nil))
	if missingRecorder.Code != http.StatusNotFound {
		t.Fatalf("missing license status=%d", missingRecorder.Code)
	}
}
