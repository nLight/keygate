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

	keycrypto "github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

func TestExportLicensesEnforcesProductScopeForJSONAndCSV(t *testing.T) {
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
	s.LicenseKeyAEAD = keycrypto.MustDeriveAEAD(make([]byte, 32), "license-key")

	ctx := context.Background()
	suffix := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "-")
	p1 := &model.Product{Name: "Scoped Product", Slug: "export-scoped-" + suffix, Type: model.ProductTypeDesktop}
	p2 := &model.Product{Name: "Foreign Product", Slug: "export-foreign-" + suffix, Type: model.ProductTypeDesktop}
	if err := s.CreateProduct(ctx, p1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProduct(ctx, p2); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.NewRaw("DELETE FROM licenses WHERE product_id IN (?, ?)", p1.ID, p2.ID).Exec(context.Background())
		_, _ = s.DB.NewRaw("DELETE FROM plans WHERE product_id IN (?, ?)", p1.ID, p2.ID).Exec(context.Background())
		_, _ = s.DB.NewRaw("DELETE FROM products WHERE id IN (?, ?)", p1.ID, p2.ID).Exec(context.Background())
	})
	plan1 := &model.Plan{ProductID: p1.ID, Name: "Pro", Slug: "pro", LicenseType: "perpetual", LicenseModel: "standard", MaxActivations: 1}
	plan2 := &model.Plan{ProductID: p2.ID, Name: "Pro", Slug: "pro", LicenseType: "perpetual", LicenseModel: "standard", MaxActivations: 1}
	if err := s.CreatePlan(ctx, plan1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePlan(ctx, plan2); err != nil {
		t.Fatal(err)
	}
	ownKey := "KGT-EXPORT-OWN-" + suffix
	foreignKey := "KGT-EXPORT-FOREIGN-" + suffix
	if err := s.CreateLicense(ctx, &model.License{ProductID: p1.ID, PlanID: plan1.ID, Email: "own@example.com", LicenseKey: ownKey, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateLicense(ctx, &model.License{ProductID: p2.ID, PlanID: plan2.ID, Email: "foreign@example.com", LicenseKey: foreignKey, Status: model.StatusActive}); err != nil {
		t.Fatal(err)
	}

	h := &AdminHandler{Store: s}
	request := func(format, productID string, apiKey *model.APIKey) *httptest.ResponseRecorder {
		t.Helper()
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.GET("/export", func(c *gin.Context) {
			c.Set("request_id", "export-security-test")
			if apiKey != nil {
				c.Set("api_key", apiKey)
				c.Set("auth_type", "api_key")
			} else {
				c.Set("auth_type", "session")
				c.Set("user_id", "test-admin")
			}
			h.ExportLicenses(c)
		})
		path := "/export?format=" + format
		if productID != "" {
			path += "&product_id=" + productID
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}

	scoped := &model.APIKey{ID: "scoped-export-key-" + suffix, ProductID: p1.ID}
	for _, format := range []string{"json", "csv"} {
		t.Run("scoped omitted product "+format, func(t *testing.T) {
			w := request(format, "", scoped)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), ownKey) || strings.Contains(w.Body.String(), foreignKey) {
				t.Fatalf("scoped %s export crossed product boundary: %s", format, w.Body.String())
			}
		})
	}

	if w := request("json", p2.ID, scoped); w.Code != http.StatusForbidden {
		t.Fatalf("foreign product status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request("json", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), ownKey) || !strings.Contains(w.Body.String(), foreignKey) {
		t.Fatalf("unscoped administrator lost cross-product export: status=%d body=%s", w.Code, w.Body.String())
	}

	var scopedAudits []*model.AuditLog
	if err := s.DB.NewSelect().Model(&scopedAudits).
		Where("entity = 'license_export' AND actor_id = ?", scoped.ID).
		Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(scopedAudits) != 2 {
		t.Fatalf("scoped export audit rows=%d, want 2", len(scopedAudits))
	}
	for _, audit := range scopedAudits {
		encoded, _ := json.Marshal(audit.Changes)
		if !strings.Contains(string(encoded), p1.ID) || strings.Contains(string(encoded), ownKey) || strings.Contains(string(encoded), foreignKey) {
			t.Fatalf("invalid or key-bearing export audit: %s", encoded)
		}
	}
}
