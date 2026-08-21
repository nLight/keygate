package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// setupRouter builds the two setup routes against a handler with no store.
// Every case below is rejected before the handler reaches the database, which
// is exactly the property under test: an unauthenticated caller must not be
// able to make the setup endpoint do database work.
func setupRouter(t *testing.T, opts SetupOptions) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewSetupHandler(nil, opts)
	r.GET("/setup/status", h.Status)
	r.POST("/setup/initialize", h.Initialize)
	return r
}

func postSetup(t *testing.T, r *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/setup/initialize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

const validSetupBody = `{
  "bootstrap_secret": %s,
  "admin_email": "owner@example.com",
  "admin_name": "Owner",
  "site_name": "Keygate",
  "product_name": "App",
  "product_slug": "app",
  "product_type": "desktop"
}`

// SETUP_ENABLED=false has to close the endpoint outright. This is the control
// an operator relies on after the first owner exists — the wizard creates an
// owner account with no authentication at all.
func TestSetupDisabledClosesBothEndpoints(t *testing.T) {
	r := setupRouter(t, SetupOptions{Enabled: false, BootstrapSecret: strings.Repeat("s", 32)})

	w := postSetup(t, r, strings.Replace(validSetupBody, "%s", `"`+strings.Repeat("s", 32)+`"`, 1))
	if w.Code != http.StatusNotFound {
		t.Fatalf("initialize with setup disabled: status=%d body=%s, want 404", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/setup/status", nil)
	sw := httptest.NewRecorder()
	r.ServeHTTP(sw, req)
	if sw.Code != http.StatusOK {
		t.Fatalf("status: %d", sw.Code)
	}
	var payload struct {
		Data struct {
			Needed bool   `json:"needed"`
			Step   string `json:"step"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sw.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode %s: %v", sw.Body.String(), err)
	}
	if payload.Data.Needed || payload.Data.Step != "disabled" {
		t.Fatalf("status should report disabled, got %+v", payload.Data)
	}
}

// A wrong, absent, or empty bootstrap secret must be rejected before any
// database work — and must never be accepted just because the configured
// secret happens to be empty.
func TestSetupInitializeRejectsBadBootstrapSecret(t *testing.T) {
	secret := strings.Repeat("s", 32)
	r := setupRouter(t, SetupOptions{Enabled: true, BootstrapSecret: secret})

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"wrong secret", strings.Replace(validSetupBody, "%s", `"`+strings.Repeat("x", 32)+`"`, 1), http.StatusUnauthorized},
		{"truncated secret", strings.Replace(validSetupBody, "%s", `"`+secret[:31]+`"`, 1), http.StatusUnauthorized},
		{"extended secret", strings.Replace(validSetupBody, "%s", `"`+secret+`x"`, 1), http.StatusUnauthorized},
		{"empty secret", strings.Replace(validSetupBody, "%s", `""`, 1), http.StatusBadRequest},
		{"missing field", `{"admin_email":"o@example.com","admin_name":"O","site_name":"K","product_name":"A","product_slug":"a","product_type":"desktop"}`, http.StatusBadRequest},
		{"not json", `not json`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := postSetup(t, r, tc.body).Code; got != tc.want {
				t.Fatalf("status=%d, want %d", got, tc.want)
			}
		})
	}
}

// An operator who enables setup without setting BOOTSTRAP_SECRET is caught by
// config validation, but the handler must not be the thing that lets an empty
// secret through if that check is ever bypassed.
func TestSetupInitializeWithEmptyConfiguredSecretRejectsEmptyInput(t *testing.T) {
	r := setupRouter(t, SetupOptions{Enabled: true, BootstrapSecret: ""})
	if got := postSetup(t, r, strings.Replace(validSetupBody, "%s", `""`, 1)).Code; got != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 — binding must reject an empty bootstrap_secret", got)
	}
}

// NewSetupHandler is variadic for backward compatibility. The zero-option form
// must not silently produce an open, secret-less wizard.
func TestNewSetupHandlerDefaultRejectsUnknownSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/setup/initialize", NewSetupHandler(nil).Initialize)
	if got := postSetup(t, r, strings.Replace(validSetupBody, "%s", `"anything"`, 1)).Code; got != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", got)
	}
}
