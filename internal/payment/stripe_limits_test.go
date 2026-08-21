package payment

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestStripeWebhookBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &StripeHandler{MaxWebhookBodyBytes: 8}
	r := gin.New()
	r.POST("/stripe", h.Webhook)
	req := httptest.NewRequest(http.MethodPost, "/stripe", strings.NewReader("123456789"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "123456789") {
		t.Fatal("413 response leaked request body")
	}

	// The exact configured maximum reaches signature validation rather than
	// being rejected as oversized. No secret is configured in this unit test,
	// so the expected terminal response is 400 (not 413).
	req = httptest.NewRequest(http.MethodPost, "/stripe", strings.NewReader("12345678"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("exact-limit status=%d body=%s", w.Code, w.Body.String())
	}
}
