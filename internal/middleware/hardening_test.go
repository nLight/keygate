package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBodySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodySizeLimit(8))
	r.POST("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"within limit", "12345678", http.StatusNoContent},
		{"over limit", "123456789", http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}

	t.Run("chunked over limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = io.NopCloser(strings.NewReader("123456789"))
		req.ContentLength = -1
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})
}

func TestBearerTokenAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", BearerTokenAuth("01234567890123456789012345678901"), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	bad := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, bad)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d", w.Code)
	}

	good := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	good.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, good)
	if w.Code != http.StatusNoContent {
		t.Fatalf("valid token status=%d", w.Code)
	}
}
