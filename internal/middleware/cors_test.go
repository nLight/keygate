package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func corsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS("https://keygate.example", true))
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	r.GET("/api/v1/releases/:product_slug/latest", ok)
	r.GET("/api/v1/releases/:product_slug/latest/download", ok)
	r.GET("/api/v1/releases/:product_slug/feed.xml", ok)
	r.GET("/api/v1/admin/settings", ok)
	return r
}

func TestCORS(t *testing.T) {
	const site = "https://summitnotes.app"
	tests := []struct {
		name        string
		method      string
		path        string
		origin      string
		reqHeaders  string
		wantStatus  int
		wantOrigin  string
		wantCreds   string
		wantHeaders string
	}{
		{"public GET from any origin", http.MethodGet, "/api/v1/releases/app/latest", site, "", http.StatusOK, "*", "", "Content-Type"},
		{"public preflight from any origin", http.MethodOptions, "/api/v1/releases/app/latest", site, "content-type", http.StatusNoContent, "*", "", "Content-Type"},
		{"public download preflight", http.MethodOptions, "/api/v1/releases/app/latest/download", site, "", http.StatusNoContent, "*", "", "Content-Type"},
		{"public feed preflight", http.MethodOptions, "/api/v1/releases/app/feed.xml", site, "", http.StatusNoContent, "*", "", "Content-Type"},
		{"public path from allowed origin stays uncredentialed", http.MethodGet, "/api/v1/releases/app/latest", "https://keygate.example", "", http.StatusOK, "*", "", "Content-Type"},
		{"private preflight from foreign origin rejected", http.MethodOptions, "/api/v1/admin/settings", site, "authorization", http.StatusForbidden, "", "", ""},
		{"private GET from foreign origin has no CORS", http.MethodGet, "/api/v1/admin/settings", site, "", http.StatusOK, "", "", ""},
		{"private preflight from allowed origin", http.MethodOptions, "/api/v1/admin/settings", "https://keygate.example", "authorization", http.StatusNoContent, "https://keygate.example", "true", "Authorization,Content-Type"},
		{"lookalike path is not public", http.MethodOptions, "/api/v1/releases/app/latest/other", site, "", http.StatusForbidden, "", "", ""},
	}
	r := corsRouter()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Origin", tc.origin)
			if tc.method == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", http.MethodGet)
			}
			if tc.reqHeaders != "" {
				req.Header.Set("Access-Control-Request-Headers", tc.reqHeaders)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Errorf("Allow-Origin = %q, want %q", got, tc.wantOrigin)
			}
			if got := w.Header().Get("Access-Control-Allow-Credentials"); got != tc.wantCreds {
				t.Errorf("Allow-Credentials = %q, want %q", got, tc.wantCreds)
			}
			if got := w.Header().Get("Access-Control-Allow-Headers"); got != tc.wantHeaders {
				t.Errorf("Allow-Headers = %q, want %q", got, tc.wantHeaders)
			}
		})
	}
}
