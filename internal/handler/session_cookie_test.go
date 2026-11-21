package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/config"
)

// The Secure attribute has to follow the connection the browser
// actually used, not the environment name. A Secure cookie handed out
// over plain HTTP is dropped by the browser without a word: the login
// answers 200 and the very next request 401s (issue #25). The reverse
// matters too — an HTTPS install must keep the attribute whatever
// ENVIRONMENT says.
func TestSessionCookieSecureFollowsTheRequestScheme(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name       string
		env        string
		baseURL    string
		tls        bool
		forwarded  string
		wantSecure bool
	}{
		{"plain http, production", "production", "http://box.local:9000", false, "", false},
		{"plain http, development", "development", "http://localhost:9000", false, "", false},
		{"https, production", "production", "https://keygate.example.com", true, "", true},
		{"https, staging", "staging", "https://keygate.example.com", true, "", true},
		{"behind a TLS proxy", "production", "http://keygate.internal:9000", false, "https", true},
		{"proxy chain, browser used TLS", "production", "http://x:9000", false, "https, http", true},
		{"proxy chain, browser used http", "production", "http://x:9000", false, "http, https", false},
		{"https BASE_URL, silent proxy", "production", "https://keygate.example.com", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &AuthHandler{Config: &config.Config{Environment: tc.env, BaseURL: tc.baseURL}}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			scheme := "http://"
			if tc.tls {
				scheme = "https://"
			}
			c.Request = httptest.NewRequest("POST", scheme+"host/api/v1/auth/otp/verify", nil)
			if tc.forwarded != "" {
				c.Request.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			setSecureCookie(c, "session", "jwt", 3600, "/", h.requestIsHTTPS(c), true)
			got := w.Header().Get("Set-Cookie")
			if secure := strings.Contains(got, "; Secure"); secure != tc.wantSecure {
				t.Fatalf("Secure=%v, want %v: %s", secure, tc.wantSecure, got)
			}
			// The rest of the cookie is not up for negotiation.
			for _, want := range []string{"HttpOnly", "SameSite=Lax", "Path=/"} {
				if !strings.Contains(got, want) {
					t.Fatalf("cookie lost %s: %s", want, got)
				}
			}
		})
	}
}
