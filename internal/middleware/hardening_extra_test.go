package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// A fixture, not a credential. The property under test is that the compare is
// length- and content-independent, so a readable low-entropy string works as
// well as a random one — and does not trip the repo's secret scanner.
const opsToken = "test-metrics-token-fixture-00001"

func opsRouter(token string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", BearerTokenAuth(token), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return r
}

func opsStatus(t *testing.T, r *gin.Engine, authorization string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// The comparison must not branch on length. A length-guarded compare answers
// "is METRICS_TOKEN 32 or 64 characters?" for free, which meaningfully shrinks
// an offline search.
func TestBearerTokenAuthRejectsEveryWrongLength(t *testing.T) {
	r := opsRouter(opsToken)
	for _, provided := range []string{
		"",
		"x",
		opsToken[:len(opsToken)-1],
		opsToken + "x",
		strings.Repeat("z", len(opsToken)),
		strings.Repeat("z", 512),
	} {
		if got := opsStatus(t, r, "Bearer "+provided); got != http.StatusUnauthorized {
			t.Errorf("token %q: status=%d, want 401", provided, got)
		}
	}
}

// An unset METRICS_TOKEN must lock the endpoint, not open it. Config
// validation makes this fatal in production, but staging and development
// deployments reach this code path with an empty token.
func TestBearerTokenAuthDeniesWhenUnconfigured(t *testing.T) {
	r := opsRouter("")
	for _, header := range []string{"", "Bearer ", "Bearer anything"} {
		if got := opsStatus(t, r, header); got != http.StatusUnauthorized {
			t.Errorf("header %q against an empty token: status=%d, want 401", header, got)
		}
	}
}

func TestBearerTokenAuthAcceptsSchemeCaseInsensitively(t *testing.T) {
	r := opsRouter(opsToken)
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		if got := opsStatus(t, r, scheme+" "+opsToken); got != http.StatusNoContent {
			t.Errorf("scheme %q: status=%d, want 204", scheme, got)
		}
	}
}

func TestBearerTokenAuthRejectsOtherSchemes(t *testing.T) {
	r := opsRouter(opsToken)
	for _, header := range []string{
		opsToken,
		"Basic " + opsToken,
		"Token " + opsToken,
		"Bearer" + opsToken,
	} {
		if got := opsStatus(t, r, header); got != http.StatusUnauthorized {
			t.Errorf("header %q: status=%d, want 401", header, got)
		}
	}
}

func TestBearerTokenAuthAdvertisesChallenge(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	opsRouter(opsToken).ServeHTTP(w, req)
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
}

// BodySizeLimit reads the body to normalise chunked requests. The handler
// still has to be able to bind it, otherwise the limiter silently breaks
// every POST endpoint.
func TestBodySizeLimitLeavesBodyReadable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodySizeLimit(1024))
	r.POST("/echo", func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusInternalServerError, "read: %v", err)
			return
		}
		c.String(http.StatusOK, string(body))
	})

	const payload = `{"license_key":"KGT-TEST","feature":"api_calls"}`
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(payload))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Body.String() != payload {
		t.Fatalf("handler saw %q, want %q", w.Body.String(), payload)
	}
}

// A lying Content-Length must not buy extra bytes: the header is rejected up
// front and MaxBytesReader still caps the actual stream.
func TestBodySizeLimitIgnoresLyingContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodySizeLimit(8))
	r.POST("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	t.Run("oversized declared length", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345678"))
		req.ContentLength = 1 << 20
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d, want 413", w.Code)
		}
	})

	t.Run("understated declared length", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = io.NopCloser(strings.NewReader(strings.Repeat("A", 64)))
		req.ContentLength = 2
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d, want 413", w.Code)
		}
	})
}

func TestBodySizeLimitAllowsEmptyBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodySizeLimit(8))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", w.Code)
	}
}
