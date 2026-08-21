package middleware

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// BodySizeLimit bounds every request body before a handler or JSON binder can
// read it. Reading once here also makes chunked requests return the same stable
// 413 envelope as requests with an oversized Content-Length.
func BodySizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		if c.Request.ContentLength > maxBytes {
			abortWithError(c, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds the configured limit")
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				abortWithError(c, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds the configured limit")
				return
			}
			abortWithError(c, http.StatusBadRequest, "BAD_REQUEST", "unable to read request body")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Request.ContentLength = int64(len(body))
		c.Next()
	}
}

// BearerTokenAuth protects operational endpoints such as /metrics and
// /ready. Empty tokens deny access so a configuration mistake never exposes
// operational data.
//
// Both sides are hashed before comparison. Comparing the raw strings needs a
// length guard first, and that guard short-circuits — it turns the handler
// into an oracle for the configured token's length. SHA-256 digests are
// always 32 bytes, so one ConstantTimeCompare covers every input.
func BearerTokenAuth(expected string) gin.HandlerFunc {
	expectedDigest := sha256.Sum256([]byte(expected))
	configured := expected != ""
	return func(c *gin.Context) {
		raw := strings.TrimSpace(c.GetHeader("Authorization"))
		provided := ""
		if len(raw) >= len("Bearer ") && strings.EqualFold(raw[:len("Bearer ")], "bearer ") {
			provided = strings.TrimSpace(raw[len("Bearer "):])
		}
		providedDigest := sha256.Sum256([]byte(provided))
		if !configured || subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) != 1 {
			c.Header("WWW-Authenticate", "Bearer")
			abortWithError(c, http.StatusUnauthorized, "UNAUTHORIZED", "operational endpoint authentication required")
			return
		}
		c.Next()
	}
}
