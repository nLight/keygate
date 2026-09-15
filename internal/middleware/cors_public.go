package middleware

import (
	"github.com/gin-gonic/gin"
)

// PublicCORS opens an anonymous, read-only endpoint to every origin so a
// product's marketing site can fetch it from the browser. It replaces the
// credentialed per-origin headers the global CORS middleware may already
// have written: a wildcard origin must never be paired with credentials.
func PublicCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET,OPTIONS")
		h.Del("Access-Control-Allow-Headers")
		h.Del("Access-Control-Allow-Credentials")
		c.Next()
	}
}
