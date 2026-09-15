package middleware

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

// publicFeedPath matches the anonymous, read-only release endpoints a
// product's marketing site may fetch from the browser.
var publicFeedPath = regexp.MustCompile(`^/api/v1/releases/[^/]+/(feed\.xml|feed\.json|upgrade\.json|latest|latest/download)$`)

// CORS reflects allowedOrigin with credentials for the admin/portal UI; in
// development any origin is reflected. Public feed paths are handled first
// and opened to every origin — including their preflights, which would
// otherwise be rejected here before any route middleware could run.
func CORS(allowedOrigin string, production bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}
		if publicFeedPath.MatchString(c.Request.URL.Path) {
			writePublicCORS(c)
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}
		if production && origin != allowedOrigin {
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// writePublicCORS opens a response to every origin. A wildcard origin is
// never paired with credentials, so no cookies or auth ride along.
func writePublicCORS(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET,OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "86400")
	h.Del("Access-Control-Allow-Credentials")
}
