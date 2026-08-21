package handler

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRecordUsageRejectsOverflowingQuantity pins the input bound on the usage
// endpoints. The atomic quota check in the store is
// `currentUsed + quantity > limit` over int64: a quantity near math.MaxInt64
// wraps that sum negative, so the comparison that is supposed to enforce the
// quota returns false. The handler must reject the value before the service
// or the database ever sees it.
//
// The nil service is deliberate — a request that reaches RecordUsage would
// panic, so a clean 400 also proves the check runs before any dependency.
func TestRecordUsageRejectsOverflowingQuantity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewUsageHandler(nil)
	r.POST("/usage", h.RecordUsage)
	r.POST("/admin/usage", h.RecordBillableUsage)

	for _, quantity := range []string{
		strconv.FormatInt(math.MaxInt64, 10),
		strconv.FormatInt(math.MaxInt64-1, 10),
		strconv.FormatInt(MaxUsageQuantity+1, 10),
		"9000000000000000000",
	} {
		for _, path := range []string{"/usage", "/admin/usage"} {
			body := `{"license_key":"KGT-TEST","feature":"api_calls","quantity":` + quantity + `}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("%s quantity=%s: status=%d body=%s, want 400",
					path, quantity, w.Code, w.Body.String())
			}
		}
	}
}

// The bound must not be so tight that it breaks a legitimate batched report.
// These values pass the handler check and go on to the service, which is nil
// here — so a panic is the expected proof that the request got through.
func TestRecordUsageAcceptsRealisticQuantities(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, quantity := range []string{"0", "1", "1000", "1000000", strconv.FormatInt(MaxUsageQuantity, 10)} {
		t.Run(quantity, func(t *testing.T) {
			r := gin.New()
			r.POST("/usage", NewUsageHandler(nil).RecordUsage)

			body := `{"license_key":"KGT-TEST","feature":"api_calls","quantity":` + quantity + `}`
			req := httptest.NewRequest(http.MethodPost, "/usage", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			defer func() {
				if recover() == nil && w.Code == http.StatusBadRequest {
					t.Fatalf("quantity=%s was rejected but is within MaxUsageQuantity", quantity)
				}
			}()
			r.ServeHTTP(w, req)
		})
	}
}
