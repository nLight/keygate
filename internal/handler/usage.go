package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/service"
	"github.com/tabloy/keygate/pkg/response"
)

type UsageHandler struct {
	svc *service.UsageService
}

func NewUsageHandler(svc *service.UsageService) *UsageHandler {
	return &UsageHandler{svc: svc}
}

func (h *UsageHandler) RecordUsage(c *gin.Context) {
	h.recordUsage(c, false)
}

// RecordBillableUsage is mounted only behind admin/session-or-API-key scope
// enforcement. Client-held license keys may update informational quota usage,
// but only this trusted path can enqueue financial meter events.
func (h *UsageHandler) RecordBillableUsage(c *gin.Context) {
	h.recordUsage(c, true)
}

func (h *UsageHandler) recordUsage(c *gin.Context, trustedBilling bool) {
	var req struct {
		LicenseKey string         `json:"license_key" binding:"required"`
		Feature    string         `json:"feature" binding:"required"`
		Quantity   int64          `json:"quantity"`
		Metadata   map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "license_key and feature are required")
		return
	}

	productID, _ := c.Get("product_id")
	if trustedBilling {
		if v, ok := c.Get("api_key"); ok {
			if ak, ok := v.(*model.APIKey); ok && ak != nil && ak.ProductID != "" {
				productID = ak.ProductID
			}
		}
	}
	result, err := h.svc.RecordUsage(c.Request.Context(), service.RecordUsageInput{
		LicenseKey:     req.LicenseKey,
		Feature:        req.Feature,
		Quantity:       req.Quantity,
		Metadata:       req.Metadata,
		ProductID:      str(productID),
		IPAddress:      c.ClientIP(),
		TrustedBilling: trustedBilling,
	})
	if err != nil {
		writeAppErr(c, err)
		return
	}
	response.OK(c, result)
}

func (h *UsageHandler) GetQuotaStatus(c *gin.Context) {
	var req struct {
		LicenseKey string `json:"license_key" binding:"required"`
		Feature    string `json:"feature" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "license_key and feature are required")
		return
	}

	productID, _ := c.Get("product_id")
	result, err := h.svc.GetQuotaStatus(c.Request.Context(), req.LicenseKey, req.Feature, str(productID))
	if err != nil {
		writeAppErr(c, err)
		return
	}
	response.OK(c, result)
}
