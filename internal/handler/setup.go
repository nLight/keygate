package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
	"github.com/tabloy/keygate/pkg/apperr"
	"github.com/tabloy/keygate/pkg/response"
)

// SetupHandler manages the first-run setup wizard.
type SetupHandler struct {
	Store      *store.Store
	enabled    bool
	secretHash [sha256.Size]byte
}

type SetupOptions struct {
	Enabled         bool
	BootstrapSecret string
}

func NewSetupHandler(s *store.Store, options ...SetupOptions) *SetupHandler {
	opt := SetupOptions{Enabled: true}
	if len(options) > 0 {
		opt = options[0]
	}
	return &SetupHandler{
		Store:      s,
		enabled:    opt.Enabled,
		secretHash: sha256.Sum256([]byte(opt.BootstrapSecret)),
	}
}

// setupNeeded returns true if no owner exists and setup_complete is not "true".
func (h *SetupHandler) setupNeeded(c *gin.Context) (bool, string, error) {
	complete, err := h.Store.GetSetting(c, "setup_complete")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}
	if complete == "true" {
		return false, "complete", nil
	}

	ownerCount, err := h.Store.CountOwners(c)
	if err != nil {
		return false, "", err
	}
	if ownerCount > 0 {
		return false, "complete", nil
	}

	return true, "initialize", nil
}

// Status returns whether setup is needed and which step the wizard is on.
// GET /api/v1/setup/status
func (h *SetupHandler) Status(c *gin.Context) {
	if !h.enabled {
		response.OK(c, gin.H{"needed": false, "step": "disabled"})
		return
	}
	needed, step, err := h.setupNeeded(c)
	if err != nil {
		response.Internal(c)
		return
	}
	response.OK(c, gin.H{
		"needed": needed,
		"step":   step,
	})
}

// Initialize completes setup in one call. This is the ONLY endpoint that allows
// creating the first owner without authentication.
// POST /api/v1/setup/initialize
func (h *SetupHandler) Initialize(c *gin.Context) {
	if !h.enabled {
		response.NotFound(c, "setup is disabled")
		return
	}

	var req struct {
		BootstrapSecret string `json:"bootstrap_secret" binding:"required"`
		AdminEmail      string `json:"admin_email" binding:"required,email"`
		AdminName       string `json:"admin_name" binding:"required"`
		SiteName        string `json:"site_name" binding:"required"`
		ProductName     string `json:"product_name" binding:"required"`
		ProductSlug     string `json:"product_slug" binding:"required"`
		ProductType     string `json:"product_type" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid setup request")
		return
	}
	presentedHash := sha256.Sum256([]byte(req.BootstrapSecret))
	if subtle.ConstantTimeCompare(presentedHash[:], h.secretHash[:]) != 1 {
		response.Unauthorized(c, "invalid setup credentials")
		return
	}
	req.BootstrapSecret = ""

	// 1. Verify setup not already complete
	needed, _, err := h.setupNeeded(c)
	if err != nil {
		response.Internal(c)
		return
	}
	if !needed {
		response.Err(c, http.StatusConflict, "SETUP_COMPLETE", "setup already complete")
		return
	}

	req.AdminEmail = strings.TrimSpace(strings.ToLower(req.AdminEmail))
	req.AdminName = strings.TrimSpace(req.AdminName)
	req.SiteName = strings.TrimSpace(req.SiteName)
	req.ProductName = strings.TrimSpace(req.ProductName)
	req.ProductSlug = strings.TrimSpace(strings.ToLower(req.ProductSlug))
	req.ProductType = strings.TrimSpace(strings.ToLower(req.ProductType))

	if req.ProductType != "saas" && req.ProductType != "desktop" && req.ProductType != "hybrid" {
		response.BadRequest(c, "product_type must be one of: saas, desktop, hybrid")
		return
	}
	if err := apperr.ValidateName("product_name", req.ProductName); err != nil {
		response.BadRequest(c, err.Message)
		return
	}
	if err := apperr.ValidateSlug(req.ProductSlug); err != nil {
		response.BadRequest(c, err.Message)
		return
	}

	// All mutations in a single transaction — if any step fails, everything rolls back
	ctx := c.Request.Context()
	tx, err := h.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		response.Internal(c)
		return
	}
	defer tx.Rollback()

	// Transaction-scoped advisory lock and the state re-check run on the SAME
	// database connection as owner creation. This both serializes concurrent
	// initializers and guarantees automatic unlock on commit/rollback.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(8675309)"); err != nil {
		response.Internal(c)
		return
	}
	var setupComplete string
	err = tx.NewRaw("SELECT value FROM settings WHERE key = 'setup_complete'").Scan(ctx, &setupComplete)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		response.Internal(c)
		return
	}
	var ownerCount int
	if err := tx.NewRaw("SELECT count(*) FROM users WHERE role = 'owner'").Scan(ctx, &ownerCount); err != nil {
		response.Internal(c)
		return
	}
	if setupComplete == "true" || ownerCount > 0 {
		response.Err(c, http.StatusConflict, "SETUP_COMPLETE", "setup already complete")
		return
	}

	// Create owner user
	userID := store.NewID()
	if _, err := tx.NewRaw(
		"INSERT INTO users (id, email, name, role, created_at, updated_at) VALUES (?, ?, ?, 'owner', now(), now()) ON CONFLICT (email) DO UPDATE SET role = 'owner', name = EXCLUDED.name, updated_at = now()",
		userID, req.AdminEmail, req.AdminName,
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}
	// Get actual user ID (may differ if email existed)
	var actualUserID string
	if err := tx.NewRaw("SELECT id FROM users WHERE email = ?", req.AdminEmail).Scan(ctx, &actualUserID); err != nil {
		response.Internal(c)
		return
	}

	// Set site_name
	if _, err := tx.NewRaw(
		"INSERT INTO settings (key, value) VALUES ('site_name', ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
		req.SiteName,
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}

	// Create product
	productID := store.NewID()
	if _, err := tx.NewRaw(
		"INSERT INTO products (id, name, slug, type, created_at) VALUES (?, ?, ?, ?, now())",
		productID, req.ProductName, req.ProductSlug, req.ProductType,
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}

	// Create default plan — pick activation/seat defaults that match
	// the product type's capability surface. The product_type drives
	// what fields are even valid: a SaaS product whose plan carries
	// max_activations=5 would silently violate the capability gate
	// at runtime (every /license/activate call would 404).
	planID := store.NewID()
	var maxActivations, maxSeats int
	switch req.ProductType {
	case "saas":
		maxActivations, maxSeats = 0, 10
	case "desktop":
		maxActivations, maxSeats = 3, 0
	case "hybrid":
		maxActivations, maxSeats = 3, 10
	}
	if _, err := tx.NewRaw(
		"INSERT INTO plans (id, product_id, name, slug, license_type, max_activations, max_seats, grace_days, active, checkout_id, created_at) VALUES (?, ?, 'Pro', 'pro', 'subscription', ?, ?, 7, true, ?, now())",
		planID, productID, maxActivations, maxSeats, store.ShortID(),
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}

	// We deliberately don't auto-create an API key during setup.
	// Under RequireScope, a fresh key with scopes={} can't reach any
	// admin route — shipping one in the response would mislead users
	// into thinking they have a usable credential. They mint one
	// later from /admin/api-keys with the scope that matches the
	// intended use (admin / licenses:write / releases:write).

	// Mark setup complete
	if _, err := tx.NewRaw(
		"INSERT INTO settings (key, value) VALUES ('setup_complete', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'",
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}
	if _, err := tx.NewRaw(
		"INSERT INTO settings (key, value) VALUES ('setup_bootstrap_consumed_at', ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
		time.Now().UTC().Format(time.RFC3339),
	).Exec(ctx); err != nil {
		response.Internal(c)
		return
	}

	if err := tx.Commit(); err != nil {
		response.Internal(c)
		return
	}

	// Build response objects
	user := &model.User{ID: actualUserID, Email: req.AdminEmail, Name: req.AdminName, Role: model.RoleOwner}
	product := &model.Product{ID: productID, Name: req.ProductName, Slug: req.ProductSlug, Type: req.ProductType}
	plan := &model.Plan{ID: planID, ProductID: productID, Name: "Pro", Slug: "pro", LicenseType: "subscription"}

	response.Created(c, gin.H{
		"user":    user,
		"product": product,
		"plan":    plan,
	})
}
