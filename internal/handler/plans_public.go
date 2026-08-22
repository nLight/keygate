package handler

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	stripeprice "github.com/stripe/stripe-go/v82/price"

	"github.com/tabloy/keygate/internal/store"
	"github.com/tabloy/keygate/pkg/response"
)

// PublicPlansHandler exposes:
//
//	GET /api/v1/products/:product_slug/plans   public plan catalog (pricing page)
//
// No auth: called by anonymous visitors before they have a license or
// account. Price/currency are not stored locally — Stripe Price is the
// source of truth (see payment.StripeHandler.CheckoutByPlan) — so this
// handler fetches them from Stripe and caches the result briefly.
// Without a cache, every anonymous pricing-page load would fan out one
// Stripe API call per plan, which is both slow and a way for anonymous
// traffic to burn Stripe rate-budget (the same concern that keeps
// /checkout/verify behind its own rate limit).
type PublicPlansHandler struct {
	store *store.Store
	log   *slog.Logger

	priceCacheMu  sync.RWMutex
	priceCache    map[string]cachedPrice
	priceCacheTTL time.Duration
}

type cachedPrice struct {
	amount    int64
	currency  string
	fetchedAt time.Time
}

func NewPublicPlansHandler(s *store.Store, log *slog.Logger) *PublicPlansHandler {
	if log == nil {
		log = slog.Default()
	}
	return &PublicPlansHandler{
		store:         s,
		log:           log,
		priceCache:    make(map[string]cachedPrice),
		priceCacheTTL: 5 * time.Minute,
	}
}

// ListPlans handles GET /api/v1/products/:product_slug/plans.
func (h *PublicPlansHandler) ListPlans(c *gin.Context) {
	slug := strings.ToLower(strings.TrimSpace(c.Param("product_slug")))
	if slug == "" {
		response.BadRequest(c, "product_slug is required")
		return
	}

	prod, err := h.store.FindProductBySlug(c.Request.Context(), slug)
	if err != nil {
		// Don't differentiate "no such product" from "other DB error" —
		// guesses at slugs leak nothing.
		response.NotFound(c, "product not found")
		return
	}

	plans, err := h.store.ListPlans(c.Request.Context(), prod.ID, "")
	if err != nil {
		response.Internal(c)
		return
	}

	active := []gin.H{}
	for _, p := range plans {
		if !p.Active {
			continue
		}
		out := gin.H{
			"id": p.ID, "name": p.Name, "slug": p.Slug,
			"license_type": p.LicenseType, "billing_interval": p.BillingInterval,
			"stripe_price_id": p.StripePriceID, "checkout_id": p.CheckoutID,
			"price":    nil,
			"currency": nil,
		}
		if p.StripePriceID != "" {
			if price, ok := h.fetchPrice(p.StripePriceID); ok {
				out["price"] = price.amount
				out["currency"] = price.currency
			}
			// On fetch failure, leave price/currency null rather than
			// failing the whole listing — the plan is still selectable
			// and checkout (which fetches the price directly) is the
			// final source of truth.
		}
		active = append(active, out)
	}
	response.OK(c, gin.H{"plans": active})
}

// fetchPrice returns the cached Stripe price for priceID, refetching
// from Stripe once the cache entry is older than priceCacheTTL.
func (h *PublicPlansHandler) fetchPrice(priceID string) (cachedPrice, bool) {
	h.priceCacheMu.RLock()
	cached, ok := h.priceCache[priceID]
	h.priceCacheMu.RUnlock()
	if ok && time.Since(cached.fetchedAt) < h.priceCacheTTL {
		return cached, true
	}

	sp, err := stripeprice.Get(priceID, nil)
	if err != nil {
		h.log.Warn("public plans: failed to fetch stripe price", "price_id", priceID, "error", err)
		if ok {
			// Serve the stale cached value rather than nothing.
			return cached, true
		}
		return cachedPrice{}, false
	}

	fresh := cachedPrice{
		amount:    sp.UnitAmount,
		currency:  string(sp.Currency),
		fetchedAt: time.Now(),
	}
	h.priceCacheMu.Lock()
	h.priceCache[priceID] = fresh
	h.priceCacheMu.Unlock()
	return fresh, true
}
