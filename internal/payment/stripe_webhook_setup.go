package payment

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhookendpoint"
)

const (
	settingWebhookEndpointID = "stripe_webhook_endpoint_id"
	settingWebhookSecret     = "stripe_webhook_secret"
)

var stripeWebhookEvents = []*string{
	stripe.String("checkout.session.completed"),
	stripe.String("invoice.paid"),
	stripe.String("invoice.payment_failed"),
	stripe.String("customer.subscription.deleted"),
	stripe.String("customer.subscription.updated"),
	stripe.String("charge.refunded"),
	stripe.String("charge.dispute.created"),
	stripe.String("charge.dispute.closed"),
	stripe.String("invoice.payment_action_required"),
	stripe.String("customer.subscription.paused"),
	stripe.String("customer.subscription.resumed"),
	stripe.String("customer.subscription.trial_will_end"),
	stripe.String("invoice.upcoming"),
	stripe.String("customer.updated"),
}

// IsLocalhostURL returns true if the URL points to a local address.
// Stripe cannot deliver webhooks to localhost.
func IsLocalhostURL(baseURL string) bool {
	return strings.Contains(baseURL, "localhost") || strings.Contains(baseURL, "127.0.0.1")
}

// SetupWebhookEndpoint ensures a Stripe webhook endpoint is configured.
// It runs synchronously on first attempt, then retries in the background if it fails.
func (h *StripeHandler) SetupWebhookEndpoint(ctx context.Context) {
	if err := h.ensureWebhookEndpoint(ctx); err != nil {
		slog.Error("stripe webhook auto-setup failed, will retry every 60s", "error", err)
		go h.retryWebhookSetup(ctx)
	}
}

func (h *StripeHandler) ensureWebhookEndpoint(ctx context.Context) error {
	webhookURL := strings.TrimRight(h.BaseURL, "/") + "/api/v1/webhook/stripe"

	// Check database for existing endpoint
	endpointID, _ := h.Store.GetSetting(ctx, settingWebhookEndpointID)
	secret, _ := h.Store.GetSetting(ctx, settingWebhookSecret)

	// staleEndpointID is an existing endpoint that must be replaced. Stripe
	// only accepts api_version at creation, so an endpoint pinned to a
	// different version (or none — which means the account default) has to
	// be recreated before stripe-go can verify its events reliably.
	staleEndpointID := ""
	if endpointID != "" && secret != "" {
		// Verify the endpoint still exists in Stripe
		ep, err := webhookendpoint.Get(endpointID, nil)
		switch {
		case err != nil || ep.Deleted || ep.Status != "enabled":
			slog.Warn("stripe webhook endpoint not found or disabled, creating new", "old_endpoint_id", endpointID)
		case ep.APIVersion != stripe.APIVersion:
			// Keep verifying the existing endpoint's deliveries until the
			// replacement is saved; if replacement fails, this stays active.
			h.SetWebhookSecret(secret)
			slog.Warn("stripe webhook endpoint API version mismatch, recreating",
				"endpoint_id", endpointID, "endpoint_api_version", ep.APIVersion,
				"sdk_api_version", stripe.APIVersion)
			staleEndpointID = endpointID
		case ep.URL == webhookURL:
			h.SetWebhookSecret(secret)
			slog.Info("stripe webhook endpoint verified", "endpoint_id", endpointID)
			return nil
		default:
			// URL changed (BASE_URL changed) — update the endpoint
			_, err := webhookendpoint.Update(endpointID, &stripe.WebhookEndpointParams{
				URL:           stripe.String(webhookURL),
				EnabledEvents: stripeWebhookEvents,
			})
			if err == nil {
				h.SetWebhookSecret(secret)
				slog.Info("stripe webhook endpoint updated", "endpoint_id", endpointID, "url", webhookURL)
				return nil
			}
			slog.Warn("stripe webhook endpoint update failed, will recreate", "error", err)
		}
	}

	// Create new webhook endpoint
	ep, err := webhookendpoint.New(&stripe.WebhookEndpointParams{
		URL:           stripe.String(webhookURL),
		EnabledEvents: stripeWebhookEvents,
		APIVersion:    stripe.String(stripe.APIVersion),
		Description:   stripe.String("Keygate auto-managed webhook"),
		Metadata:      map[string]string{"managed_by": "keygate"},
	})
	if err != nil {
		return fmt.Errorf("create stripe webhook endpoint: %w", err)
	}

	// Stripe only returns Secret at creation time — save both atomically
	if err := h.Store.SetSettings(ctx, map[string]string{
		settingWebhookEndpointID: ep.ID,
		settingWebhookSecret:     ep.Secret,
	}); err != nil {
		// Nothing references the new endpoint; remove it so retries don't
		// accumulate orphans against Stripe's per-account endpoint limit.
		if _, delErr := webhookendpoint.Del(ep.ID, nil); delErr != nil {
			slog.Warn("delete unsaved stripe webhook endpoint failed", "endpoint_id", ep.ID, "error", delErr)
		}
		return fmt.Errorf("save webhook settings: %w", err)
	}

	h.SetWebhookSecret(ep.Secret)
	slog.Info("stripe webhook endpoint created", "endpoint_id", ep.ID, "url", webhookURL)

	// Delete the replaced endpoint only after the new one is saved, so a
	// failure above never leaves us without a working endpoint.
	if staleEndpointID != "" {
		if _, err := webhookendpoint.Del(staleEndpointID, nil); err != nil {
			slog.Warn("delete stale stripe webhook endpoint failed", "endpoint_id", staleEndpointID, "error", err)
		}
	}
	return nil
}

func (h *StripeHandler) retryWebhookSetup(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.ensureWebhookEndpoint(ctx); err != nil {
				slog.Error("stripe webhook auto-setup retry failed", "error", err)
				continue
			}
			slog.Info("stripe webhook auto-setup succeeded on retry")
			return
		}
	}
}
