package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tabloy/keygate/internal/middleware"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

type WebhookService struct {
	store        *store.Store
	logger       *slog.Logger
	client       *http.Client
	maxRetries   int
	sem          chan struct{} // concurrency limiter
	requireHTTPS bool
}

func NewWebhookService(s *store.Store, logger *slog.Logger, httpTimeout time.Duration, maxRetries int) *WebhookService {
	return NewWebhookServiceWithConfig(s, logger, WebhookHTTPConfig{
		Timeout: httpTimeout, MaxRetries: maxRetries,
	})
}

type WebhookHTTPConfig struct {
	Timeout      time.Duration
	MaxRetries   int
	RequireHTTPS bool
}

func NewWebhookServiceWithConfig(s *store.Store, logger *slog.Logger, cfg WebhookHTTPConfig) *WebhookService {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeWebhookDialer,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
	}
	svc := &WebhookService{
		store:        s,
		logger:       logger,
		maxRetries:   cfg.MaxRetries,
		sem:          make(chan struct{}, 20),
		requireHTTPS: cfg.RequireHTTPS,
	}
	svc.client = &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("webhook redirect limit exceeded")
			}
			return svc.ValidateDestinationURL(req.Context(), req.URL.String())
		},
	}
	return svc
}

// forbiddenWebhookNets covers the internal ranges net.IP's own predicates miss.
// Parsed once: isForbiddenWebhookIP runs on every resolved address of every
// delivery and every redirect hop.
//
//   - 0.0.0.0/8      "this network"; 0.x.y.z reaches 127.0.0.1 on Linux.
//   - 100.64.0.0/10  carrier-grade NAT, not covered by IsPrivate.
//   - 192.0.0.0/24   IETF protocol assignments (includes NAT64 well-known).
//   - 198.18.0.0/15  benchmarking range, routed internally in many networks.
//   - 2002::/16      6to4; the embedded IPv4 can be any internal address.
//   - 64:ff9b::/96   NAT64 well-known prefix; same embedding problem.
//   - 64:ff9b:1::/48 local-use NAT64 prefix.
var forbiddenWebhookNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
		"2002::/16", "64:ff9b::/96", "64:ff9b:1::/48",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("webhook blocklist: " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

func isForbiddenWebhookIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// Normalise 4-in-6 (::ffff:10.0.0.1) so the IPv4 ranges below match it.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range forbiddenWebhookNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func safeWebhookDialer(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve webhook host: %w", err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, addr := range addrs {
		if isForbiddenWebhookIP(addr.IP) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("webhook destination resolves only to blocked or unreachable addresses")
}

// ValidateDestinationURL is applied when a webhook is saved, before every
// request, after each redirect, and again at dial time.
func (s *WebhookService) ValidateDestinationURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("invalid webhook URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTP or HTTPS")
	}
	if s.requireHTTPS && u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTPS")
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return fmt.Errorf("webhook destination is not public")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("webhook host cannot be resolved")
	}
	for _, addr := range addrs {
		if isForbiddenWebhookIP(addr.IP) {
			return fmt.Errorf("webhook destination is not public")
		}
	}
	return nil
}

func (s *WebhookService) Dispatch(ctx context.Context, productID, event string, data map[string]any) {
	if err := s.DispatchWithLog(ctx, productID, event, data); err != nil {
		s.logger.Error("webhook dispatch failed", "event", event, "product_id", productID, "error", err)
	}
}

// DispatchWithLog dispatches webhook events and returns any error that occurs during setup.
// Use this when the caller needs to handle or log dispatch failures explicitly.
func (s *WebhookService) DispatchWithLog(ctx context.Context, productID, event string, data map[string]any) error {
	webhooks, err := s.store.FindWebhooksForEvent(ctx, productID, event)
	if err != nil {
		return fmt.Errorf("find webhooks: %w", err)
	}
	if len(webhooks) == 0 {
		return nil
	}

	payload := map[string]any{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	}

	for _, wh := range webhooks {
		delivery := &model.WebhookDelivery{
			WebhookID: wh.ID,
			Event:     event,
			Payload:   payload,
			Status:    "pending",
		}
		if err := s.store.CreateWebhookDelivery(ctx, delivery); err != nil {
			s.logger.Error("webhook delivery create failed", "webhook_id", wh.ID, "error", err)
			continue
		}
		go func() {
			s.sem <- struct{}{}        // acquire
			defer func() { <-s.sem }() // release
			s.deliver(wh, delivery)
		}()
	}
	return nil
}

func (s *WebhookService) deliver(wh *model.Webhook, delivery *model.WebhookDelivery) {
	ctx := context.Background()
	if err := s.ValidateDestinationURL(ctx, wh.URL); err != nil {
		s.failDelivery(ctx, delivery, 0, err.Error())
		return
	}
	body, _ := json.Marshal(delivery.Payload)
	sig := signPayload(body, wh.Secret)

	req, err := http.NewRequestWithContext(ctx, "POST", wh.URL, bytes.NewReader(body))
	if err != nil {
		s.failDelivery(ctx, delivery, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keygate-Event", delivery.Event)
	req.Header.Set("X-Keygate-Signature", "sha256="+sig)
	req.Header.Set("X-Keygate-Delivery", delivery.ID)

	resp, err := s.client.Do(req)
	if err != nil {
		s.failDelivery(ctx, delivery, 0, err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	delivery.ResponseCode = resp.StatusCode
	delivery.ResponseBody = string(respBody)
	delivery.Attempts++

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now()
		delivery.Status = "delivered"
		delivery.DeliveredAt = &now
		middleware.WebhookDeliveries.WithLabelValues("delivered").Inc()
	} else {
		s.scheduleRetry(delivery)
	}
	_ = s.store.UpdateWebhookDelivery(ctx, delivery)
}

func (s *WebhookService) scheduleRetry(d *model.WebhookDelivery) {
	if d.Attempts >= s.maxRetries {
		d.Status = "failed"
		middleware.WebhookDeliveries.WithLabelValues("failed").Inc()
		return
	}
	backoff := time.Duration(1<<uint(d.Attempts)) * 30 * time.Second
	next := time.Now().Add(backoff)
	d.NextRetry = &next
	d.Status = "pending"
	middleware.WebhookDeliveries.WithLabelValues("retrying").Inc()
}

func (s *WebhookService) failDelivery(ctx context.Context, d *model.WebhookDelivery, code int, body string) {
	d.Attempts++
	d.ResponseCode = code
	d.ResponseBody = body
	s.scheduleRetry(d)
	_ = s.store.UpdateWebhookDelivery(ctx, d)
}

// ErrWebhookDeliveryNotResendable is returned by Redispatch when the
// target delivery exists but the parent webhook has been deleted or
// disabled. Surfaces as 409 so the admin UI can disable the button
// instead of silently failing.
var ErrWebhookDeliveryNotResendable = fmt.Errorf("webhook delivery is not resendable")

// Redispatch fires a fresh delivery using the payload of an existing
// one. Industry-standard "resend" behaviour: the receiver sees the
// SAME `data` (so its idempotency dedup still works) but a new
// `X-Keygate-Delivery` header and a new row in the deliveries table
// — so retries, response codes, and timestamps are tracked
// independently of the original attempt.
//
// Returns the new delivery on success. Caller should audit-log the
// admin action with both delivery IDs.
func (s *WebhookService) Redispatch(ctx context.Context, deliveryID string) (*model.WebhookDelivery, error) {
	orig, err := s.store.FindWebhookDeliveryByID(ctx, deliveryID)
	if err != nil {
		return nil, err
	}
	wh, err := s.store.FindWebhookByID(ctx, orig.WebhookID)
	if err != nil {
		return nil, ErrWebhookDeliveryNotResendable
	}
	if !wh.Active {
		return nil, ErrWebhookDeliveryNotResendable
	}
	fresh := &model.WebhookDelivery{
		WebhookID: wh.ID,
		Event:     orig.Event,
		Payload:   orig.Payload, // byte-identical replay
		Status:    "pending",
	}
	if err := s.store.CreateWebhookDelivery(ctx, fresh); err != nil {
		return nil, err
	}
	go func() {
		s.sem <- struct{}{}
		defer func() { <-s.sem }()
		s.deliver(wh, fresh)
	}()
	return fresh, nil
}

func (s *WebhookService) ProcessRetries(ctx context.Context) {
	deliveries, err := s.store.ListPendingDeliveries(ctx, 50)
	if err != nil || len(deliveries) == 0 {
		return
	}
	for _, d := range deliveries {
		wh, err := s.store.FindWebhookByID(ctx, d.WebhookID)
		if err != nil {
			continue
		}
		go func(wh *model.Webhook, d *model.WebhookDelivery) {
			s.sem <- struct{}{}
			defer func() { <-s.sem }()
			s.deliver(wh, d)
		}(wh, d)
	}
}

func (s *WebhookService) StartRetryLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ProcessRetries(ctx)
		}
	}
}

func GenerateWebhookSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func signPayload(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
