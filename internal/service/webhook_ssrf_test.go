package service

import (
	"context"
	"net"
	"testing"
)

// TestForbiddenWebhookIPs_ExtendedRanges covers the internal destinations
// net.IP's own predicates do not classify. Each of these is reachable from a
// deployment's own network while looking "public" to IsPrivate/IsLoopback, so
// a tenant who controls a webhook URL (or a DNS record it points at) could
// otherwise aim deliveries at infrastructure behind the app.
func TestForbiddenWebhookIPs_ExtendedRanges(t *testing.T) {
	blocked := map[string]string{
		"0.1.2.3":                "0.0.0.0/8 reaches loopback on Linux",
		"0.0.0.0":                "unspecified",
		"100.64.0.1":             "carrier-grade NAT",
		"100.127.255.254":        "carrier-grade NAT upper bound",
		"192.0.0.1":              "IETF protocol assignments",
		"198.18.0.1":             "benchmarking range, routed internally",
		"198.19.255.255":         "benchmarking range upper bound",
		"169.254.169.254":        "cloud instance metadata",
		"::ffff:10.0.0.1":        "IPv4-mapped private address",
		"::ffff:127.0.0.1":       "IPv4-mapped loopback",
		"::ffff:169.254.169.254": "IPv4-mapped metadata address",
		"2002:0a00:0001::":       "6to4 wrapping 10.0.0.1",
		"64:ff9b::a00:1":         "NAT64 well-known prefix wrapping 10.0.0.1",
		"64:ff9b:1::1":           "NAT64 local-use prefix",
		"ff01::1":                "interface-local multicast",
	}
	for raw, why := range blocked {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("test fixture %q is not a valid IP", raw)
		}
		if !isForbiddenWebhookIP(ip) {
			t.Errorf("%s should be blocked (%s)", raw, why)
		}
	}
}

// The blocklist must not swallow the public internet — an over-broad filter
// silently breaks every customer's webhook endpoint.
func TestForbiddenWebhookIPs_AllowsPublicNeighbours(t *testing.T) {
	for _, raw := range []string{
		"8.8.8.8", "1.1.1.1", "9.255.255.255", "100.63.255.255", "100.128.0.0",
		"192.0.1.1", "198.17.255.255", "198.20.0.0", "203.0.113.9",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	} {
		if isForbiddenWebhookIP(net.ParseIP(raw)) {
			t.Errorf("%s is public and must remain deliverable", raw)
		}
	}
}

func TestForbiddenWebhookIPs_NilIsBlocked(t *testing.T) {
	if !isForbiddenWebhookIP(nil) {
		t.Fatal("an unparsable address must fail closed")
	}
}

// ValidateDestinationURL is called on save, before each delivery, and again
// after every redirect hop. Anything it lets through has to be re-checked at
// dial time, so a gap here plus a DNS flip is a live SSRF.
func TestValidateDestinationURL_RejectsNonPublicForms(t *testing.T) {
	svc := NewWebhookServiceWithConfig(nil, nil, WebhookHTTPConfig{})
	for _, raw := range []string{
		"https://localhost/hook",
		"https://LOCALHOST/hook",
		"http://127.0.0.1:8080/hook",
		"http://[::1]/hook",
		"http://0.0.0.0/hook",
		"http://100.64.0.1/hook",
		"http://198.18.0.1/hook",
		"http://[::ffff:10.0.0.1]/hook",
		"gopher://example.com/hook",
		"ftp://example.com/hook",
		"//example.com/hook",
		"",
		"http://user:pass@example.com/hook",
	} {
		if err := svc.ValidateDestinationURL(context.Background(), raw); err == nil {
			t.Errorf("%q should be rejected", raw)
		}
	}
}

// requireHTTPS is production-only; a staging deployment still has to be able
// to point a webhook at a plain-HTTP collector.
func TestValidateDestinationURL_HTTPSOnlyIsProductionScoped(t *testing.T) {
	const raw = "http://example.com/hook"

	prod := NewWebhookServiceWithConfig(nil, nil, WebhookHTTPConfig{RequireHTTPS: true})
	if err := prod.ValidateDestinationURL(context.Background(), raw); err == nil {
		t.Fatal("production must refuse plain HTTP webhook destinations")
	}

	dev := NewWebhookServiceWithConfig(nil, nil, WebhookHTTPConfig{})
	err := dev.ValidateDestinationURL(context.Background(), raw)
	if err != nil && err.Error() == "webhook URL must use HTTPS" {
		t.Fatal("non-production must not enforce HTTPS")
	}
}
