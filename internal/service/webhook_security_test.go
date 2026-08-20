package service

import (
	"context"
	"net"
	"testing"
)

func TestForbiddenWebhookIPs(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
		"::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if !isForbiddenWebhookIP(net.ParseIP(raw)) {
			t.Errorf("%s should be blocked", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if isForbiddenWebhookIP(net.ParseIP(raw)) {
			t.Errorf("%s should be public", raw)
		}
	}
}

func TestValidateWebhookDestinationRejectsPrivateAndPlainHTTP(t *testing.T) {
	svc := NewWebhookServiceWithConfig(nil, nil, WebhookHTTPConfig{RequireHTTPS: true})
	for _, raw := range []string{
		"http://example.com/hook",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/latest/meta-data",
		"file:///etc/passwd",
		"https://user@example.com/hook",
	} {
		if err := svc.ValidateDestinationURL(context.Background(), raw); err == nil {
			t.Errorf("%s should be rejected", raw)
		}
	}
}
