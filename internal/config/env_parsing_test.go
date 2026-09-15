package config

import (
	"strings"
	"testing"
	"time"
)

// setMinimumEnv supplies the values Load() refuses to start without, so each
// test can vary exactly one variable.
func setMinimumEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://localhost/keygate")
	t.Setenv("JWT_SECRET", strings.Repeat("j", 32))
	t.Setenv("LICENSE_SIGNING_KEY", strings.Repeat("01", 32))
}

// TestLoadRejectsMalformedBooleans pins the fail-closed contract on boolean
// switches. Falling back to the default on a parse error is what makes a typo
// dangerous: SETUP_ENABLED=flase would leave the unauthenticated first-run
// bootstrap endpoint live, and OTP_OPEN_REGISTRATION=maybe would leave OTP
// self-registration open, both without a word in the logs.
func TestLoadRejectsMalformedBooleans(t *testing.T) {
	for _, key := range []string{"SETUP_ENABLED", "OTP_ENABLED", "OTP_OPEN_REGISTRATION"} {
		t.Run(key, func(t *testing.T) {
			setMinimumEnv(t)
			t.Setenv(key, "flase")

			cfg, err := Load()
			if err == nil {
				t.Fatalf("Load() accepted %s=flase and produced %+v", key, cfg)
			}
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("error should name the offending variable, got: %v", err)
			}
		})
	}
}

func TestLoadAcceptsBooleanSpellings(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"1", true}, {"t", true},
		{"false", false}, {"FALSE", false}, {"0", false}, {"f", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			setMinimumEnv(t)
			t.Setenv("SETUP_ENABLED", tc.raw)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load(): %v", err)
			}
			if cfg.SetupEnabled != tc.want {
				t.Fatalf("SETUP_ENABLED=%s → %v, want %v", tc.raw, cfg.SetupEnabled, tc.want)
			}
		})
	}
}

// An unset or blank value keeps the documented default rather than erroring —
// blank is how docker-compose passes "operator did not set this".
func TestLoadBlankBooleanKeepsDefault(t *testing.T) {
	setMinimumEnv(t)
	t.Setenv("SETUP_ENABLED", "   ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if !cfg.SetupEnabled {
		t.Fatal("blank SETUP_ENABLED should fall back to the documented default (true)")
	}
}

// OTP_OPEN_REGISTRATION defaults to closed in production and open elsewhere.
// Getting this backwards turns the OTP endpoint into an open account factory.
func TestOTPOpenRegistrationDefaultsClosedInProduction(t *testing.T) {
	setMinimumEnv(t)
	t.Setenv("ENVIRONMENT", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.OTPOpenRegistration {
		t.Fatal("production must default to closed OTP registration")
	}

	t.Setenv("ENVIRONMENT", "development")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if !cfg.OTPOpenRegistration {
		t.Fatal("development should default to open OTP registration")
	}
}

func TestLoadRejectsMalformedDurations(t *testing.T) {
	setMinimumEnv(t)
	t.Setenv("OFFLINE_TOKEN_TTL", "24 hours")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an unparsable OFFLINE_TOKEN_TTL")
	}
}

// The production fatals added by the hardening pass are the only thing
// standing between a default-configured deployment and an unauthenticated
// /metrics scrape or an unpeppered OTP table. Assert each one fires.
func TestProductionFatalsCoverEveryNewSecret(t *testing.T) {
	base := func() *Config {
		return &Config{
			Environment:               "production",
			BaseURL:                   "https://keygate.example",
			RedisURL:                  "redis://localhost:6379/0",
			JWTSecret:                 strings.Repeat("j", 32),
			LicenseSigningKey:         strings.Repeat("01", 32),
			LicenseTokenPolicyVersion: 1,
			OfflineTokenTTL:           time.Hour,
			MaxRequestBodyBytes:       1024,
			StripeWebhookMaxBytes:     512,
			HTTPReadHeaderTimeout:     time.Second,
			HTTPReadTimeout:           time.Second,
			HTTPWriteTimeout:          time.Second,
			HTTPIdleTimeout:           time.Second,
			HTTPMaxHeaderBytes:        1024,
			ReleaseKeyEncryptionKey:   strings.Repeat("02", 32),
			MetricsToken:              strings.Repeat("m", 32),
			OTPPepper:                 strings.Repeat("o", 32),
			OTPEnabled:                true,
			SMTPHost:                  "smtp.example",
			SMTPFrom:                  "no-reply@example",
			SetupEnabled:              false,
		}
	}

	if _, fatal := base().ValidateSecurityDefaults(); len(fatal) != 0 {
		t.Fatalf("baseline production config should be clean, got: %v", fatal)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		expect string
	}{
		{"metrics token too short", func(c *Config) { c.MetricsToken = "short" }, "METRICS_TOKEN"},
		{"otp pepper too short", func(c *Config) { c.OTPPepper = "short" }, "OTP_PEPPER"},
		{"otp without smtp", func(c *Config) { c.SMTPHost = "" }, "SMTP_HOST"},
		{"setup enabled without secret", func(c *Config) { c.SetupEnabled = true }, "BOOTSTRAP_SECRET"},
		{"master key missing", func(c *Config) { c.ReleaseKeyEncryptionKey = "" }, "RELEASE_KEY_ENCRYPTION_KEY"},
		{"previous master key equals current", func(c *Config) {
			c.ReleaseKeyEncryptionPreviousKey = c.ReleaseKeyEncryptionKey
		}, "must differ"},
		{"previous signing key without id", func(c *Config) {
			c.LicensePreviousPublicKey = strings.Repeat("03", 32)
		}, "previous signing key"},
		{"negative grace period", func(c *Config) { c.OfflineGracePeriod = -time.Second }, "OFFLINE_GRACE_PERIOD"},
		{"webhook cap exceeds body cap", func(c *Config) { c.StripeWebhookMaxBytes = c.MaxRequestBodyBytes + 1 }, "STRIPE_WEBHOOK_MAX_KB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			_, fatal := c.ValidateSecurityDefaults()
			if !strings.Contains(strings.Join(fatal, "\n"), tc.expect) {
				t.Fatalf("expected a fatal mentioning %q, got: %v", tc.expect, fatal)
			}
		})
	}
}

// Paths are appended to BaseURL, so a trailing slash must not leak into it.
// The token issuer keeps the configured value: already-issued tokens carry
// it and clients may pin it.
func TestLoadTrimsBaseURLTrailingSlash(t *testing.T) {
	setMinimumEnv(t)
	t.Setenv("BASE_URL", "https://license.example.com/")
	t.Setenv("LICENSE_TOKEN_ISSUER", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.BaseURL != "https://license.example.com" {
		t.Fatalf("BaseURL = %q, want no trailing slash", cfg.BaseURL)
	}
	if cfg.LicenseTokenIssuer != "https://license.example.com/" {
		t.Fatalf("LicenseTokenIssuer = %q, want BASE_URL unchanged", cfg.LicenseTokenIssuer)
	}
}
