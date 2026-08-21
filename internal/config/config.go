package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port        string
	Environment string
	BaseURL     string

	DatabaseURL string

	JWTSecret                    string
	LicenseSigningKey            string
	LicenseSigningKeyID          string
	LicensePreviousPublicKey     string
	LicensePreviousKeyID         string
	LicensePreviousKeyValidUntil time.Time
	LicenseTokenIssuer           string
	LicenseTokenPolicyVersion    int
	OfflineTokenTTL              time.Duration
	OfflineGracePeriod           time.Duration
	OfflineClockSkew             time.Duration

	// First-run setup is disabled after an owner has been provisioned. When it
	// is enabled, BootstrapSecret is a one-time, out-of-band credential and is
	// never returned by the API.
	SetupEnabled    bool
	BootstrapSecret string

	OTPEnabled          bool
	OTPPepper           string
	OTPOpenRegistration bool
	OTPAllowedDomains   []string

	StripeSecretKey     string
	StripeWebhookSecret string
	// StripeLivemode tells the webhook handler which environment to
	// trust. A mismatch between this flag and event.Livemode is a
	// configuration error or a forged delivery; either way the
	// handler must reject. Auto-derived from the secret key prefix
	// (sk_live_ vs sk_test_) unless STRIPE_LIVEMODE is set explicitly.
	StripeLivemode bool

	WebhookMaxAttempts    int
	WebhookRetryInterval  string
	WebhookHTTPTimeout    string
	QuotaWarningThreshold float64

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	RedisURL     string
	MetricsToken string

	MaxRequestBodyBytes   int64
	StripeWebhookMaxBytes int64
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	HTTPMaxHeaderBytes    int

	RateLimitAPI   int
	RateLimitAdmin int
	RateLimitAuth  int

	// Brute-force protection on /license/* — caps repeated bad license
	// keys per IP. In tests these defaults are too tight, so they're
	// configurable via env: BF_MAX_FAILS=5 / BF_LOCKOUT=30s / etc.
	BFMaxFails       int
	BFLockoutSeconds int

	AdminEmails []string

	// ─── Storage (release artifacts: R2 / S3 / S3-compatible) ───
	// All fields are optional. The storage subsystem is enabled iff
	// StorageBucket is non-empty and credentials are present. When disabled,
	// release endpoints return 503 — license/billing functions are unaffected.
	StorageEndpoint       string // e.g. https://<account>.r2.cloudflarestorage.com (empty = AWS S3)
	StorageRegion         string // R2 uses "auto"; AWS S3 uses real region
	StorageBucket         string
	StorageAccessKey      string
	StorageSecretKey      string
	StoragePublicURL      string // optional CDN URL prefix for public reads (not used for license-gated downloads)
	StorageForcePathStyle bool   // true for MinIO and some self-hosted S3 gateways

	// Presigned URL TTLs.
	StorageUploadTTL   string // default "1h"
	StorageDownloadTTL string // default "10m"

	// ReleaseKeyEncryptionKey is a 64-char hex string (32 bytes) used as the
	// AES-256-GCM master key for encrypting product release-signing private
	// keys at rest. Required when storage is enabled.
	//
	// Operational notes:
	//   - Generate via: openssl rand -hex 32
	//   - Rotation requires supplying the former value through
	//     RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY for one successful startup.
	//     Startup verifies and restart-safely re-encrypts existing rows.
	//   - Losing this key permanently locks all signed releases.
	ReleaseKeyEncryptionKey string
	// ReleaseKeyEncryptionPreviousKey is accepted only during a controlled,
	// restart-safe rotation. Remove it after every row has been re-encrypted.
	ReleaseKeyEncryptionPreviousKey string

	// MaxReleaseSignSize caps the largest artifact we will sign server-side.
	// Pure Ed25519 requires the full message in memory; 500 MB is a
	// reasonable default that doesn't OOM modest VMs. Larger artifacts
	// must use unsigned mode (Phase 3 will add streaming via tempfile).
	MaxReleaseSignSize int64
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Port:        envOr("PORT", "9000"),
		Environment: envOr("ENVIRONMENT", "development"),
		BaseURL:     envOr("BASE_URL", "http://localhost:9000"),

		DatabaseURL: os.Getenv("DATABASE_URL"),

		JWTSecret:                 os.Getenv("JWT_SECRET"),
		LicenseSigningKey:         os.Getenv("LICENSE_SIGNING_KEY"),
		LicenseSigningKeyID:       os.Getenv("LICENSE_SIGNING_KEY_ID"),
		LicensePreviousPublicKey:  os.Getenv("LICENSE_PREVIOUS_PUBLIC_KEY"),
		LicensePreviousKeyID:      os.Getenv("LICENSE_PREVIOUS_KEY_ID"),
		LicenseTokenPolicyVersion: envIntOr("LICENSE_TOKEN_POLICY_VERSION", 1),
		BootstrapSecret:           os.Getenv("BOOTSTRAP_SECRET"),
		OTPPepper:                 os.Getenv("OTP_PEPPER"),

		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
	}
	cfg.LicenseTokenIssuer = envOr("LICENSE_TOKEN_ISSUER", cfg.BaseURL)

	var err error
	if cfg.SetupEnabled, err = envBoolOr("SETUP_ENABLED", true); err != nil {
		return nil, err
	}
	if cfg.OTPEnabled, err = envBoolOr("OTP_ENABLED", true); err != nil {
		return nil, err
	}
	if cfg.OTPOpenRegistration, err = envBoolOr("OTP_OPEN_REGISTRATION", !cfg.IsProduction()); err != nil {
		return nil, err
	}
	if domains := os.Getenv("OTP_ALLOWED_DOMAINS"); domains != "" {
		for _, domain := range strings.Split(domains, ",") {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" {
				cfg.OTPAllowedDomains = append(cfg.OTPAllowedDomains, domain)
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv("LICENSE_PREVIOUS_KEY_VALID_UNTIL")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, fmt.Errorf("LICENSE_PREVIOUS_KEY_VALID_UNTIL must be RFC3339: %w", err)
		}
		cfg.LicensePreviousKeyValidUntil = parsed
	}

	if cfg.OfflineTokenTTL, err = envDurationOr("OFFLINE_TOKEN_TTL", "24h"); err != nil {
		return nil, err
	}
	if cfg.OfflineGracePeriod, err = envDurationOr("OFFLINE_GRACE_PERIOD", "0s"); err != nil {
		return nil, err
	}
	if cfg.OfflineClockSkew, err = envDurationOr("OFFLINE_CLOCK_SKEW", "2m"); err != nil {
		return nil, err
	}
	if cfg.HTTPReadHeaderTimeout, err = envDurationOr("HTTP_READ_HEADER_TIMEOUT", "5s"); err != nil {
		return nil, err
	}
	if cfg.HTTPReadTimeout, err = envDurationOr("HTTP_READ_TIMEOUT", "15s"); err != nil {
		return nil, err
	}
	if cfg.HTTPWriteTimeout, err = envDurationOr("HTTP_WRITE_TIMEOUT", "30s"); err != nil {
		return nil, err
	}
	if cfg.HTTPIdleTimeout, err = envDurationOr("HTTP_IDLE_TIMEOUT", "60s"); err != nil {
		return nil, err
	}
	cfg.MaxRequestBodyBytes = int64(envIntOr("MAX_REQUEST_BODY_KB", 1024)) * 1024
	cfg.StripeWebhookMaxBytes = int64(envIntOr("STRIPE_WEBHOOK_MAX_KB", 256)) * 1024
	cfg.HTTPMaxHeaderBytes = envIntOr("HTTP_MAX_HEADER_KB", 32) * 1024

	envVal, envSet := os.LookupEnv("STRIPE_LIVEMODE")
	cfg.StripeLivemode = deriveLivemode(envVal, envSet, cfg.StripeSecretKey)

	cfg.RedisURL = os.Getenv("REDIS_URL")
	cfg.MetricsToken = os.Getenv("METRICS_TOKEN")

	cfg.SMTPHost = os.Getenv("SMTP_HOST")
	cfg.SMTPPort = envOr("SMTP_PORT", "587")
	cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
	cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
	cfg.SMTPFrom = os.Getenv("SMTP_FROM")

	cfg.RateLimitAPI = envIntOr("RATE_LIMIT_API", 60)
	cfg.RateLimitAdmin = envIntOr("RATE_LIMIT_ADMIN", 120)
	cfg.RateLimitAuth = envIntOr("RATE_LIMIT_AUTH", 20)
	cfg.BFMaxFails = envIntOr("BF_MAX_FAILS", 5)
	cfg.BFLockoutSeconds = envIntOr("BF_LOCKOUT_SECONDS", 30)

	cfg.WebhookMaxAttempts = envIntOr("WEBHOOK_MAX_ATTEMPTS", 5)
	cfg.WebhookRetryInterval = envOr("WEBHOOK_RETRY_INTERVAL", "30s")
	cfg.WebhookHTTPTimeout = envOr("WEBHOOK_HTTP_TIMEOUT", "10s")
	cfg.QuotaWarningThreshold = envFloatOr("QUOTA_WARNING_THRESHOLD", 0.8)

	if admins := os.Getenv("ADMIN_EMAILS"); admins != "" {
		for _, e := range strings.Split(admins, ",") {
			cfg.AdminEmails = append(cfg.AdminEmails, strings.TrimSpace(e))
		}
	}

	cfg.StorageEndpoint = os.Getenv("STORAGE_ENDPOINT")
	cfg.StorageRegion = envOr("STORAGE_REGION", "auto")
	cfg.StorageBucket = os.Getenv("STORAGE_BUCKET")
	cfg.StorageAccessKey = os.Getenv("STORAGE_ACCESS_KEY")
	cfg.StorageSecretKey = os.Getenv("STORAGE_SECRET_KEY")
	cfg.StoragePublicURL = os.Getenv("STORAGE_PUBLIC_URL")
	cfg.StorageForcePathStyle = strings.EqualFold(os.Getenv("STORAGE_FORCE_PATH_STYLE"), "true")
	cfg.StorageUploadTTL = envOr("STORAGE_UPLOAD_TTL", "1h")
	cfg.StorageDownloadTTL = envOr("STORAGE_DOWNLOAD_TTL", "10m")
	cfg.ReleaseKeyEncryptionKey = os.Getenv("RELEASE_KEY_ENCRYPTION_KEY")
	cfg.ReleaseKeyEncryptionPreviousKey = os.Getenv("RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY")
	cfg.MaxReleaseSignSize = int64(envIntOr("MAX_RELEASE_SIGN_SIZE_MB", 500)) * 1024 * 1024

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if cfg.LicenseSigningKey == "" {
		return nil, fmt.Errorf("LICENSE_SIGNING_KEY is required")
	}

	return cfg, nil
}

func (c *Config) normalizedEnv() string {
	return strings.ToLower(strings.TrimSpace(c.Environment))
}

func (c *Config) IsProduction() bool { return c.normalizedEnv() == "production" }

func (c *Config) IsDevLoginAllowed() bool { return c.normalizedEnv() == "development" }

// IsAdminEmail checks if an email is in the ADMIN_EMAILS list.
// Used for backward compatibility and initial setup bootstrap.
// In normal operation, admin status is determined by the user's role in the database.
func (c *Config) IsAdminEmail(email string) bool {
	for _, e := range c.AdminEmails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

// deriveLivemode decides whether the server should treat Stripe
// events as live (real money) or test. Order of precedence:
//
//  1. STRIPE_LIVEMODE env (case-insensitive "true" or "1") wins.
//  2. sk_live_… / rk_live_… secret key prefix → true.
//  3. sk_test_… / rk_test_… → false.
//  4. anything else (including unset) → false. Safe default:
//     operators must opt INTO live mode rather than fall into it
//     by accident. Mismatched events get a 400 in the webhook
//     handler, so this default minimises the blast radius of a
//     half-configured deployment.
//
// Pulled out as a free function so it can be unit-tested without
// the full Load() side-effects (godotenv, ADMIN_EMAILS parsing, etc).
func deriveLivemode(envVal string, envSet bool, secretKey string) bool {
	if envSet {
		return strings.EqualFold(envVal, "true") || envVal == "1"
	}
	return strings.HasPrefix(secretKey, "sk_live_") ||
		strings.HasPrefix(secretKey, "rk_live_")
}

// IsStorageEnabled reports whether the storage subsystem (release artifacts)
// has the minimum required configuration. Endpoint/region/path-style are
// optional — only bucket+credentials are mandatory.
func (c *Config) IsStorageEnabled() bool {
	return c.StorageBucket != "" &&
		c.StorageAccessKey != "" &&
		c.StorageSecretKey != ""
}

// IsMasterEncryptionKeyConfigured reports whether the operator supplied the
// AES-256 master key that's used to derive subkeys for:
//   - license_key at-rest encryption
//   - release artifact signing private keys
//
// These two features are independently useful: a deployment that never
// distributes binaries can still benefit from license-key encryption.
// We therefore treat the master key as orthogonal to storage.
func (c *Config) IsMasterEncryptionKeyConfigured() bool {
	return len(c.ReleaseKeyEncryptionKey) == 64
}

// ValidateSecurityDefaults checks for common misconfigurations that could
// lead to security vulnerabilities in production deployments.
// Returns a list of warnings (non-fatal) and errors (fatal).
func (c *Config) ValidateSecurityDefaults() (warnings []string, fatal []string) {
	// Validate environment value
	env := strings.ToLower(strings.TrimSpace(c.Environment))
	switch env {
	case "development", "staging", "production":
		// valid
	default:
		fatal = append(fatal, "ENVIRONMENT must be 'development', 'staging', or 'production', got: '"+c.Environment+"'")
	}

	// Fatal: JWT secret too short
	if len(c.JWTSecret) < 32 {
		fatal = append(fatal, "JWT_SECRET must be at least 32 characters")
	}
	// LICENSE_SIGNING_KEY must be a 32-byte ed25519 seed, hex-encoded
	// (64 chars). It signs the offline-verifiable license token that
	// SDKs hand to desktop clients. Ed25519 + hex-encoded seed is the
	// industry-standard format for env-var-style key distribution.
	if seed, err := hex.DecodeString(strings.TrimSpace(c.LicenseSigningKey)); err != nil || len(seed) != 32 {
		fatal = append(fatal,
			"LICENSE_SIGNING_KEY must be a 32-byte ed25519 seed in hex (64 chars); generate with 'openssl rand -hex 32'")
	}

	if c.IsProduction() {
		baseURL, err := url.Parse(c.BaseURL)
		if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" {
			fatal = append(fatal, "BASE_URL must be an absolute https URL in production")
		}
		if strings.TrimSpace(c.RedisURL) == "" {
			fatal = append(fatal, "REDIS_URL is required in production for distributed abuse protection")
		}
		// Must have at least one admin
		if len(c.AdminEmails) == 0 {
			warnings = append(warnings, "SECURITY: ADMIN_EMAILS is empty — no one can access the admin panel")
		}
		if len(c.MetricsToken) < 32 {
			fatal = append(fatal, "METRICS_TOKEN must contain at least 32 characters in production")
		}
		if c.OTPEnabled && (c.SMTPHost == "" || c.SMTPFrom == "") {
			fatal = append(fatal, "SMTP_HOST and SMTP_FROM are required when OTP_ENABLED=true in production")
		}
	}
	if c.ReleaseKeyEncryptionPreviousKey != "" {
		if len(c.ReleaseKeyEncryptionPreviousKey) != 64 {
			fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY must be exactly 64 hex chars")
		} else if _, err := hex.DecodeString(c.ReleaseKeyEncryptionPreviousKey); err != nil {
			fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY is not valid hex: "+err.Error())
		} else if c.ReleaseKeyEncryptionPreviousKey == c.ReleaseKeyEncryptionKey {
			fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY must differ from the current master key")
		}
	}
	if c.SetupEnabled && len(c.BootstrapSecret) < 32 {
		fatal = append(fatal, "BOOTSTRAP_SECRET must contain at least 32 characters while SETUP_ENABLED=true")
	}
	if c.OTPEnabled && len(c.OTPPepper) < 32 {
		fatal = append(fatal, "OTP_PEPPER must contain at least 32 characters when OTP_ENABLED=true")
	}
	if c.OfflineTokenTTL <= 0 {
		fatal = append(fatal, "OFFLINE_TOKEN_TTL must be positive")
	}
	if c.OfflineGracePeriod < 0 || c.OfflineClockSkew < 0 {
		fatal = append(fatal, "OFFLINE_GRACE_PERIOD and OFFLINE_CLOCK_SKEW cannot be negative")
	}
	if c.LicenseTokenPolicyVersion <= 0 {
		fatal = append(fatal, "LICENSE_TOKEN_POLICY_VERSION must be positive")
	}
	if c.MaxRequestBodyBytes <= 0 || c.StripeWebhookMaxBytes <= 0 || c.StripeWebhookMaxBytes > c.MaxRequestBodyBytes {
		fatal = append(fatal, "request body limits must be positive and STRIPE_WEBHOOK_MAX_KB must not exceed MAX_REQUEST_BODY_KB")
	}
	if c.HTTPReadHeaderTimeout <= 0 || c.HTTPReadTimeout <= 0 || c.HTTPWriteTimeout <= 0 || c.HTTPIdleTimeout <= 0 || c.HTTPMaxHeaderBytes <= 0 {
		fatal = append(fatal, "HTTP server timeouts and header limit must be positive")
	}
	if c.LicensePreviousPublicKey != "" {
		pub, err := hex.DecodeString(strings.TrimSpace(c.LicensePreviousPublicKey))
		if err != nil || len(pub) != 32 || c.LicensePreviousKeyID == "" || c.LicensePreviousKeyValidUntil.IsZero() {
			fatal = append(fatal, "previous signing key requires a 32-byte hex LICENSE_PREVIOUS_PUBLIC_KEY, LICENSE_PREVIOUS_KEY_ID, and LICENSE_PREVIOUS_KEY_VALID_UNTIL")
		}
	}

	if c.IsDevLoginAllowed() {
		warnings = append(warnings, "SECURITY: dev-login is enabled (ENVIRONMENT=development) — do NOT use in production")
	}

	// Storage: validate that partial config doesn't silently disable releases.
	// If any storage field is set, all required fields must be set.
	storageFieldsSet := c.StorageBucket != "" ||
		c.StorageAccessKey != "" ||
		c.StorageSecretKey != "" ||
		c.StorageEndpoint != ""
	if storageFieldsSet && !c.IsStorageEnabled() {
		fatal = append(fatal, "STORAGE_*: partial config detected — STORAGE_BUCKET, STORAGE_ACCESS_KEY, and STORAGE_SECRET_KEY must all be set together (or all empty to disable releases)")
	}

	// Release signing master key: required iff storage is enabled. Length
	// must be exactly 64 hex chars (32 bytes for AES-256). We don't accept
	// the "fallback to a derived key" mode — operators must explicitly own
	// this secret because losing it means losing the ability to verify
	// past signatures.
	// Master encryption key validation: required when storage is enabled
	// (release signing needs it) AND validated even when only set without
	// storage (license-key encryption uses it independently).
	switch {
	case c.IsStorageEnabled() && c.ReleaseKeyEncryptionKey == "":
		fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_KEY is required when storage is enabled — generate via: openssl rand -hex 32")
	case c.ReleaseKeyEncryptionKey == "":
		fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_KEY is required for ciphertext-only license-key storage — generate via: openssl rand -hex 32")
	case len(c.ReleaseKeyEncryptionKey) != 64:
		fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_KEY must be exactly 64 hex chars (32 bytes for AES-256)")
	default:
		if _, err := hex.DecodeString(c.ReleaseKeyEncryptionKey); err != nil {
			fatal = append(fatal, "RELEASE_KEY_ENCRYPTION_KEY is not valid hex: "+err.Error())
		}
	}

	return
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envFloatOr(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

// envBoolOr parses a boolean env var, failing closed on garbage.
//
// Returning the fallback for an unparsable value is the wrong default for a
// security switch: a typo in SETUP_ENABLED or OTP_OPEN_REGISTRATION would
// silently leave first-run bootstrap or open registration enabled instead of
// stopping the boot. The operator has to fix the value.
func envBoolOr(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean (true/false/1/0), got %q", key, v)
	}
	return b, nil
}

func envDurationOr(key, fallback string) (time.Duration, error) {
	raw := envOr(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}
	return d, nil
}
