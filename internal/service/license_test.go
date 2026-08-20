package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	lictoken "github.com/tabloy/keygate/internal/license"
	"github.com/tabloy/keygate/internal/model"
)

func TestAssertUsable(t *testing.T) {
	svc := &LicenseService{}

	now := time.Now()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)
	wayPast := now.Add(-30 * 24 * time.Hour)

	tests := []struct {
		name    string
		license *model.License
		wantErr bool
		errCode string
	}{
		{
			name:    "active license with future expiry",
			license: &model.License{Status: model.StatusActive, ValidUntil: &future, Plan: &model.Plan{GraceDays: 7}},
			wantErr: false,
		},
		{
			name:    "active license no expiry",
			license: &model.License{Status: model.StatusActive, Plan: &model.Plan{GraceDays: 7}},
			wantErr: false,
		},
		{
			name:    "active license recently expired within grace",
			license: &model.License{Status: model.StatusActive, ValidUntil: &past, Plan: &model.Plan{GraceDays: 7}},
			wantErr: false,
		},
		{
			name:    "active license expired beyond grace",
			license: &model.License{Status: model.StatusActive, ValidUntil: &wayPast, Plan: &model.Plan{GraceDays: 7}},
			wantErr: true,
			errCode: "LICENSE_EXPIRED",
		},
		{
			name:    "trialing license",
			license: &model.License{Status: model.StatusTrialing, Plan: &model.Plan{GraceDays: 7}},
			wantErr: false,
		},
		{
			name:    "canceled license within paid period",
			license: &model.License{Status: model.StatusCanceled, ValidUntil: &future},
			wantErr: false,
		},
		{
			name:    "canceled license past paid period",
			license: &model.License{Status: model.StatusCanceled, ValidUntil: &past},
			wantErr: true,
			errCode: "LICENSE_CANCELED",
		},
		{
			name:    "suspended license",
			license: &model.License{Status: model.StatusSuspended},
			wantErr: true,
			errCode: "LICENSE_SUSPENDED",
		},
		{
			name:    "revoked license",
			license: &model.License{Status: model.StatusRevoked},
			wantErr: true,
			errCode: "LICENSE_REVOKED",
		},
		{
			name:    "expired license",
			license: &model.License{Status: model.StatusExpired},
			wantErr: true,
			errCode: "LICENSE_EXPIRED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.assertUsable(tt.license)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				// Check error contains expected code
				if tt.errCode != "" && !containsCode(err, tt.errCode) {
					t.Fatalf("expected error code %s, got %v", tt.errCode, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestOfflineTokenLifetimeBoundedByLicense(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(2_000_000_000, 0)
	svc := NewLicenseServiceWithConfig(nil, priv, nil, nil, nil, LicenseTokenConfig{
		Issuer: "issuer", PolicyVersion: 1, TTL: 7 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	validUntil := now.Add(time.Hour)
	lic := &model.License{
		ID: "lic", ProductID: "prod", PlanID: "plan", Status: model.StatusActive,
		ValidUntil: &validUntil, Plan: &model.Plan{GraceDays: 7},
	}
	raw, err := svc.signToken(lic, "device")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := lictoken.Verify(raw, lictoken.PublicKey(priv))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.ExpiresAt != validUntil.Unix() {
		t.Fatalf("exp=%d want %d", parsed.ExpiresAt, validUntil.Unix())
	}
	if parsed.ValidUntil != validUntil.Unix() || parsed.ProductID != "prod" || parsed.KeyID == "" || parsed.PolicyVersion != 1 {
		t.Fatalf("required claims missing: %+v", parsed)
	}
}

func TestOfflineTokenRejectsNonPositiveOrInactiveLifetime(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(2_000_000_000, 0)
	svc := NewLicenseServiceWithConfig(nil, priv, nil, nil, nil, LicenseTokenConfig{
		Issuer: "issuer", TTL: time.Hour, Now: func() time.Time { return now },
	})
	past := now.Add(-time.Second)
	for _, lic := range []*model.License{
		{ID: "expired-by-date", ProductID: "p", Status: model.StatusActive, ValidUntil: &past},
		{ID: "suspended", ProductID: "p", Status: model.StatusSuspended},
		{ID: "revoked", ProductID: "p", Status: model.StatusRevoked},
		{ID: "expired", ProductID: "p", Status: model.StatusExpired},
	} {
		if _, err := svc.signToken(lic, "device"); err == nil {
			t.Fatalf("%s received a token", lic.ID)
		}
	}
}

func containsCode(err error, code string) bool {
	return err != nil && containsStr(err.Error(), code)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMaxActivations(t *testing.T) {
	svc := &LicenseService{}

	tests := []struct {
		name string
		lic  *model.License
		want int
	}{
		{"with plan", &model.License{Plan: &model.Plan{MaxActivations: 5}}, 5},
		{"without plan", &model.License{}, 3},
		{"nil plan", &model.License{Plan: nil}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.maxActivations(tt.lic)
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGraceDays(t *testing.T) {
	svc := &LicenseService{}

	tests := []struct {
		name string
		lic  *model.License
		want int
	}{
		{"with plan", &model.License{Plan: &model.Plan{GraceDays: 14}}, 14},
		{"without plan", &model.License{}, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.graceDays(tt.lic)
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEntitlements(t *testing.T) {
	svc := &LicenseService{}

	lic := &model.License{
		Plan: &model.Plan{
			Entitlements: []*model.Entitlement{
				{Feature: "export", ValueType: "bool", Value: "true"},
				{Feature: "sso", ValueType: "bool", Value: "false"},
				{Feature: "max_users", ValueType: "int", Value: "50"},
				{Feature: "sla", ValueType: "string", Value: "99.9%"},
			},
		},
	}

	features := svc.entitlements(lic)

	if features["export"] != true {
		t.Error("export should be true")
	}
	if features["sso"] != false {
		t.Error("sso should be false")
	}
	if features["max_users"] != "50" {
		t.Errorf("max_users should be '50', got %v", features["max_users"])
	}
	if features["sla"] != "99.9%" {
		t.Errorf("sla should be '99.9%%', got %v", features["sla"])
	}

	nilLic := &model.License{}
	emptyFeatures := svc.entitlements(nilLic)
	if len(emptyFeatures) != 0 {
		t.Error("nil plan should return empty features")
	}
}
