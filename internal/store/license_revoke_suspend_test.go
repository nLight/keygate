package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// Ported from upstream 35ed499 / fbdbe1d, adapted to this fork's helpers.

func licenseStatus(t *testing.T, s *store.Store, ctx context.Context, id string) string {
	t.Helper()
	var st string
	if err := s.DB.NewRaw("SELECT status FROM licenses WHERE id = ?", id).Scan(ctx, &st); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return st
}

func TestRevokeLicense_DeletesActivationsAndFloatingSessions(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()
	lic := createTestLicense(t, s, ctx)

	if err := s.CreateActivation(ctx, &model.Activation{LicenseID: lic.ID, Identifier: "machine-1", IdentifierType: "device"}); err != nil {
		t.Fatalf("create activation: %v", err)
	}
	if err := s.CheckOutFloating(ctx, &model.FloatingSession{LicenseID: lic.ID, Identifier: "machine-1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("checkout floating: %v", err)
	}

	if err := s.RevokeLicense(ctx, lic.ID); err != nil {
		t.Fatalf("RevokeLicense: %v", err)
	}
	if st := licenseStatus(t, s, ctx, lic.ID); st != model.StatusRevoked {
		t.Errorf("status = %s, want revoked", st)
	}
	if n, err := s.CountActivations(ctx, lic.ID); err != nil || n != 0 {
		t.Errorf("activations after revoke = %d (%v), want 0", n, err)
	}
	if n, err := s.DB.NewSelect().Model((*model.FloatingSession)(nil)).Where("license_id = ?", lic.ID).Count(ctx); err != nil || n != 0 {
		t.Errorf("floating sessions after revoke = %d (%v), want 0", n, err)
	}
}

func TestRevokeAndSuspend_NotFound(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()
	if err := s.RevokeLicense(ctx, "nonexistent-id"); !errors.Is(err, store.ErrLicenseNotFound) {
		t.Errorf("RevokeLicense err = %v, want ErrLicenseNotFound", err)
	}
	if err := s.SuspendLicense(ctx, "nonexistent-id"); !errors.Is(err, store.ErrLicenseNotFound) {
		t.Errorf("SuspendLicense err = %v, want ErrLicenseNotFound", err)
	}
}

// A revoked licence cannot be suspended: reinstate accepts a suspended
// licence, so revoke → suspend → reinstate would bring it back.
func TestSuspendLicense_RefusesRevokedAndSuspended(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()

	lic := createTestLicense(t, s, ctx)
	if err := s.SuspendLicense(ctx, lic.ID); err != nil {
		t.Fatalf("SuspendLicense: %v", err)
	}
	if err := s.SuspendLicense(ctx, lic.ID); !errors.Is(err, store.ErrLicenseNotSuspendable) {
		t.Errorf("second suspend err = %v, want ErrLicenseNotSuspendable", err)
	}

	revoked := createTestLicense(t, s, ctx)
	if err := s.RevokeLicense(ctx, revoked.ID); err != nil {
		t.Fatalf("RevokeLicense: %v", err)
	}
	if err := s.SuspendLicense(ctx, revoked.ID); !errors.Is(err, store.ErrLicenseNotSuspendable) {
		t.Fatalf("suspend revoked err = %v, want ErrLicenseNotSuspendable", err)
	}
	if err := s.ReinstateLicense(ctx, revoked.ID); err == nil {
		t.Errorf("reinstate of a revoked licence succeeded")
	}
	if st := licenseStatus(t, s, ctx, revoked.ID); st != model.StatusRevoked {
		t.Errorf("status = %s, want revoked", st)
	}
}
