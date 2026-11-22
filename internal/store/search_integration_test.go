package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/store"
)

// Admin list searches match literally: _ and % in a term are not LIKE
// wildcards, so "kg_live_x" does not also find "kgxlive1x".
func TestAdminListSearchesAreLiteral(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()
	suffix := time.Now().Format("150405.000000")

	target := &model.Product{Name: "100%-" + suffix, Slug: "kg_live_" + suffix, Type: "desktop"}
	decoy := &model.Product{Name: "100x-" + suffix, Slug: "kgxlive1" + suffix, Type: "desktop"}
	for _, p := range []*model.Product{target, decoy} {
		if err := s.CreateProduct(ctx, p); err != nil {
			t.Fatalf("create product: %v", err)
		}
	}
	for _, q := range []string{"kg_live_" + suffix, "100%-" + suffix} {
		got, err := s.ListProducts(ctx, q)
		if err != nil {
			t.Fatalf("ListProducts(%q): %v", q, err)
		}
		if len(got) != 1 || got[0].ID != target.ID {
			t.Errorf("ListProducts(%q) matched %d rows, want only the target", q, len(got))
		}
	}
}

// A license is found by its whole key (through the key hash) and by
// email; plaintext keys are not stored, so there is no prefix search.
func TestListLicensesSearchByKeyAndEmail(t *testing.T) {
	s := setupTestDB(t)
	defer s.Close()
	ctx := context.Background()
	lic := createTestLicense(t, s, ctx)

	for _, q := range []string{lic.LicenseKey, " " + lic.LicenseKey + " ", lic.Email} {
		got, total, err := s.ListLicenses(ctx, store.LicenseListFilter{Search: q, Limit: 10})
		if err != nil {
			t.Fatalf("ListLicenses(%q): %v", q, err)
		}
		if total != 1 || len(got) != 1 || got[0].ID != lic.ID {
			t.Errorf("ListLicenses(%q) = %d rows (total %d), want the license", q, len(got), total)
		}
	}
	got, _, err := s.ListLicenses(ctx, store.LicenseListFilter{Search: lic.LicenseKey[:6], Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		if l.ID == lic.ID {
			t.Errorf("a key prefix matched the license; only whole keys should")
		}
	}
}
