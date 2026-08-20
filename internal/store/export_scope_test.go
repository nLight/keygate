package store

import (
	"context"
	"errors"
	"testing"
)

func TestExportLicensesRejectsProductScopeMismatchBeforeQuery(t *testing.T) {
	s := &Store{}
	_, err := s.ExportLicenses(context.Background(), LicenseExportFilter{
		ProductID: "product-b", ScopeProductID: "product-a",
	})
	if !errors.Is(err, ErrProductScopeMismatch) {
		t.Fatalf("expected ErrProductScopeMismatch, got %v", err)
	}
}
