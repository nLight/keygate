package store

import (
	"strings"
	"testing"

	"github.com/tabloy/keygate/internal/crypto"
	"github.com/tabloy/keygate/internal/model"
)

// These tests don't require a DB — they exercise the in-memory AEAD path
// (prepareLicenseForInsert + DecryptLicenseKey). The full DB round-trip
// is covered by the integration_test.go suite when TEST_DATABASE_URL is set.

func makeStoreWithAEAD(t *testing.T) *Store {
	t.Helper()
	master := strings.Repeat("ab", crypto.MasterKeyBytes) // 64 hex chars
	aead, err := crypto.NewAESGCMFromHex(master)
	if err != nil {
		t.Fatalf("aead init: %v", err)
	}
	return &Store{LicenseKeyAEAD: aead}
}

func TestPrepareLicenseForInsert_PopulatesEncrypted(t *testing.T) {
	s := makeStoreWithAEAD(t)
	l := &model.License{LicenseKey: "KGT-AAAA-BBBB-CCCC-DDDD"}

	if err := s.prepareLicenseForInsert(l); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	if l.ID == "" {
		t.Error("ID must be set")
	}
	if l.KeyHash == "" {
		t.Error("KeyHash must be set")
	}
	if len(l.LicenseKeyEncrypted) == 0 {
		t.Error("LicenseKeyEncrypted must be populated when AEAD is configured")
	}
	// Sanity: ciphertext must not be the plaintext.
	if string(l.LicenseKeyEncrypted) == l.LicenseKey {
		t.Error("ciphertext must differ from plaintext")
	}
}

func TestDecryptLicenseKey_RoundTrip(t *testing.T) {
	s := makeStoreWithAEAD(t)
	l := &model.License{LicenseKey: "KGT-XXXX-YYYY-ZZZZ"}
	if err := s.prepareLicenseForInsert(l); err != nil {
		t.Fatal(err)
	}

	// Simulate a row read after the legacy plaintext column has been wiped.
	plainSaved := l.LicenseKey
	l.LicenseKey = ""

	got := s.DecryptLicenseKey(l)
	if got != plainSaved {
		t.Errorf("round-trip failed: got %q want %q", got, plainSaved)
	}
}

func TestDecryptLicenseKey_MissingCiphertextFailsClosed(t *testing.T) {
	s := makeStoreWithAEAD(t)
	l := &model.License{ID: "lic_legacy", LicenseKey: "KGT-OLD-ROW"}

	got := s.DecryptLicenseKey(l)
	if got != "" {
		t.Errorf("missing ciphertext must fail closed: got %q", got)
	}
}

func TestDecryptLicenseKey_NoAEAD(t *testing.T) {
	// Encryption disabled (e.g. storage not configured).
	s := &Store{}
	l := &model.License{ID: "lic_x", LicenseKey: "KGT-FOO"}

	got := s.DecryptLicenseKey(l)
	if got != "" {
		t.Errorf("missing AEAD must fail closed: got %q", got)
	}
}

func TestDecryptLicenseKey_AADBindingPreventsCrossRowReplay(t *testing.T) {
	s := makeStoreWithAEAD(t)
	l1 := &model.License{LicenseKey: "KGT-AAAA"}
	l2 := &model.License{LicenseKey: "KGT-BBBB"}
	if err := s.prepareLicenseForInsert(l1); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareLicenseForInsert(l2); err != nil {
		t.Fatal(err)
	}

	// Try to graft l1's ciphertext onto l2's row (different ID = different AAD).
	swapped := &model.License{
		ID:                  l2.ID,
		LicenseKey:          "", // simulate Phase C
		LicenseKeyEncrypted: l1.LicenseKeyEncrypted,
	}
	got := s.DecryptLicenseKey(swapped)
	// Decrypt fails with wrong AAD and there is deliberately no plaintext
	// fallback, so the fail-closed result is empty.
	if got == "KGT-AAAA" {
		t.Errorf("AAD binding broken: cross-row decrypt succeeded")
	}
	if got != "" {
		t.Errorf("expected empty (decrypt fail + empty plaintext fallback): got %q", got)
	}
}

func TestDecryptLicenseKey_NilLicense(t *testing.T) {
	s := makeStoreWithAEAD(t)
	if got := s.DecryptLicenseKey(nil); got != "" {
		t.Errorf("nil license must return empty string: got %q", got)
	}
}

func TestPrepareLicenseForInsert_NoAEADFailsClosed(t *testing.T) {
	s := &Store{} // no AEAD
	l := &model.License{LicenseKey: "KGT-NOENC"}

	if err := s.prepareLicenseForInsert(l); err == nil {
		t.Fatal("expected missing AEAD to reject the insert")
	}
}

func TestPrepareLicenseForInsert_DifferentIDsProduceDifferentCiphertexts(t *testing.T) {
	s := makeStoreWithAEAD(t)
	l1 := &model.License{LicenseKey: "KGT-SAME"}
	l2 := &model.License{LicenseKey: "KGT-SAME"}
	_ = s.prepareLicenseForInsert(l1)
	_ = s.prepareLicenseForInsert(l2)

	// Even with the same plaintext, AAD (= ID) differs → ciphertexts differ.
	// More importantly, GCM nonces are randomly generated per call, so even
	// without AAD differences the ciphertexts would differ. But the AAD
	// binding is what matters for the cross-row replay defense above.
	if string(l1.LicenseKeyEncrypted) == string(l2.LicenseKeyEncrypted) {
		t.Error("identical plaintexts under different IDs must produce different ciphertexts")
	}
}
