package handler

import (
	"strings"
	"testing"
)

// The OTP verifier column stores a keyed digest, not a bare SHA-256. A bare
// hash of a six-digit code is trivially reversible — the whole keyspace is a
// million entries — so anyone who reads the otp_codes table (a backup, a SQL
// injection elsewhere, a compromised replica) could mint a valid login for
// every pending code. The pepper lives outside the database.
func TestHashOTPCodeIsPeppered(t *testing.T) {
	const code = "123456"
	pepperA := strings.Repeat("a", 32)
	pepperB := strings.Repeat("b", 32)

	if hashOTPCode(code, pepperA) == hashOTPCode(code, pepperB) {
		t.Fatal("verifier must depend on the pepper")
	}
	if hashOTPCode(code, pepperA) != hashOTPCode(code, pepperA) {
		t.Fatal("verifier must be deterministic for a given code and pepper")
	}
	if hashOTPCode("654321", pepperA) == hashOTPCode(code, pepperA) {
		t.Fatal("distinct codes must produce distinct verifiers")
	}
}

// A precomputed table over the six-digit keyspace must not match anything the
// server stores. Asserting the unpeppered SHA-256 is absent is the concrete
// form of that claim.
func TestHashOTPCodeIsNotAPlainSHA256(t *testing.T) {
	const code = "000000"
	// sha256("000000")
	const plainSHA = "91b4d142823f7d20c5f08df69122de43f35f057a988d9619f6d3138485c9a203"
	if got := hashOTPCode(code, strings.Repeat("p", 32)); got == plainSHA {
		t.Fatal("verifier is an unkeyed SHA-256 of the code")
	}
}

// HMAC-SHA256 hex is 64 characters; the column and the constant-time compare
// both depend on a fixed width.
func TestHashOTPCodeWidthIsStable(t *testing.T) {
	for _, code := range []string{"", "0", "123456", strings.Repeat("9", 4096)} {
		if got := hashOTPCode(code, strings.Repeat("p", 32)); len(got) != 64 {
			t.Errorf("hashOTPCode(%q) length = %d, want 64", code, len(got))
		}
	}
}

// The dummy verifier the no-rows path compares against must never collide
// with the digest of a real code, or an email with no pending code would
// authenticate by submitting the empty string.
func TestDummyVerifierNeverMatchesARealCode(t *testing.T) {
	pepper := strings.Repeat("p", 32)
	dummy := hashOTPCode("", pepper)
	for _, code := range []string{"000000", "123456", "999999"} {
		if hashOTPCode(code, pepper) == dummy {
			t.Fatalf("code %q collides with the dummy verifier", code)
		}
	}
}

func TestGenerateOTPCodeShape(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < 2000; i++ {
		code := generateOTPCode()
		if len(code) != 6 {
			t.Fatalf("generateOTPCode() = %q, want 6 digits", code)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("generateOTPCode() = %q contains a non-digit", code)
			}
		}
		seen[code]++
	}
	// Not a statistical test — just a smoke check that the generator is not
	// pinned to a constant or to a tiny cycle.
	if len(seen) < 1000 {
		t.Fatalf("only %d distinct codes in 2000 draws — generator lacks entropy", len(seen))
	}
}
