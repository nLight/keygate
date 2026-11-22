package apperr

import (
	"errors"
	"testing"
)

func TestAppErrorFormattingAndUnwrap(t *testing.T) {
	base := errors.New("database connection refused")
	err := Wrap(500, "DB_ERROR", "failed to connect", base)

	expectedMsg := "DB_ERROR: failed to connect: database connection refused"
	if err.Error() != expectedMsg {
		t.Errorf("Error() = %q, want %q", err.Error(), expectedMsg)
	}
	if !errors.Is(err, base) {
		t.Errorf("errors.Is failed to unwrap cause: %v", err.Unwrap())
	}

	errNoCause := New(400, "BAD_INPUT", "invalid payload")
	if errNoCause.Error() != "BAD_INPUT: invalid payload" {
		t.Errorf("Error() = %q, want %q", errNoCause.Error(), "BAD_INPUT: invalid payload")
	}
	if errNoCause.Unwrap() != nil {
		t.Errorf("expected nil cause, got %v", errNoCause.Unwrap())
	}
}

func TestWithDetails(t *testing.T) {
	err := New(400, "INVALID_FIELDS", "validation failed")
	details := map[string]string{"email": "required"}
	errWith := WithDetails(err, details)

	if errWith != err {
		t.Fatalf("WithDetails returned a new error; it sets the details on the one given")
	}
	if got, ok := errWith.Details.(map[string]string); !ok || got["email"] != "required" {
		t.Fatalf("Details = %#v, want the map passed in", errWith.Details)
	}
}

func TestPredefinedErrors(t *testing.T) {
	nf := NotFound("LICENSE", "key-123")
	if nf.Status != 404 || nf.Code != "LICENSE_NOT_FOUND" || nf.Message != "LICENSE 'key-123' not found" {
		t.Errorf("unexpected NotFound error: %+v", nf)
	}

	br := BadRequest("missing param")
	if br.Status != 400 || br.Code != "BAD_REQUEST" {
		t.Errorf("unexpected BadRequest error: %+v", br)
	}

	unauth := Unauthorized("invalid token")
	if unauth.Status != 401 || unauth.Code != "UNAUTHORIZED" {
		t.Errorf("unexpected Unauthorized error: %+v", unauth)
	}

	forb := Forbidden("not allowed")
	if forb.Status != 403 || forb.Code != "FORBIDDEN" {
		t.Errorf("unexpected Forbidden error: %+v", forb)
	}

	conf := Conflict("SEATS_EXCEEDED", "max seats reached")
	if conf.Status != 409 || conf.Code != "SEATS_EXCEEDED" {
		t.Errorf("unexpected Conflict error: %+v", conf)
	}

	cause := errors.New("disk full")
	internal := Internal(cause)
	// The cause is kept for logs but never put in the message a client sees.
	if internal.Status != 500 || internal.Code != "INTERNAL_ERROR" || !errors.Is(internal, cause) || internal.Message != "an internal error occurred" {
		t.Errorf("unexpected Internal error: %+v", internal)
	}
}
