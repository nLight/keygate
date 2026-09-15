package payment

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stripe/stripe-go/v82"
)

// Fixtures in testdata/ are basil-shaped (2025-03-31.basil and later)
// Invoice and Subscription objects: no top-level invoice `subscription`
// or subscription `current_period_end`.
const (
	renewalSubID     = "sub_Basil123"
	renewalPeriodEnd = int64(1769904000) // 2026-02-01, end of the paid cycle
	invoicePeriodEnd = int64(1767225600) // 2026-01-01, invoice's own period_end
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWebhookInvoiceDecodesBasilShape(t *testing.T) {
	raw := readFixture(t, "invoice_paid_renewal.json")

	var inv webhookInvoice
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if got := inv.subscriptionID(); got != renewalSubID {
		t.Fatalf("subscriptionID = %q, want %q", got, renewalSubID)
	}

	// Cross-check against the SDK's own basil struct so the fixture and
	// the handler paths can't drift from what stripe-go considers valid.
	var sdk stripe.Invoice
	if err := json.Unmarshal(raw, &sdk); err != nil {
		t.Fatal(err)
	}
	if sdk.Parent == nil || sdk.Parent.SubscriptionDetails == nil ||
		sdk.Parent.SubscriptionDetails.Subscription == nil ||
		sdk.Parent.SubscriptionDetails.Subscription.ID != renewalSubID {
		t.Fatalf("stripe-go does not see the subscription at parent.subscription_details: %+v", sdk.Parent)
	}
	if len(sdk.Lines.Data) != 1 || sdk.Lines.Data[0].Period.End != renewalPeriodEnd {
		t.Fatalf("stripe-go line period mismatch: %+v", sdk.Lines.Data)
	}
	if sdk.PeriodEnd != invoicePeriodEnd {
		t.Fatalf("stripe-go invoice period_end = %d, want %d", sdk.PeriodEnd, invoicePeriodEnd)
	}
}

func TestWebhookInvoiceWithoutSubscriptionParent(t *testing.T) {
	var inv webhookInvoice
	raw := `{"object":"invoice","parent":null,"period_end":1767225600,
		"lines":{"data":[{"period":{"end":1769904000},"parent":{"type":"invoice_item_details",
		"invoice_item_details":{"invoice_item":"ii_1"},"subscription_item_details":null}}]}}`
	if err := json.Unmarshal([]byte(raw), &inv); err != nil {
		t.Fatal(err)
	}
	if got := inv.subscriptionID(); got != "" {
		t.Fatalf("subscriptionID = %q, want empty for a one-off invoice", got)
	}

	// A pre-basil payload must not be silently accepted either.
	inv = webhookInvoice{}
	if err := json.Unmarshal([]byte(`{"subscription":"sub_legacy","period_end":1767225600}`), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.subscriptionID() != "" {
		t.Fatalf("legacy top-level fields must be ignored: %+v", inv)
	}
}

func TestWebhookSubscriptionDecodesBasilShape(t *testing.T) {
	raw := readFixture(t, "subscription_updated.json")

	var sub webhookSubscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		t.Fatal(err)
	}
	if sub.ID != renewalSubID || sub.Status != "active" {
		t.Fatalf("decoded = (%q, %q)", sub.ID, sub.Status)
	}
	if got := sub.currentPeriodEnd(); got != renewalPeriodEnd {
		t.Fatalf("currentPeriodEnd = %d, want %d", got, renewalPeriodEnd)
	}
	if sub.Items.HasMore {
		t.Fatal("fixture items list should be complete")
	}

	var sdk stripe.Subscription
	if err := json.Unmarshal(raw, &sdk); err != nil {
		t.Fatal(err)
	}
	if sdk.Items == nil || len(sdk.Items.Data) != 1 || sdk.Items.Data[0].CurrentPeriodEnd != renewalPeriodEnd {
		t.Fatalf("stripe-go item period mismatch: %+v", sdk.Items)
	}

	// Multiple items on different cycles: access runs to the latest.
	sub = webhookSubscription{}
	multi := `{"id":"sub_1","status":"active","items":{"data":[{"current_period_end":1769904000},{"current_period_end":1798761600}]}}`
	if err := json.Unmarshal([]byte(multi), &sub); err != nil {
		t.Fatal(err)
	}
	if got := sub.currentPeriodEnd(); got != 1798761600 {
		t.Fatalf("currentPeriodEnd = %d, want 1798761600", got)
	}

	// Legacy top-level field is not read.
	sub = webhookSubscription{}
	if err := json.Unmarshal([]byte(`{"id":"sub_1","current_period_end":1769904000}`), &sub); err != nil {
		t.Fatal(err)
	}
	if got := sub.currentPeriodEnd(); got != 0 {
		t.Fatalf("currentPeriodEnd = %d, want 0 for a legacy payload", got)
	}
}
