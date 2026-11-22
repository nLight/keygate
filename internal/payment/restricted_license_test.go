package payment

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tabloy/keygate/internal/model"
)

func setLicenseState(t *testing.T, h *StripeHandler, lic *model.License, status, suspendedBy string) {
	t.Helper()
	future := time.Now().Add(20 * 24 * time.Hour)
	var by any
	if suspendedBy != "" {
		by = suspendedBy
	}
	if _, err := h.Store.DB.NewRaw("UPDATE licenses SET status = ?, valid_until = ?, suspended_by = ? WHERE id = ?",
		status, future, by, lic.ID).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Revoking a licence cancels its Stripe subscription, and Stripe then
// sends customer.subscription.deleted. That event must not turn the
// revoked licence into a canceled one, which stays usable until
// valid_until: the revoke would undo itself.
func TestSubscriptionDeletedDoesNotUndoRevoke(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)
	setLicenseState(t, h, lic, model.StatusRevoked, "")
	deliverEvent(t, h, "customer.subscription.deleted", []byte(fmt.Sprintf(`{"id":%q,"object":"subscription"}`, lic.StripeSubscriptionID)))
	if got := reloadLicense(t, s, lic); got.Status != model.StatusRevoked {
		t.Fatalf("status after subscription.deleted = %s, want revoked", got.Status)
	}
}

// A payment does not lift an operator's suspension, nor revive a
// revoked licence.
func TestInvoicePaidDoesNotLiftAdminSuspensionOrRevoke(t *testing.T) {
	for _, tc := range []struct{ status, by string }{
		{model.StatusSuspended, model.SuspendedByAdmin},
		{model.StatusRevoked, ""},
	} {
		h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)
		setLicenseState(t, h, lic, tc.status, tc.by)
		deliverEvent(t, h, "invoice.paid", fixtureFor(t, "invoice_paid_renewal.json", lic))
		if got := reloadLicense(t, s, lic); got.Status != tc.status {
			t.Errorf("%s licence after invoice.paid = %s", tc.status, got.Status)
		}
	}
}

// A Stripe pause is lifted by the matching resume; an operator's
// suspension is not.
func TestSubscriptionResumedLiftsOnlyStripePause(t *testing.T) {
	h, s, lic, _ := setupBasilWebhookTest(t, model.StatusActive)
	obj := []byte(fmt.Sprintf(`{"id":%q,"object":"subscription"}`, lic.StripeSubscriptionID))

	deliverEvent(t, h, "customer.subscription.paused", obj)
	if got := reloadLicense(t, s, lic); got.Status != model.StatusSuspended || got.SuspendedBy != model.SuspendedByStripe {
		t.Fatalf("after pause: status=%s suspended_by=%q", got.Status, got.SuspendedBy)
	}
	deliverEvent(t, h, "customer.subscription.resumed", obj)
	if got := reloadLicense(t, s, lic); got.Status != model.StatusActive {
		t.Fatalf("after resume: status=%s, want active", got.Status)
	}

	setLicenseState(t, h, lic, model.StatusSuspended, model.SuspendedByAdmin)
	deliverEvent(t, h, "customer.subscription.resumed", obj)
	if got := reloadLicense(t, s, lic); got.Status != model.StatusSuspended {
		t.Fatalf("admin-suspended licence after resume = %s, want suspended", got.Status)
	}
}

// A canceled licence comes back on payment only when a fresh read of
// the subscription says it is live (an "unpaid" subscription, mapped to
// canceled, that was then paid); a payload alone does not revive it.
func TestInvoicePaidRevivesCanceledOnlyWhenSubscriptionIsLive(t *testing.T) {
	for _, tc := range []struct {
		subStatus, want string
	}{
		{"active", model.StatusActive},
		{"canceled", model.StatusCanceled},
	} {
		h, s, lic, fake := setupBasilWebhookTest(t, model.StatusActive)
		fake.subStatus = tc.subStatus
		setLicenseState(t, h, lic, model.StatusCanceled, "")
		deliverEvent(t, h, "invoice.paid", fixtureFor(t, "invoice_paid_renewal.json", lic))
		if got := reloadLicense(t, s, lic); got.Status != tc.want {
			t.Errorf("subscription %s: licence after invoice.paid = %s, want %s", tc.subStatus, got.Status, tc.want)
		}
	}
}
