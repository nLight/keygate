-- One-time (payment mode) purchases have no subscription, and a Stripe
-- customer can hold several licenses, so refunds need the payment intent
-- to find the license they paid for. Unique: one payment buys one license.
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS stripe_payment_intent_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_payment_intent
    ON licenses(stripe_payment_intent_id);
