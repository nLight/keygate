DROP INDEX IF EXISTS idx_licenses_stripe_payment_intent;
ALTER TABLE licenses DROP COLUMN IF EXISTS stripe_payment_intent_id;
