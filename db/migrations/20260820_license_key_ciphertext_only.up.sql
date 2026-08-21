-- Ciphertext-only license-key storage. Application startup performs the
-- cryptographic backfill and verifies coverage before setting this column to
-- NULL. Keeping the nullable column for one release makes rollback of the
-- schema possible without retaining any usable plaintext values.
ALTER TABLE licenses ALTER COLUMN license_key DROP NOT NULL;
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_license_key_key;
DROP INDEX IF EXISTS idx_licenses_key;

-- The application adds and validates plaintext-absent/hash/ciphertext
-- constraints only after it has completed the cryptographic backfill. Adding
-- them here would make the first of the two backfill updates fail against the
-- still-missing second field.
