-- Drop every constraint FinalizeLicenseKeyStorage adds at startup. Leaving
-- licenses_key_plaintext_absent in place would block the rolled-back binary
-- from writing the plaintext column it expects to own.
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_key_ciphertext_present;
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_key_hash_present;
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_key_plaintext_absent;
-- Plaintext values are deliberately unrecoverable. A rollback must reissue
-- keys rather than attempting to reconstruct the removed column contents.
-- license_key therefore stays nullable and non-unique; restoring NOT NULL
-- would fail against the rows this migration emptied.
