ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_key_ciphertext_present;
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_key_hash_present;
-- Plaintext values are deliberately unrecoverable. A rollback must reissue
-- keys rather than attempting to reconstruct the removed column contents.
