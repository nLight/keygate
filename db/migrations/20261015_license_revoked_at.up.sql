-- A revoked license showed no date: revocation reused no timestamp, and
-- canceled_at means something else (the subscription ended), so an admin
-- could not tell when access was pulled or line it up against the
-- provider's timeline.
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
