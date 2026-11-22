-- Who suspended a licence: 'admin' (an operator's decision, which only an
-- operator lifts) or 'stripe' (the subscription was paused, which Stripe
-- lifts by resuming it). Stripe events never make a licence an admin
-- suspended usable again. NULL when not suspended.
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS suspended_by TEXT;

-- Licences suspended before this column existed: the newest "suspended"
-- audit line says who did it. Anything not plainly Stripe's counts as an
-- operator's — the safe reading, since that one an event cannot undo.
UPDATE licenses l
SET suspended_by = CASE
    WHEN (SELECT a.actor_type FROM audit_logs a
          WHERE a.entity = 'license' AND a.entity_id = l.id AND a.action = 'suspended'
          ORDER BY a.created_at DESC LIMIT 1) = 'webhook' THEN 'stripe'
    ELSE 'admin' END
WHERE l.status = 'suspended' AND l.suspended_by IS NULL;
