# Production deployment baseline

Keygate must run behind a maintained TLS reverse proxy. Bind the application
listener to loopback or a private service network, keep PostgreSQL and Redis off
the public network, and configure the proxy with body/header limits no looser
than `MAX_REQUEST_BODY_KB`, `STRIPE_WEBHOOK_MAX_KB`, and
`HTTP_MAX_HEADER_KB`.

## Required secrets

Generate independent secrets for every environment and store them in a secrets
manager rather than an image, Compose file, or Git repository:

- `JWT_SECRET` — at least 32 random bytes.
- `LICENSE_SIGNING_KEY` — an Ed25519 seed (`openssl rand -hex 32`).
- `RELEASE_KEY_ENCRYPTION_KEY` — 32-byte hex master key. Startup fails without
  it because license-key storage is ciphertext-only.
- `OTP_PEPPER` — at least 32 random bytes, distinct from all other secrets.
- `METRICS_TOKEN` — at least 32 random bytes for `/metrics` and `/ready`.
- database, Redis, SMTP, storage, and Stripe credentials.

To rotate `RELEASE_KEY_ENCRYPTION_KEY`, deploy the new value together with the
old value in `RELEASE_KEY_ENCRYPTION_PREVIOUS_KEY`. Startup verifies and
compare-and-swap re-encrypts both license ciphertexts and release-signing seeds;
the procedure is restart-safe. After a successful restart and backup, remove
the previous key and restart once more to verify recovery no longer depends on
it. Losing both keys fails startup/reveal and never falls back to plaintext.

For first-run setup only, set `SETUP_ENABLED=true` and provide a random
`BOOTSTRAP_SECRET` of at least 32 characters out of band. Send it in the
`bootstrap_secret` field of `POST /api/v1/setup/initialize`. After the request
succeeds, set `SETUP_ENABLED=false`, remove `BOOTSTRAP_SECRET`, and restart.
Wrong or concurrent requests cannot consume the real secret; owner creation and
the consumed marker commit in one transaction. Do not expose setup routes
outside a private administration network.

OTP login is closed to unknown users by default in production. Keep
`OTP_OPEN_REGISTRATION=false`; existing users, license owners, invited seats,
and domains in `OTP_ALLOWED_DOMAINS` remain eligible. Production startup fails
when OTP is enabled without SMTP delivery.

## Offline token and key rotation policy

`OFFLINE_TOKEN_TTL` defaults to 24 hours. A dated license token expires at the
earlier of that TTL and `valid_until + OFFLINE_GRACE_PERIOD`; the grace default
is zero. Perpetual licenses receive only the configured TTL and must refresh
periodically. This TTL plus any configured grace is the maximum revocation
delay for a client that is offline when a license is revoked.

Set `LICENSE_SIGNING_KEY_ID` explicitly for managed rotations. Before switching
the current key, publish the old public key with
`LICENSE_PREVIOUS_PUBLIC_KEY`, `LICENSE_PREVIOUS_KEY_ID`, and
`LICENSE_PREVIOUS_KEY_VALID_UNTIL`. Keep the overlap longer than the maximum
outstanding offline-token lifetime, verify `/api/v1/license/keys`, rotate the
current seed, and remove the previous key only after the overlap expires.

## Operations

- `/health` is minimal public liveness. Authenticate to `/ready` and `/metrics`
  with `Authorization: Bearer $METRICS_TOKEN`.
- A configured `REDIS_URL` is checked at startup. Runtime Redis failures fail
  rate limits closed; alert on `keygate_rate_limit_backend_errors_total`,
  `keygate_rate_limit_rejections_total`, and HTTP 429s, then restore Redis
  rather than bypassing protection.
- Encrypt PostgreSQL volumes and backups, enable point-in-time recovery, and
  perform scheduled restore tests. Record RPO/RTO and rollback owners.
- Use read-only root filesystems, a writable `noexec,nosuid` `/tmp`, dropped
  Linux capabilities, and the non-root UID embedded in the image.
- Centralize redacted logs. Alert on OTP failures, rate limiting, license export,
  activation churn, webhook retry exhaustion, signing failures, and database
  readiness failures.
- Exercise database restore, signing-key overlap, revocation, Redis/SMTP/Stripe
  outage, and rollback procedures in staging before rollout.

Client-reported `/license/usage` updates quota information but cannot enqueue
Stripe billing events. Billable usage must use the scoped, authenticated
`POST /api/v1/admin/usage` endpoint with an `Idempotency-Key`.

The prescribed **Powered by Keygate** UI, email, config-response, and
`X-Powered-By` attribution is mandatory under the project's AGPL Section 7(b)
terms. Network deployment of a modified build also requires the corresponding
source-availability process described by the AGPL and `NOTICE`.
