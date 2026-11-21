# NOTES

## Hours spent

**TODO: write your honest number here (e.g. "about 14 hours, over two days").**

---

## Threat model

The attacker is a remote, unauthenticated user on the internet. They may hold lists of leaked
email/password pairs, control many IP addresses, and occasionally obtain a user's access or refresh
token (malware on a client, a leaked log, a shoulder-surfed TOTP code), or a read-only copy of the
database. I defend against account takeover (credential stuffing, guessing, token theft and replay),
privilege escalation and cross-user access (self-registration as ADMIN, BOLA), account enumeration,
and offline use of a stolen database dump. I do not defend against an attacker who already controls
the server or its environment (they hold the signing key) or a fully compromised user device.

---

## Decision table

| Area | Chosen | Rejected | Why |
| --- | --- | --- | --- |
| **Password hashing** | argon2id, m=19 MiB, t=2, p=1 (OWASP minimum) | bcrypt cost ≥ 12; scrypt | Memory-hard, so far more expensive on GPUs than bcrypt; no 72-byte truncation. Verification is constant-time inside the library. |
| **Access token format** | JWT signed with **EdDSA (Ed25519)**, 15 min, `kid` + `typ: at+jwt`, claims `iss aud exp iat sub jti` + `sid` | HS256 (symmetric: every verifier could mint tokens); RS256 (large, slow keys); opaque access tokens | Asymmetric as required, small fast keys, deterministic signatures (no nonce pitfalls). `kid` enables rotation; `typ` prevents token confusion. Verification pins `algorithms: ["EdDSA"]` and requires all six claims. |
| **Refresh token storage** | Opaque 256-bit random token, **SHA-256 hash** stored in `RefreshToken`, single-use, rotated on every refresh, grouped by `Session` (= token family) | JWT refresh tokens (not revocable); argon2 hashing (salted, so no indexed lookup) | 256 bits of entropy make a fast hash safe and allow a unique-index lookup. A DB dump yields no usable token. |
| **Refresh token transport** | JSON body (`data.refreshToken`, sent back in the body) | `HttpOnly` cookie | API-only service with no specified browser client: no ambient credentials, so no CSRF surface, and it works for mobile/CLI/server clients. Trade-off: the client must store it safely (a browser SPA should not use localStorage). |
| **Revocation strategy** | Server-side sessions: the access token carries `sid`; every authenticated request checks the session is not revoked/expired and re-reads the user's role. Reuse of a rotated refresh token revokes the whole session (family) | Pure stateless JWTs (wait up to 15 min); a JWT deny-list keyed by `jti` | Logout, logout-all, password change and replay detection take effect immediately, and role changes apply on the next request. Cost: one indexed DB read per authenticated request. |
| **Rate limit store** | PostgreSQL table `RateLimit`, fixed window, one atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` per check | In-memory (lost on restart, per-instance); Redis (extra infrastructure for the grader) | Shared across instances, survives restarts, no new infrastructure. Cost: one DB write per throttled-route request; Redis would be the move at scale. |
| Breached-password check | HIBP Pwned Passwords range API (k-anonymity, padding, 3 s timeout), **fail open** | Fail closed; a local corpus | An outage of a third-party service must not block every registration and reset. Gap documented below. |
| TOTP | RFC 6238 implemented on `node:crypto` HMAC-SHA1, ±1 step, verified against the RFC test vectors in the test suite | `otplib` | ~15 lines, fully specified by the RFC, and I need the matched time step for replay protection. |
| MFA secret at rest | AES-256-GCM, random 96-bit IV, **user id as AAD**, versioned `v1:` format | Hashing (impossible: the server must recompute codes); plaintext | GCM detects tampering; the AAD stops a DB attacker from moving a secret to another account. |
| Recovery codes | 16 chars (80 bits) from a 32-char unambiguous alphabet, SHA-256 hashed, single-use | 8-char codes with argon2 | 80 bits makes a fast hash safe and allows a single atomic `updateMany` to verify-and-consume. |
| ORM version | Prisma 7 (stable) | Prisma 8 release candidate (what `npm install prisma` gave) | An RC can still ship breaking changes; the fixed `User` model is written in Prisma 7 syntax. |

---

## What I built

Every control from the Scope section, and which bucket it is in:

| Scope control | Bucket | Where / how |
| --- | --- | --- |
| argon2id hashing | **Built** | `src/lib/password.ts` |
| Length policy (min 12) + breached corpus | **Built** (HIBP, fail-open) | `passwordSchema`, `isPasswordBreached` |
| Constant-time comparison of secrets | **Built** | `argon2.verify`, `safeEqual` (SHA-256 both sides then `timingSafeEqual`), TOTP compares all 3 steps without early exit; tokens are looked up by hash |
| Short-lived asymmetric access token | **Built** | EdDSA, 15 min, `src/lib/jwt.ts` |
| Opaque, hashed, single-use, rotated refresh tokens | **Built** | `src/services/session.service.ts` |
| Replay revokes the entire family | **Built** | Including concurrent replays (atomic conditional `updateMany`) |
| Claims set and validated (`iss aud exp iat sub jti`) | **Built** | `requiredClaims`, plus `typ` and `kid` checks |
| Signing-key rotation without logging everyone out | **Built** | `kid` + list of public keys; procedure in README |
| Cookies: `HttpOnly; Secure; SameSite`, scoped path | **Skipped deliberately** (not applicable) | No cookies are used (body transport, see decision table) |
| Access token never in localStorage | **Built** (server side) / client responsibility | The API never sets or suggests browser storage; tokens are only returned in JSON with `Cache-Control: no-store` |
| CSRF defence on cookie-authenticated routes | **Skipped deliberately** (not applicable) | No cookie authentication, so no ambient credentials to forge |
| Security headers; CORS allow-list, never `*` | **Built** | helmet with an API-strict CSP (`default-src 'none'`), `X-Frame-Options: DENY`, `no-store`, no `X-Powered-By`; CORS from `CORS_ORIGINS` |
| Rate limiting per IP **and** per account on login, refresh, register, reset | **Built** | Also on forgot, change and MFA verify; 429 + `Retry-After`; account keys are SHA-256 of the email/user id |
| Lockout with backoff + why it is not a DoS vector | **Built** | See below |
| No enumeration on login | **Built** | Same status, body and argon2 cost (dummy hash) for unknown email, wrong password and locked account |
| No enumeration on reset | **Built** | `/forgot` answers before looking up the user; work happens in the background |
| No enumeration on register | **Partially built, deliberate trade-off** | The spec fixes **409** for a duplicate email, which is inherently an oracle. Mitigated: HIBP + argon2 run before the duplicate is known (uniform timing), neutral message, per-IP and per-account rate limits |
| Reset tokens: single-use, hashed, short TTL, invalidated on use and on any password change | **Built** | 15 min, SHA-256, atomic claim; a new request or any password change invalidates outstanding tokens; a rejected new password does not burn the token |
| Password change revokes every session | **Built** | Reset **and** change revoke all sessions (including the caller's) in the same transaction; change then opens one fresh session for the caller |
| TOTP (RFC 6238) with replay protection | **Built** | `lastUsedStep`, accepted only if strictly newer, atomically |
| Recovery codes hashed and single-use | **Built** | 10 codes, shown once |
| Secrets from the environment + documented rotation path | **Built** for JWT keys; **partially** for the MFA key | Validated at startup with zod; JWT rotation in README; MFA key rotation not automated (below) |
| Structured audit log recording the decision | **Built** | `AuditLog` table + structured log line; `event`, `outcome`, `reason`, user, IP, user agent, request id |
| No secrets, tokens or password material in logs or error bodies | **Built** | Bodies, headers and query strings are never logged; pino redaction as a second net; 500s return a generic message; stack traces are logged without their first line (Prisma messages can echo data) |
| Deny by default, enforced server-side on every route | **Built** | Global guard with an explicit public allow-list; unknown routes return 401 without a token; routers also apply `requireAuth` as defence in depth |
| Object-level checks, not only role checks | **Built** | `GET /users/:id` (owner or admin, checked before reading the DB, 403 even for non-existent ids); logout/logout-all/change act only on the token's session/user; recovery codes filtered by user; MFA ciphertext bound to the user id |

**Lockout, and why it is not a DoS vector.** Per account, starting after 5 consecutive failures,
backing off 1, 2, 4, 8 minutes up to a 15-minute cap. It is not a DoS vector because: (1) it is always
temporary, with no admin unlock needed; (2) attempts made while locked are neither counted nor extend
the lock, so an attacker can at most re-lock an account once every 15 minutes; (3) the per-account rate
limit (10 per 15 min) caps how fast failures can be generated; (4) password reset stays available during
a lock and clears it. The residual cost is that a targeted user may wait up to 15 minutes or reset their
password. Locking per (account, IP) would remove that cost but give a distributed attacker many more
guesses, so I prioritised password safety.

**Other things built:** operator-only admin bootstrap script; structured pino logs with a
server-generated `X-Request-Id`; account lockout cleared by reset; MFA login challenge (5-minute,
single-use, 5 attempts max); separate `auth_test` database created automatically for the tests.

**Tests (57, in 8 files).** Each file opens with why those behaviours are pinned. Chosen for blast
radius, not coverage: token forgery (`alg: none`, HS256, tampering, audience, expiry, missing `exp`,
unknown `kid`, wrong `typ`), refresh reuse including concurrency, privilege escalation, enumeration
(status + body), lockout as DoS, reset token reuse, TOTP replay, recovery code reuse, BOLA, demotion
taking effect immediately, error/header/CORS hygiene. Deliberately not tested: response-time uniformity
(flaky under load; checked manually), purely functional paths.

---

## What I skipped deliberately, and what it would cost

- **No cookie transport / CSRF defence.** Not applicable with body transport. Switching for a
  first-party web client: `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` cookie, read it in
  `/refresh` and `/logout`, clear it on logout, CORS `credentials: true`, and an Origin check or
  double-submit CSRF token on cookie-authenticated routes. ~3–4h.
- **No email verification at registration.** Anyone can register an address they do not own. Needs an
  `emailVerifiedAt` column, a hashed single-use verification token (same pattern as reset), and a
  verify route. ~3h.
- **Register is not enumeration-proof (spec-fixed 409).** The clean alternative is to always return 201
  and email the address ("someone tried to register / welcome"). Needs a real mail pipeline. ~4h.
- **No offline breached-password corpus.** When HIBP is unreachable the check fails open. A local bloom
  filter of the top N breached passwords, checked first, would close the gap. ~3h.
- **No grace window for concurrent refreshes.** Two simultaneous refreshes with the same token revoke the
  session (safe, but logs out a client with two tabs). A 10-second grace window returning the same
  successor would need a `replacedById` column and an idempotent lookup. ~2h.
- **MFA encryption key rotation is not automated.** Ciphertexts are versioned (`v1:`), but there is no
  keyring or re-encryption job. Needs `MFA_ENCRYPTION_KEYS` with ids, `v2:<keyId>:...` format, decrypt
  with any key / encrypt with the active one, and a script that re-encrypts all rows. ~3h.
- **No step-up authentication for `/mfa/enroll` and no MFA disable / recovery-code regeneration.** A
  stolen access token can start an enrolment (but cannot replace an already-enabled MFA: 409). Requiring
  the current password on enrol/confirm and adding disable/regenerate routes (password + valid code). ~3h.
- **Enabling MFA does not revoke other sessions.** Sessions opened before enrolment stay valid. One
  `revokeAllSessions` call except the current one on confirmation. ~30 min.
- **Rate limits per IPv6 address, not per /64.** Needs IPv6 prefix normalisation in the IP key. ~1h.
- **No cleanup of expired rows** (`RateLimit`, used/expired tokens, challenges) and **no audit retention
  policy.** A scheduled `DELETE ... WHERE expiresAt < now()`. ~1h.
- **Audit log is not tamper-evident.** A DB admin can delete rows. Options: an `INSERT`-only DB role for
  the app on `AuditLog`, or hash-chaining rows. ~3h.
- **Audit under flood.** Every 429 writes an audit row; a large attack fills the table. Aggregate
  identical events per window instead. ~2h.
- **Injectable clock for tests.** MFA tests can fail if a 30-second TOTP boundary falls mid-test. ~1h.

---

## Where I would attack my own implementation

1. **`/mfa/enroll` with a stolen access token, before the victim enables MFA.** The attacker enrols
   their own authenticator and confirms it; the victim's next login then requires the attacker's code.
   Biggest real gap. Fix: require the current password on enrol/confirm (above).
2. **The register 409.** Still an existence oracle, only slowed down by rate limits (5 per account and
   30 per IP per 15 min; more with many IPs).
3. **Timing residue on login.** A wrong password on an existing account performs one extra DB write (the
   failure counter) compared to an unknown email. Milliseconds, inside argon2's jitter, but measurable
   with many samples. Fix: an equivalent dummy write for unknown emails.
4. **Fail-open HIBP.** If outbound traffic to HIBP is blocked, breached passwords of 12+ characters are
   accepted.
5. **IP limits with IPv6.** One host with a /64 can rotate addresses; the per-account limits still hold.
6. **Lockout nuisance.** An attacker who knows a user's email can keep them waiting up to 15 minutes
   between attempts (bounded, but real).
7. **Resource exhaustion via the tables.** Unique emails and IPs create `RateLimit` rows; floods create
   audit rows. No cleanup job yet.
8. **Strict refresh reuse detection.** A flaky client that retries a refresh logs its user out (safe
   failure, but an availability cost).
9. **Single `.env` holds every secret.** Whoever reads it can sign tokens and decrypt every TOTP secret.
   In production these belong in a secrets manager.
10. **Development mail outbox.** Reset tokens are written to `mail-outbox/` in plain text outside
    production. Disabled when `NODE_ENV=production`, but a misconfigured environment variable would
    re-enable it.
11. **`trust proxy` misconfiguration.** Behind a proxy with `TRUST_PROXY_HOPS=0`, every client shares the
    proxy's IP (IP limits become global); with too high a value, `X-Forwarded-For` becomes spoofable.

What I attacked and is covered by tests: forged tokens (`alg: none`, HS256 confusion, tampered payload,
wrong audience/typ/kid, expired, no `exp`), replayed and concurrently replayed refresh tokens, ADMIN
self-registration, enumeration by status/body on login, register throttling and forgot, lockout
extension, `X-Forwarded-For` spoofing, reset token reuse, TOTP replay across challenges, recovery code
reuse, MFA challenge brute force, BOLA on `/users/:id`, stale roles after demotion, stack traces and
internals in error bodies.

---

## The honest bucket

**TODO: review and edit this section so it is genuinely yours.**

- **Not sure about:** the 409-versus-enumeration trade-off on register (I followed the fixed status code);
  using 400 rather than 401 for an invalid reset token; returning 401 (not a "locked" message) during a
  lockout, which is safe but confusing for a legitimate user.
- **Not sure about:** whether the extra `GET /api/v1/users/:id` route is welcome; I added it to
  demonstrate object-level authorisation.
- **Not verified under load:** the cost of one session read per authenticated request, and the DB write
  per rate-limited request.
- **Known test flakiness:** TOTP 30-second boundary in the MFA tests; the breached-password tests need
  network access.
- **Not done:** a real mail transport, HTTPS termination (HSTS is sent, TLS is expected from a reverse
  proxy), deployment configuration.