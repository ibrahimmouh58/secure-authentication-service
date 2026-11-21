# Secure Authentication Service

Authentication API built with Node 20+, Express 5, TypeScript, Prisma 7 and PostgreSQL 16.
Backend only. The API listens on **port 7766**.

Design decisions, threat model and trade-offs are in [NOTES.md](NOTES.md).

---

## Prerequisites

- Node.js 20 or later
- Docker with Docker Compose v2 (Docker Desktop on Windows/macOS)
- Ports **7766** (API) and **5433** (PostgreSQL) free on your machine
- Outbound HTTPS to `api.pwnedpasswords.com` (breached-password check; the API still works without it, see NOTES.md)

---

## Run it

### 1. Clone and install

```bash
git clone https://github.com/ibrahimmouh58/secure-authentication-service.git
cd secure-authentication-service
npm ci
```

### 2. Create the `.env` file

macOS / Linux:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Open `.env` and **replace its entire content** with these local development values:

```
PORT=7766
NODE_ENV=development
LOG_LEVEL=info

POSTGRES_USER=auth
POSTGRES_PASSWORD=localdevpassword
POSTGRES_DB=auth
POSTGRES_PORT=5433
DATABASE_URL=postgresql://auth:localdevpassword@localhost:5433/auth?schema=public

CORS_ORIGINS=http://localhost:3000
TRUST_PROXY_HOPS=0

JWT_ISSUER=secure-auth-service
JWT_AUDIENCE=secure-auth-api

ACCESS_TOKEN_TTL_SECONDS=900
REFRESH_TOKEN_TTL_SECONDS=1209600
SESSION_MAX_AGE_SECONDS=2592000
RESET_TOKEN_TTL_SECONDS=900
```

The database credentials are for a local, throwaway database only.

### 3. Generate the signing keys and the MFA encryption key

```bash
npm run secrets:generate
```

This prints three lines: `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEYS` and `MFA_ENCRYPTION_KEY`.
**Append them to the end of `.env`.** Each variable must appear only once in the file.
These are real secrets: never commit or share them.

The API refuses to start if any variable is missing or malformed, and prints only the variable names.

### 4. Start PostgreSQL

```bash
docker compose up -d
```

Wait until `docker compose ps` shows the `db` service as `(healthy)`.

### 5. Build and start

```bash
npm run build
npm start
```

`npm start` applies all pending database migrations (`prisma migrate deploy`) and only then starts the API.

### 6. Check it works

```bash
curl http://localhost:7766/health
```

On Windows PowerShell, use `curl.exe` instead of `curl`.

Expected response:

```json
{"success":true,"data":{"status":"ok"}}
```

---

## Connecting to the database

```
DATABASE_URL=postgresql://auth:localdevpassword@localhost:5433/auth?schema=public
```

| Setting  | Value              |
| -------- | ------------------ |
| Host     | `localhost`        |
| Port     | `5433`             |
| User     | `auth`             |
| Password | `localdevpassword` |
| Database | `auth`             |

Or open a SQL shell directly in the container:

```bash
docker compose exec db psql -U auth -d auth
```

The `User` table follows the shared model from the assignment. All other tables (`Session`,
`RefreshToken`, `PasswordResetToken`, `MfaSecret`, `MfaChallenge`, `RecoveryCode`, `AuditLog`,
`RateLimit`) are described in NOTES.md.

---

## API

Every response uses the envelope `{ "success": true, "data": { ... } }` or
`{ "success": false, "error": { "code": "...", "message": "..." } }`.

The access token is returned as `data.accessToken` and sent back as `Authorization: Bearer <token>`.
The refresh token is returned as `data.refreshToken` and sent back **in the JSON body** of
`/api/v1/auth/refresh` (`{ "refreshToken": "..." }`).

| Method | Path                           | Auth             | Notes |
| ------ | ------------------------------ | ---------------- | ----- |
| GET    | `/health`                      | public           | 200 |
| POST   | `/api/v1/auth/register`        | public           | `{ email, password, role? }` → 201. `role: "ADMIN"` → 403 |
| POST   | `/api/v1/auth/login`           | public           | `{ email, password }` → 200 with tokens, or `{ mfaRequired: true, mfaToken }` |
| POST   | `/api/v1/auth/refresh`         | public           | `{ refreshToken }` → 200, rotates the refresh token |
| POST   | `/api/v1/auth/logout`          | Bearer           | Revokes the current session → 200 |
| POST   | `/api/v1/auth/logout-all`      | Bearer           | Revokes every session of the user → 200 |
| GET    | `/api/v1/auth/me`              | Bearer           | `{ id, email, role }` |
| POST   | `/api/v1/auth/password/forgot` | public           | `{ email }` → always the same 200 |
| POST   | `/api/v1/auth/password/reset`  | public           | `{ token, newPassword }` → 200 |
| POST   | `/api/v1/auth/password/change` | Bearer           | `{ currentPassword, newPassword }` → 200 with new tokens |
| POST   | `/api/v1/auth/mfa/enroll`      | Bearer           | Returns the TOTP secret, `otpauth://` URL and 10 recovery codes (shown once) |
| POST   | `/api/v1/auth/mfa/verify`      | see notes        | With Bearer + `{ code }`: confirms enrolment. Without Bearer + `{ mfaToken, code }` or `{ mfaToken, recoveryCode }`: completes an MFA login |
| GET    | `/api/v1/users`                | Bearer, ADMIN    | Paginated list (`?limit=1..100&offset=0`). 403 for a USER |
| GET    | `/api/v1/users/:id`            | Bearer           | Own profile, or any profile for an ADMIN (object-level check) |

Every route not listed as public requires a valid access token (deny by default), including unknown routes.

### Password reset emails in development

There is no mail server. Outside production, each email is written as a text file to
`mail-outbox/` (git-ignored). The reset token is inside. In production, no email is written to disk.

---

## Creating an admin

Public registration never creates admins. An operator with access to the server creates or promotes one:

```bash
npm run admin:create -- admin@example.com
```

- If the user already exists, it is promoted to `ADMIN`.
- Otherwise an admin account is created and a temporary password is printed once.

Roles are read from the database on every request, so a promotion or demotion takes effect immediately.

---

## Running the tests

With PostgreSQL running (`docker compose up -d`) and `.env` filled in:

```bash
npm test
```

The tests run against a separate database, `auth_test`, on the same PostgreSQL server.
It is created automatically on the first run, and all migrations are applied to it before the tests start.
The development database (`auth`) is never touched. The breached-password tests need network access to HIBP.

---

## Key rotation

### JWT signing key (no one is logged out)

Access tokens carry a `kid` header. The API signs with one key (`JWT_PRIVATE_KEY`) and verifies
against every key in `JWT_PUBLIC_KEYS`. Refresh tokens are opaque and do not depend on the signing key.

1. Generate a new key pair: `npm run secrets:generate`. Keep only the two `JWT_*` lines it prints.
2. **Add** the new public key to the existing `JWT_PUBLIC_KEYS` array (keep the old one):
   `JWT_PUBLIC_KEYS='[{...old...},{...new...}]'`. Deploy or restart.
   Every instance can now verify tokens signed with either key.
3. Replace `JWT_PRIVATE_KEY` with the new private key. Deploy or restart.
   New access tokens are signed with the new key; existing ones are still accepted.
4. After `ACCESS_TOKEN_TTL_SECONDS` (15 minutes), every token signed with the old key has expired.
   Remove the old public key from `JWT_PUBLIC_KEYS`. Deploy or restart.

The API refuses to start if the active private key's public half is not in `JWT_PUBLIC_KEYS`.

**If a signing key is compromised**, do steps 1 to 3 and remove the old public key immediately.
All access tokens signed with it become invalid at once; clients call `/auth/refresh` with their
still-valid refresh token and get a token signed with the new key. Nobody has to log in again.

### MFA encryption key

TOTP secrets are encrypted with AES-256-GCM under `MFA_ENCRYPTION_KEY`. Ciphertexts are versioned
(`v1:...`), but there is no automated re-encryption job yet: rotating this key today means
re-encrypting every row of `MfaSecret`. See NOTES.md ("What I skipped").

### Database password

Change `POSTGRES_PASSWORD` and `DATABASE_URL` together. For an existing volume, also change the
password inside PostgreSQL (`ALTER USER auth PASSWORD '...'`), since the image only applies
`POSTGRES_PASSWORD` when the volume is first created.

---

## Resetting the database

```bash
docker compose down -v
docker compose up -d
npm start
```

`down -v` deletes the database volume. `npm start` then re-applies every migration to the empty database.

---

## Project layout

```
prisma/
  schema.prisma          Database schema
  migrations/            Committed SQL migrations
scripts/
  generate-secrets.ts    Ed25519 signing key + MFA encryption key
  create-admin.ts        Operator-only admin bootstrap
src/
  app.ts                 Express app: middleware order, routers
  server.ts              Starts the HTTP server on PORT
  lib/                   env, jwt, password, crypto, totp, encryption, rate limiting, logger
  middleware/            deny-by-default, auth, roles, request context, request logger, errors
  routes/                /api/v1/auth and /api/v1/users
  schemas/               zod request schemas
  services/              sessions, auth, password, MFA, audit
tests/                   vitest + supertest suite (separate auth_test database)
```