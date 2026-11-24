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

To call every route by hand, see [Request examples](#request-examples) below.

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

## Request examples

The 13 routes of the assignment, in the order of the assignment, plus `GET /api/v1/users/:id`.
Each route has a command for **macOS / Linux** (bash or zsh) and one for **Windows PowerShell**.

Run everything **from the project root, in the same terminal, in this order**: later commands reuse the tokens,
ids and reset token kept in variables by earlier ones. Nothing needs to be copied by hand except the MFA code.
Each run uses a new email address, so the examples can be repeated.

### 0. Helpers (paste once)

A small helper sends the request, prints the HTTP status and the response body, and keeps the response.

macOS / Linux:

```bash
API=http://localhost:7766

# call METHOD PATH [JSON_BODY] [ACCESS_TOKEN]
call() {
  local args=(-s -X "$1" "$API$2" -H "Content-Type: application/json" -w '\n%{http_code}')
  if [ -n "$3" ]; then args+=(-d "$3"); fi
  if [ -n "$4" ]; then args+=(-H "Authorization: Bearer $4"); fi
  local out
  out=$(curl "${args[@]}")
  STATUS=${out##*$'\n'}
  BODY=${out%$'\n'*}
  echo "HTTP $STATUS  $BODY"
}
# field NAME → value of "NAME" in the last response
field() { printf '%s' "$BODY" | sed -nE "s/.*\"$1\":\"([^\"]*)\".*/\1/p"; }

EMAIL="alice-$(date +%s)@example.com"
PASSWORD="walkthrough-$(date +%s)-passphrase"
```

Windows PowerShell:

```powershell
# api METHOD PATH [@{ body }] [ACCESS_TOKEN]
function api {
  param($Method, $Path, $Body, $Token)
  $headers = @{}
  if ($Token) { $headers["Authorization"] = "Bearer $Token" }
  $params = @{ Method = $Method; Uri = "http://localhost:7766$Path"; Headers = $headers; UseBasicParsing = $true }
  if ($Body) { $params.Body = ($Body | ConvertTo-Json -Compress); $params.ContentType = "application/json" }
  try {
    $res = Invoke-WebRequest @params
    Write-Host "HTTP $($res.StatusCode)" -ForegroundColor Green
    return $res.Content | ConvertFrom-Json
  } catch {
    Write-Host "HTTP $([int]$_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    return $_.ErrorDetails.Message | ConvertFrom-Json
  }
}
function show($x) { $x | ConvertTo-Json -Depth 6 }

$email = "alice-$(Get-Random)@example.com"
$password = "walkthrough-" + [guid]::NewGuid()
```

If you get `429 TOO_MANY_REQUESTS`, that is the rate limiter: wait 15 minutes, or run
`docker compose exec db psql -U auth -d auth -c 'DELETE FROM "RateLimit";'`.

---

### GET /health

Unauthenticated → `200`.

```bash
call GET /health
```

```powershell
show (api GET /health)
```

---

### POST /api/v1/auth/register

`{ email, password, role? }` → `201`. Self-registration as `ADMIN` → `403`.

```bash
call POST /api/v1/auth/register "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
call POST /api/v1/auth/register "{\"email\":\"mallory-$(date +%s)@example.com\",\"password\":\"$PASSWORD\",\"role\":\"ADMIN\"}"
```

```powershell
show (api POST /api/v1/auth/register @{ email = $email; password = $password })
show (api POST /api/v1/auth/register @{ email = "mallory-$(Get-Random)@example.com"; password = $password; role = "ADMIN" })
```

---

### POST /api/v1/auth/login

`{ email, password }` → `200` with `accessToken` and `refreshToken`. A wrong password and an unknown email return the same `401`.

```bash
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
ACCESS=$(field accessToken); REFRESH=$(field refreshToken)

call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"wrong-password-123\"}"
call POST /api/v1/auth/login '{"email":"nobody@example.com","password":"wrong-password-123"}'
```

```powershell
$login = api POST /api/v1/auth/login @{ email = $email; password = $password }
show $login
$access = $login.data.accessToken; $refresh = $login.data.refreshToken

show (api POST /api/v1/auth/login @{ email = $email; password = "wrong-password-123" })
show (api POST /api/v1/auth/login @{ email = "nobody@example.com"; password = "wrong-password-123" })
```

---

### POST /api/v1/auth/refresh

`{ refreshToken }` → `200` with a new pair. Replaying the old refresh token → `401`, and the whole session is revoked:
the new refresh token is rejected too.

```bash
call POST /api/v1/auth/refresh "{\"refreshToken\":\"$REFRESH\"}"
NEW_REFRESH=$(field refreshToken)

call POST /api/v1/auth/refresh "{\"refreshToken\":\"$REFRESH\"}"         # 401: replay
call POST /api/v1/auth/refresh "{\"refreshToken\":\"$NEW_REFRESH\"}"     # 401: family revoked

# Log in again for the next steps
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
ACCESS=$(field accessToken)
```

```powershell
$rotated = api POST /api/v1/auth/refresh @{ refreshToken = $refresh }
show $rotated

show (api POST /api/v1/auth/refresh @{ refreshToken = $refresh })                        # 401: replay
show (api POST /api/v1/auth/refresh @{ refreshToken = $rotated.data.refreshToken })      # 401: family revoked

# Log in again for the next steps
$access = (api POST /api/v1/auth/login @{ email = $email; password = $password }).data.accessToken
```

---

### POST /api/v1/auth/logout

Authenticated → `200`. The current session is revoked immediately.

```bash
call POST /api/v1/auth/logout "" "$ACCESS"
call GET /api/v1/auth/me "" "$ACCESS"                                    # 401

call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
ACCESS=$(field accessToken)
```

```powershell
show (api POST /api/v1/auth/logout -Token $access)
show (api GET /api/v1/auth/me -Token $access)                            # 401

$access = (api POST /api/v1/auth/login @{ email = $email; password = $password }).data.accessToken
```

---

### POST /api/v1/auth/logout-all

Authenticated → `200` with `{ revokedSessions }`. Every session of the user is revoked.

```bash
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
OTHER=$(field accessToken)
call POST /api/v1/auth/logout-all "" "$ACCESS"
call GET /api/v1/auth/me "" "$OTHER"                                     # 401: the other session is revoked too

call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
ACCESS=$(field accessToken)
```

```powershell
$other = (api POST /api/v1/auth/login @{ email = $email; password = $password }).data.accessToken
show (api POST /api/v1/auth/logout-all -Token $access)
show (api GET /api/v1/auth/me -Token $other)                             # 401: the other session is revoked too

$access = (api POST /api/v1/auth/login @{ email = $email; password = $password }).data.accessToken
```

---

### GET /api/v1/auth/me

Authenticated → `200` with `data: { id, email, role }`. Without a token → `401`.

```bash
call GET /api/v1/auth/me "" "$ACCESS"
MY_ID=$(field id)
call GET /api/v1/auth/me
```

```powershell
$me = api GET /api/v1/auth/me -Token $access
show $me
$myId = $me.data.id
show (api GET /api/v1/auth/me)
```

---

### POST /api/v1/auth/password/forgot

`{ email }` → always the same `200`. In development, the reset token is written to `mail-outbox/`.

```bash
call POST /api/v1/auth/password/forgot "{\"email\":\"$EMAIL\"}"
call POST /api/v1/auth/password/forgot '{"email":"nobody@example.com"}'
sleep 1
MAIL="mail-outbox/$(ls -t mail-outbox | head -1)"; cat "$MAIL"
RESET_TOKEN=$(sed -n 's/^Reset token: //p' "$MAIL")
```

```powershell
show (api POST /api/v1/auth/password/forgot @{ email = $email })
show (api POST /api/v1/auth/password/forgot @{ email = "nobody@example.com" })
Start-Sleep 1
$mail = Get-ChildItem mail-outbox | Sort-Object LastWriteTime | Select-Object -Last 1
Get-Content $mail.FullName
$resetToken = (Select-String -Path $mail.FullName -Pattern '^Reset token: (.+)$').Matches[0].Groups[1].Value
```

---

### POST /api/v1/auth/password/reset

`{ token, newPassword }` → `200`. The token works once (`400` if reused). Every session is revoked.

```bash
NEW_PASSWORD="walkthrough-reset-$(date +%s)-passphrase"
call POST /api/v1/auth/password/reset "{\"token\":\"$RESET_TOKEN\",\"newPassword\":\"$NEW_PASSWORD\"}"
call POST /api/v1/auth/password/reset "{\"token\":\"$RESET_TOKEN\",\"newPassword\":\"$NEW_PASSWORD\"}"   # 400
call GET /api/v1/auth/me "" "$ACCESS"                                    # 401: sessions revoked

call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$NEW_PASSWORD\"}"
ACCESS=$(field accessToken)
```

```powershell
$newPassword = "walkthrough-reset-" + [guid]::NewGuid()
show (api POST /api/v1/auth/password/reset @{ token = $resetToken; newPassword = $newPassword })
show (api POST /api/v1/auth/password/reset @{ token = $resetToken; newPassword = $newPassword })   # 400
show (api GET /api/v1/auth/me -Token $access)                            # 401: sessions revoked

$access = (api POST /api/v1/auth/login @{ email = $email; password = $newPassword }).data.accessToken
```

---

### POST /api/v1/auth/password/change

Authenticated, `{ currentPassword, newPassword }` → `200` with new tokens. Wrong `currentPassword` → `401`.

```bash
CHANGED_PASSWORD="walkthrough-change-$(date +%s)-passphrase"
call POST /api/v1/auth/password/change "{\"currentPassword\":\"wrong-password-123\",\"newPassword\":\"$CHANGED_PASSWORD\"}" "$ACCESS"   # 401
call POST /api/v1/auth/password/change "{\"currentPassword\":\"$NEW_PASSWORD\",\"newPassword\":\"$CHANGED_PASSWORD\"}" "$ACCESS"
ACCESS=$(field accessToken)
```

```powershell
$changedPassword = "walkthrough-change-" + [guid]::NewGuid()
show (api POST /api/v1/auth/password/change @{ currentPassword = "wrong-password-123"; newPassword = $changedPassword } $access)   # 401
$changed = api POST /api/v1/auth/password/change @{ currentPassword = $newPassword; newPassword = $changedPassword } $access
show $changed
$access = $changed.data.accessToken
```

---

### POST /api/v1/auth/mfa/enroll

Authenticated → `200` with `secret`, `otpauthUrl` and 10 `recoveryCodes` (shown once).
Add the `secret` to an authenticator app (Google Authenticator, Microsoft Authenticator…: "enter a setup key").

```bash
call POST /api/v1/auth/mfa/enroll "" "$ACCESS"
SECRET=$(field secret); echo "Secret: $SECRET"
RECOVERY=$(printf '%s' "$BODY" | sed -nE 's/.*"recoveryCodes":\["([^"]+)".*/\1/p')
```

```powershell
$enroll = api POST /api/v1/auth/mfa/enroll -Token $access
show $enroll
$recovery = $enroll.data.recoveryCodes[0]
```

---

### POST /api/v1/auth/mfa/verify

**1. Confirm enrolment** (with a Bearer token) → `200` `{ mfaEnabled: true }`. Type the code shown by the app.

```bash
CODE=123456   # replace with the current code from your authenticator app
call POST /api/v1/auth/mfa/verify "{\"code\":\"$CODE\"}" "$ACCESS"
```

```powershell
$code = Read-Host "6-digit code from your authenticator app"
show (api POST /api/v1/auth/mfa/verify @{ code = $code } $access)
```

**2. Complete a login** (without a Bearer token). Login now returns an `mfaToken` instead of tokens.
Wait for a **new** code: a code that was already used is rejected (replay protection).

```bash
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$CHANGED_PASSWORD\"}"
MFA_TOKEN=$(field mfaToken)
CODE=654321   # replace with a NEW code from your authenticator app
call POST /api/v1/auth/mfa/verify "{\"mfaToken\":\"$MFA_TOKEN\",\"code\":\"$CODE\"}"

# With a recovery code instead (each one works once)
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$CHANGED_PASSWORD\"}"
MFA_TOKEN=$(field mfaToken)
call POST /api/v1/auth/mfa/verify "{\"mfaToken\":\"$MFA_TOKEN\",\"recoveryCode\":\"$RECOVERY\"}"
ACCESS=$(field accessToken)
```

```powershell
$mfaToken = (api POST /api/v1/auth/login @{ email = $email; password = $changedPassword }).data.mfaToken
$code = Read-Host "NEW 6-digit code from your authenticator app"
show (api POST /api/v1/auth/mfa/verify @{ mfaToken = $mfaToken; code = $code })

# With a recovery code instead (each one works once)
$mfaToken = (api POST /api/v1/auth/login @{ email = $email; password = $changedPassword }).data.mfaToken
$done = api POST /api/v1/auth/mfa/verify @{ mfaToken = $mfaToken; recoveryCode = $recovery }
show $done
$access = $done.data.accessToken
```

---

### GET /api/v1/users

ADMIN only → `200` with a paginated list. A USER → `403`. The admin is created with the operator script,
which prints a temporary password; the commands below read it automatically.

```bash
call GET /api/v1/users "" "$ACCESS"                                      # 403 for a USER

ADMIN_EMAIL="admin-$(date +%s)@example.com"
ADMIN_PASSWORD=$(npm run -s admin:create -- "$ADMIN_EMAIL" | sed -n 's/.*after first login): //p')
call POST /api/v1/auth/login "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}"
ADMIN_ACCESS=$(field accessToken)
call GET "/api/v1/users?limit=20&offset=0" "" "$ADMIN_ACCESS"            # 200
```

```powershell
show (api GET /api/v1/users -Token $access)                              # 403 for a USER

$adminEmail = "admin-$(Get-Random)@example.com"
$adminOutput = npm run -s admin:create -- $adminEmail
$adminPassword = ($adminOutput | Select-String 'after first login\): (.+)$').Matches[0].Groups[1].Value
$adminAccess = (api POST /api/v1/auth/login @{ email = $adminEmail; password = $adminPassword }).data.accessToken
show (api GET "/api/v1/users?limit=20&offset=0" -Token $adminAccess)     # 200
```

---

### GET /api/v1/users/:id (additional route: object-level check)

Own id → `200`. Someone else's id → `403`, whether it exists or not. An ADMIN can read any id.

```bash
call GET /api/v1/auth/me "" "$ADMIN_ACCESS"; ADMIN_ID=$(field id)
call GET "/api/v1/users/$MY_ID" "" "$ACCESS"                             # 200
call GET "/api/v1/users/$ADMIN_ID" "" "$ACCESS"                          # 403
call GET "/api/v1/users/$MY_ID" "" "$ADMIN_ACCESS"                       # 200
```

```powershell
$adminId = (api GET /api/v1/auth/me -Token $adminAccess).data.id
show (api GET "/api/v1/users/$myId" -Token $access)                      # 200
show (api GET "/api/v1/users/$adminId" -Token $access)                   # 403
show (api GET "/api/v1/users/$myId" -Token $adminAccess)                 # 200
```