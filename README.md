# Secure Authentication Service

Authentication API built with Node 20+, Express, TypeScript, Prisma 7 and PostgreSQL.
The API listens on **port 7766**.

## Prerequisites

- Node.js 20 or later
- Docker with Docker Compose v2 (Docker Desktop on Windows/macOS)
- Ports 7766 and 5433 free on your machine

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

Open `.env` and fill it with these local development values:

```
PORT=7766
NODE_ENV=development

POSTGRES_USER=auth
POSTGRES_PASSWORD=localdevpassword
POSTGRES_DB=auth
POSTGRES_PORT=5433
DATABASE_URL=postgresql://auth:localdevpassword@localhost:5433/auth?schema=public

CORS_ORIGINS=http://localhost:3000

JWT_ISSUER=secure-auth-service
JWT_AUDIENCE=secure-auth-api

ACCESS_TOKEN_TTL_SECONDS=900
REFRESH_TOKEN_TTL_SECONDS=1209600
SESSION_MAX_AGE_SECONDS=2592000
```

The database credentials are for a local, throwaway database only.

### 3. Generate the signing keys and the MFA encryption key

```bash
npm run secrets:generate
```

This prints three lines: `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEYS` and `MFA_ENCRYPTION_KEY`.
Copy them into `.env`, replacing the empty lines with the same names.
Each variable must appear only once in `.env`.
These are real secrets: never commit or share them.

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

## Connecting to the database

```
DATABASE_URL=postgresql://auth:localdevpassword@localhost:5433/auth?schema=public
```

- Host: `localhost`
- Port: `5433`
- User: `auth`
- Password: `localdevpassword`
- Database: `auth`

Or open a SQL shell directly in the container:

```bash
docker compose exec db psql -U auth -d auth
```

## Resetting the database

```bash
docker compose down -v
docker compose up -d
npm start
```

`down -v` deletes the database volume. `npm start` then re-applies every migration to the empty database.