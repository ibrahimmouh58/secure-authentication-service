import { randomUUID } from "node:crypto";
import { importJWK, jwtVerify, SignJWT, type JWTHeaderParameters } from "jose";
import { env } from "./env.js";
import { AppError } from "./errors.js";

const ALGORITHM = "EdDSA";
const TOKEN_TYPE = "at+jwt";

// --- Chargement des clés au démarrage ---

const signingKey = await importJWK(env.JWT_PRIVATE_KEY, ALGORITHM);
const activeKid = env.JWT_PRIVATE_KEY.kid;

const verificationKeys = new Map<string, Awaited<ReturnType<typeof importJWK>>>();
for (const jwk of env.JWT_PUBLIC_KEYS) {
  verificationKeys.set(jwk.kid, await importJWK(jwk, ALGORITHM));
}

function getVerificationKey(header: JWTHeaderParameters) {
  const key = header.kid ? verificationKeys.get(header.kid) : undefined;
  if (!key) {
    throw new Error("Unknown signing key");
  }
  return key;
}

// --- Création d'un access token ---

export async function signAccessToken(userId: string, sessionId: string): Promise<string> {
  return new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: ALGORITHM, kid: activeKid, typ: TOKEN_TYPE })
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setSubject(userId)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${env.ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(signingKey);
}

// --- Vérification d'un access token ---

export type AccessTokenClaims = {
  userId: string;
  sessionId: string;
  tokenId: string;
};

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  try {
    const { payload } = await jwtVerify(token, getVerificationKey, {
      algorithms: [ALGORITHM],
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      typ: TOKEN_TYPE,
      requiredClaims: ["iss", "aud", "exp", "iat", "sub", "jti"],
    });

    if (typeof payload.sid !== "string" || !payload.sub || !payload.jti) {
      throw new Error("Missing claims");
    }

    return { userId: payload.sub, sessionId: payload.sid, tokenId: payload.jti };
  } catch {
    throw new AppError(401, "UNAUTHORIZED", "Invalid or expired access token");
  }
}