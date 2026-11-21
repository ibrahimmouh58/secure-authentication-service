import type { Request, RequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { verifyAccessToken } from "../lib/jwt.js";
import { findActiveSession } from "../services/session.service.js";
import { audit } from "../services/audit.service.js";

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i;

function unauthorized(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Authentication required");
}

export async function authenticateRequest(req: Request) {
  const match = BEARER_PATTERN.exec(req.get("authorization") ?? "");
  if (!match) {
    throw unauthorized();
  }

    let claims;
  try {
    claims = await verifyAccessToken(match[1]);
  } catch (error) {
    // AUDIT : token falsifié, expiré, mauvais algorithme, kid inconnu…
    await audit({ event: "auth.token", outcome: "FAILURE", reason: "invalid_access_token" });
    throw error;
  }

  const session = await findActiveSession(claims.sessionId);
  if (!session || session.userId !== claims.userId) {
    // AUDIT : token valide, mais session révoquée ou expirée
    await audit({
      event: "auth.token",
      outcome: "FAILURE",
      reason: "session_revoked_or_expired",
      metadata: { sessionId: claims.sessionId },
    });
    throw unauthorized();
  }

  return {
    userId: session.user.id,
    sessionId: session.id,
    email: session.user.email,
    role: session.user.role,
  };
}

export const requireAuth: RequestHandler = async (req, _res, next) => {
  req.auth = await authenticateRequest(req);
  next();
};

export function getAuth(req: Request) {
  if (!req.auth) {
    throw unauthorized();
  }
  return req.auth;
}