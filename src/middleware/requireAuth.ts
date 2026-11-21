import type { Request, RequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { verifyAccessToken } from "../lib/jwt.js";
import { findActiveSession } from "../services/session.service.js";
import { audit } from "../services/audit.service.js";

// L'utilisateur connecté, attaché à la requête par l'authentification
export type AuthContext = {
  userId: string;
  sessionId: string;
  email: string;
  role: "USER" | "ADMIN";
};

// Déclare req.auth à TypeScript. Placée ici (et pas dans un fichier .d.ts séparé)
// pour être chargée par chaque fichier qui utilise l'authentification.
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i;

function unauthorized(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Authentication required");
}

export async function authenticateRequest(req: Request): Promise<AuthContext> {
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
  // Réutilise l'authentification déjà faite par le garde global, s'il y en a une
  req.auth ??= await authenticateRequest(req);
  next();
};

export function getAuth(req: Request): AuthContext {
  if (!req.auth) {
    throw unauthorized();
  }
  return req.auth;
}