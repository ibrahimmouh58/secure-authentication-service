import type { Request, RequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { verifyAccessToken } from "../lib/jwt.js";
import { findActiveSession } from "../services/session.service.js";

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i;

function unauthorized(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Authentication required");
}

export const requireAuth: RequestHandler = async (req, _res, next) => {
  // 1. Lire l'en-tête "Authorization: Bearer <token>"
  const match = BEARER_PATTERN.exec(req.get("authorization") ?? "");
  if (!match) {
    throw unauthorized();
  }

  // 2. Vérifier la signature et les claims du JWT
  const claims = await verifyAccessToken(match[1]);

  // 3. Vérifier que la session existe encore et n'est pas révoquée
  const session = await findActiveSession(claims.sessionId);
  if (!session || session.userId !== claims.userId) {
    throw unauthorized();
  }

  // 4. Attacher l'utilisateur connecté à la requête
  req.auth = {
    userId: session.user.id,
    sessionId: session.id,
    email: session.user.email,
    role: session.user.role,
  };

  next();
};

export function getAuth(req: Request) {
  if (!req.auth) {
    throw unauthorized();
  }
  return req.auth;
}