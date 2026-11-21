import type { RequestHandler } from "express";
import { authenticateRequest } from "./requireAuth.js";

// Les SEULES routes accessibles sans authentification.
// Toute autre route, y compris une route ajoutée plus tard, exige un access token valide.
const PUBLIC_ROUTES = new Set([
  "GET /health",
  "HEAD /health",
  "POST /api/v1/auth/register",
  "POST /api/v1/auth/login",
  "POST /api/v1/auth/refresh",
  "POST /api/v1/auth/password/forgot",
  "POST /api/v1/auth/password/reset",
  // Publique car elle sert aussi à terminer un login MFA ;
  // la route exige elle-même un token pour confirmer une activation.
  "POST /api/v1/auth/mfa/verify",
]);

export const denyByDefault: RequestHandler = async (req, _res, next) => {
  if (PUBLIC_ROUTES.has(`${req.method} ${req.path}`)) {
    next();
    return;
  }

  req.auth = await authenticateRequest(req);
  next();
};