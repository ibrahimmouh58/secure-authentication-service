import { Router } from "express";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";
import { ok } from "../lib/response.js";
import { parseBody } from "../lib/validation.js";
import { getClientInfo } from "../lib/client.js";
import { getAuth, requireAuth } from "../middleware/requireAuth.js";
import { loginSchema, refreshSchema, registerSchema } from "../schemas/auth.schemas.js";
import { loginUser, registerUser } from "../services/auth.service.js";
import {
  revokeAllSessions,
  revokeSession,
  rotateRefreshToken,
  type TokenPair,
} from "../services/session.service.js";

export const authRouter = Router();

function toTokenResponse(tokens: TokenPair) {
  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    tokenType: "Bearer",
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  };
}

// POST /api/v1/auth/register → 201
authRouter.post("/register", async (req, res) => {
  const body = parseBody(registerSchema, req.body);

  if (body.role === "ADMIN") {
    throw new AppError(403, "FORBIDDEN", "Self-registration as ADMIN is not allowed");
  }

  const user = await registerUser(body.email, body.password);
  ok(res, user, 201);
});

// POST /api/v1/auth/login → 200
authRouter.post("/login", async (req, res) => {
  const body = parseBody(loginSchema, req.body);
  const tokens = await loginUser(body.email, body.password, getClientInfo(req));
  ok(res, toTokenResponse(tokens));
});

// POST /api/v1/auth/refresh → 200
authRouter.post("/refresh", async (req, res) => {
  const body = parseBody(refreshSchema, req.body);
  const tokens = await rotateRefreshToken(body.refreshToken);
  ok(res, toTokenResponse(tokens));
});

// POST /api/v1/auth/logout → 200 (révoque la session courante)
authRouter.post("/logout", requireAuth, async (req, res) => {
  const auth = getAuth(req);
  await revokeSession(auth.sessionId, "logout");
  ok(res, { loggedOut: true });
});

// POST /api/v1/auth/logout-all → 200 (révoque toutes les sessions de l'utilisateur)
authRouter.post("/logout-all", requireAuth, async (req, res) => {
  const auth = getAuth(req);
  const revokedSessions = await revokeAllSessions(auth.userId, "logout_all");
  ok(res, { revokedSessions });
});

// GET /api/v1/auth/me → 200 { id, email, role }
authRouter.get("/me", requireAuth, (req, res) => {
  const auth = getAuth(req);
  ok(res, { id: auth.userId, email: auth.email, role: auth.role });
});