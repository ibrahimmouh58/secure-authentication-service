import { Router } from "express";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";
import { logger } from "../lib/logger.js";
import { ok } from "../lib/response.js";
import { parseBody } from "../lib/validation.js";
import { getClientInfo } from "../lib/client.js";
import { rateLimitByAccount, rateLimitByIp } from "../lib/rateLimit.js";
import { authenticateRequest, getAuth, requireAuth } from "../middleware/requireAuth.js";
import {
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  mfaChallengeSchema,
  mfaConfirmSchema,
  refreshSchema,
  registerSchema,
  resetPasswordSchema,
} from "../schemas/auth.schemas.js";
import { loginUser, registerUser } from "../services/auth.service.js";
import {
  completeMfaChallenge,
  confirmMfaEnrollment,
  enrollMfa,
  MFA_CHALLENGE_TTL_SECONDS,
} from "../services/mfa.service.js";
import { changePassword, requestPasswordReset, resetPassword } from "../services/password.service.js";
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

// ============================================================
// Inscription, connexion, tokens
// ============================================================

// POST /api/v1/auth/register → 201
authRouter.post("/register", rateLimitByIp("register"), async (req, res) => {
  const body = parseBody(registerSchema, req.body);
  await rateLimitByAccount("register", body.email);

  if (body.role === "ADMIN") {
    throw new AppError(403, "FORBIDDEN", "Self-registration as ADMIN is not allowed");
  }

  const user = await registerUser(body.email, body.password);
  ok(res, user, 201);
});

// POST /api/v1/auth/login → 200 (tokens, ou challenge MFA)
authRouter.post("/login", rateLimitByIp("login"), async (req, res) => {
  const body = parseBody(loginSchema, req.body);
  await rateLimitByAccount("login", body.email);

  const result = await loginUser(body.email, body.password, getClientInfo(req));

  if (result.mfaRequired) {
    ok(res, { mfaRequired: true, mfaToken: result.mfaToken, expiresIn: MFA_CHALLENGE_TTL_SECONDS });
    return;
  }

  ok(res, toTokenResponse(result.tokens));
});

// POST /api/v1/auth/refresh → 200
authRouter.post("/refresh", rateLimitByIp("refresh"), async (req, res) => {
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

// ============================================================
// Mot de passe
// ============================================================

// POST /api/v1/auth/password/forgot → 200 (toujours la même réponse)
authRouter.post("/password/forgot", rateLimitByIp("passwordForgot"), async (req, res) => {
  const body = parseBody(forgotPasswordSchema, req.body);
  await rateLimitByAccount("passwordForgot", body.email);

  // Le travail se fait APRÈS la réponse : le temps de réponse ne dépend pas de l'existence du compte
  void requestPasswordReset(body.email).catch((error: unknown) => {
    logger.error(
      { errorName: error instanceof Error ? error.name : "unknown" },
      "password reset request failed",
    );
  });

  ok(res, { message: "If an account exists for this email, a reset token has been sent." });
});

// POST /api/v1/auth/password/reset → 200
authRouter.post("/password/reset", rateLimitByIp("passwordReset"), async (req, res) => {
  const body = parseBody(resetPasswordSchema, req.body);
  await resetPassword(body.token, body.newPassword);
  ok(res, { passwordReset: true });
});

// POST /api/v1/auth/password/change → 200 (authentifiée, renvoie de nouveaux tokens)
authRouter.post("/password/change", rateLimitByIp("passwordChange"), requireAuth, async (req, res) => {
  const auth = getAuth(req);
  const body = parseBody(changePasswordSchema, req.body);
  await rateLimitByAccount("passwordChange", auth.userId);

  const tokens = await changePassword(auth.userId, body.currentPassword, body.newPassword, getClientInfo(req));
  ok(res, toTokenResponse(tokens));
});

// ============================================================
// MFA
// ============================================================

// POST /api/v1/auth/mfa/enroll → 200 (authentifiée)
authRouter.post("/mfa/enroll", requireAuth, async (req, res) => {
  const auth = getAuth(req);
  const enrollment = await enrollMfa(auth.userId, auth.email);
  ok(res, enrollment);
});

// POST /api/v1/auth/mfa/verify → 200
//   - { mfaToken, code | recoveryCode }  : termine un login (sans access token)
//   - { code } + Bearer                  : confirme l'activation de la MFA
authRouter.post("/mfa/verify", rateLimitByIp("mfaVerify"), async (req, res) => {
  const isLoginChallenge = typeof req.body === "object" && req.body !== null && "mfaToken" in req.body;

  if (isLoginChallenge) {
    const body = parseBody(mfaChallengeSchema, req.body);
    const tokens = await completeMfaChallenge(body, getClientInfo(req));
    ok(res, toTokenResponse(tokens));
    return;
  }

  const auth = await authenticateRequest(req);
  await rateLimitByAccount("mfaVerify", auth.userId);
  const body = parseBody(mfaConfirmSchema, req.body);
  await confirmMfaEnrollment(auth.userId, body.code);
  ok(res, { mfaEnabled: true });
});