import { Router } from "express";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";
import { ok } from "../lib/response.js";
import { parseBody } from "../lib/validation.js";
import { getClientInfo } from "../lib/client.js";
import { loginSchema, registerSchema } from "../schemas/auth.schemas.js";
import { loginUser, registerUser } from "../services/auth.service.js";
import type { TokenPair } from "../services/session.service.js";

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