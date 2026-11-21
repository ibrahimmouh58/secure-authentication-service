import type { RequestHandler } from "express";
import { prisma } from "./prisma.js";
import { sha256 } from "./crypto.js";
import { AppError } from "./errors.js";

type Limit = { limit: number; windowSeconds: number };

// Toutes les limites au même endroit (fenêtre de 15 minutes)
export const RATE_LIMITS = {
  login: { ip: { limit: 50, windowSeconds: 900 }, account: { limit: 10, windowSeconds: 900 } },
  register: { ip: { limit: 30, windowSeconds: 900 }, account: { limit: 5, windowSeconds: 900 } },
  refresh: { ip: { limit: 100, windowSeconds: 900 }, account: { limit: 30, windowSeconds: 900 } },
  passwordForgot: { ip: { limit: 10, windowSeconds: 900 }, account: { limit: 3, windowSeconds: 900 } },
  passwordReset: { ip: { limit: 10, windowSeconds: 900 }, account: { limit: 5, windowSeconds: 900 } },
  passwordChange: { ip: { limit: 10, windowSeconds: 900 }, account: { limit: 5, windowSeconds: 900 } },
} satisfies Record<string, { ip: Limit; account: Limit }>;

type Scope = keyof typeof RATE_LIMITS;

// Compte une requête pour une clé ; lance une erreur 429 si la limite est dépassée
export async function consumeRateLimit(key: string, { limit, windowSeconds }: Limit): Promise<void> {
  const now = new Date();
  const newResetAt = new Date(now.getTime() + windowSeconds * 1000);

  const [row] = await prisma.$queryRaw<{ count: number; resetAt: Date }[]>`
    INSERT INTO "RateLimit" ("key", "count", "resetAt")
    VALUES (${key}, 1, ${newResetAt})
    ON CONFLICT ("key") DO UPDATE SET
      "count" = CASE
        WHEN "RateLimit"."resetAt" <= ${now} THEN 1
        ELSE "RateLimit"."count" + 1
      END,
      "resetAt" = CASE
        WHEN "RateLimit"."resetAt" <= ${now} THEN EXCLUDED."resetAt"
        ELSE "RateLimit"."resetAt"
      END
    RETURNING "count", "resetAt"
  `;

  if (row && row.count > limit) {
    const retryAfter = Math.max(1, Math.ceil((row.resetAt.getTime() - now.getTime()) / 1000));
    throw new AppError(429, "TOO_MANY_REQUESTS", "Too many requests, please try again later", {
      "Retry-After": String(retryAfter),
    });
  }
}

// Limite par IP : un middleware à placer AVANT la route
export function rateLimitByIp(scope: Scope): RequestHandler {
  return async (req, _res, next) => {
    await consumeRateLimit(`${scope}:ip:${req.ip ?? "unknown"}`, RATE_LIMITS[scope].ip);
    next();
  };
}

// Limite par compte : à appeler DANS la route, une fois l'email (ou l'id) connu
export async function rateLimitByAccount(scope: Scope, accountIdentifier: string): Promise<void> {
  await consumeRateLimit(`${scope}:account:${sha256(accountIdentifier)}`, RATE_LIMITS[scope].account);
}
