import { prisma } from "../lib/prisma.js";
import { generateToken, sha256 } from "../lib/crypto.js";
import { signAccessToken } from "../lib/jwt.js";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";

export type ClientInfo = {
  ipAddress?: string;
  userAgent?: string;
};

export type TokenPair = {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
};

function secondsFromNow(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

function refreshTokenExpiry(sessionExpiresAt: Date): Date {
  const candidate = secondsFromNow(env.REFRESH_TOKEN_TTL_SECONDS);
  return candidate < sessionExpiresAt ? candidate : sessionExpiresAt;
}

function invalidRefreshToken(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Invalid refresh token");
}

// --- 1. Créer une session (au login) ---

export async function createSession(userId: string, client: ClientInfo): Promise<TokenPair> {
  const refreshToken = generateToken();
  const sessionExpiresAt = secondsFromNow(env.SESSION_MAX_AGE_SECONDS);

  const session = await prisma.session.create({
    data: {
      userId,
      expiresAt: sessionExpiresAt,
      ipAddress: client.ipAddress,
      userAgent: client.userAgent,
      refreshTokens: {
        create: {
          tokenHash: sha256(refreshToken),
          expiresAt: refreshTokenExpiry(sessionExpiresAt),
        },
      },
    },
  });

  const accessToken = await signAccessToken(userId, session.id);
  return { accessToken, refreshToken, sessionId: session.id };
}

// --- 2. Échanger un refresh token contre une nouvelle paire (rotation) ---

export async function rotateRefreshToken(presentedToken: string): Promise<TokenPair> {
  const now = new Date();

  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash: sha256(presentedToken) },
    include: { session: true },
  });

  if (!stored) {
    throw invalidRefreshToken();
  }

  const { session } = stored;

  // Rejeu : ce token a déjà été échangé → on révoque toute la famille
  if (stored.usedAt) {
    await revokeSession(session.id, "refresh_token_reuse");
    throw invalidRefreshToken();
  }

  if (session.revokedAt || session.expiresAt <= now || stored.expiresAt <= now) {
    throw invalidRefreshToken();
  }

  const newRefreshToken = generateToken();

  const rotated = await prisma.$transaction(async (tx) => {
    const claimed = await tx.refreshToken.updateMany({
      where: { id: stored.id, usedAt: null, session: { revokedAt: null } },
      data: { usedAt: now },
    });

    if (claimed.count !== 1) {
      return false;
    }

    await tx.refreshToken.create({
      data: {
        sessionId: session.id,
        tokenHash: sha256(newRefreshToken),
        expiresAt: refreshTokenExpiry(session.expiresAt),
      },
    });

    return true;
  });

  // Deux requêtes simultanées avec le même token : la seconde perd → rejeu
  if (!rotated) {
    await revokeSession(session.id, "refresh_token_reuse");
    throw invalidRefreshToken();
  }

  const accessToken = await signAccessToken(session.userId, session.id);
  return { accessToken, refreshToken: newRefreshToken, sessionId: session.id };
}

// --- 3. Révoquer une session (logout) ---

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  await prisma.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
}

// --- 4. Révoquer toutes les sessions d'un utilisateur (logout-all, changement de mot de passe) ---

export async function revokeAllSessions(userId: string, reason: string): Promise<number> {
  const result = await prisma.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
  return result.count;
}

// --- 5. Retrouver une session active (pour le middleware d'authentification) ---

export async function findActiveSession(sessionId: string) {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { user: true },
  });

  if (!session || session.revokedAt || session.expiresAt <= new Date()) {
    return null;
  }

  return session;
}