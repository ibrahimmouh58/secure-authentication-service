import type { Prisma } from "../generated/prisma/client.js";
import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";
import { generateToken, sha256 } from "../lib/crypto.js";
import { sendMail } from "../lib/mailer.js";
import { rateLimitByAccount } from "../lib/rateLimit.js";
import { assertPasswordNotBreached, hashPassword, verifyPassword } from "../lib/password.js";
import { createSession, type ClientInfo, type TokenPair } from "./session.service.js";

function invalidResetToken(): AppError {
  return new AppError(400, "INVALID_TOKEN", "Invalid or expired reset token");
}

// Applique un nouveau mot de passe et invalide TOUT ce qui était lié à l'ancien
async function applyNewPassword(
  tx: Prisma.TransactionClient,
  userId: string,
  passwordHash: string,
  reason: string,
): Promise<void> {
  const now = new Date();

  await tx.user.update({
    where: { id: userId },
    data: { passwordHash, failedLoginCount: 0, lockedUntil: null },
  });

  await tx.passwordResetToken.updateMany({
    where: { userId, usedAt: null },
    data: { usedAt: now },
  });

  await tx.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: now, revokedReason: reason },
  });
}

// --- 1. Demande de reset (appelée en arrière-plan) ---

export async function requestPasswordReset(email: string): Promise<void> {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return;
  }

  const token = generateToken();
  const now = new Date();

  await prisma.$transaction([
    // Une nouvelle demande annule les liens précédents
    prisma.passwordResetToken.updateMany({
      where: { userId: user.id, usedAt: null },
      data: { usedAt: now },
    }),
    prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash: sha256(token),
        expiresAt: new Date(now.getTime() + env.RESET_TOKEN_TTL_SECONDS * 1000),
      },
    }),
  ]);

  const minutes = Math.round(env.RESET_TOKEN_TTL_SECONDS / 60);
  await sendMail(
    user.email,
    "Reset your password",
    `Use this token to reset your password. It expires in ${minutes} minutes and can be used once.\n\nReset token: ${token}\n\nIf you did not request this, you can ignore this email.`,
  );
}

// --- 2. Reset avec le token ---

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  const stored = await prisma.passwordResetToken.findUnique({
    where: { tokenHash: sha256(token) },
  });

  if (!stored || stored.usedAt || stored.expiresAt <= new Date()) {
    throw invalidResetToken();
  }

  await rateLimitByAccount("passwordReset", stored.userId);

  // Vérifié AVANT de consommer le token : si le mot de passe est refusé, le lien reste utilisable
  await assertPasswordNotBreached(newPassword);
  const passwordHash = await hashPassword(newPassword);

  const applied = await prisma.$transaction(async (tx) => {
    const claimed = await tx.passwordResetToken.updateMany({
      where: { id: stored.id, usedAt: null, expiresAt: { gt: new Date() } },
      data: { usedAt: new Date() },
    });

    if (claimed.count !== 1) {
      return false;
    }

    await applyNewPassword(tx, stored.userId, passwordHash, "password_reset");
    return true;
  });

  if (!applied) {
    throw invalidResetToken();
  }
}

// --- 3. Changement de mot de passe (utilisateur connecté) ---

export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  client: ClientInfo,
): Promise<TokenPair> {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user || !(await verifyPassword(user.passwordHash, currentPassword))) {
    throw new AppError(401, "UNAUTHORIZED", "Current password is incorrect");
  }

  await assertPasswordNotBreached(newPassword);
  const passwordHash = await hashPassword(newPassword);

  await prisma.$transaction(async (tx) => {
    await applyNewPassword(tx, userId, passwordHash, "password_change");
  });

  // Toutes les anciennes sessions sont révoquées ; on en ouvre une NOUVELLE pour ce client
  return createSession(userId, client);
}