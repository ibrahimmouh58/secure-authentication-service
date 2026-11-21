import { prisma } from "../lib/prisma.js";
import { env } from "../lib/env.js";
import { AppError } from "../lib/errors.js";
import { generateToken, sha256 } from "../lib/crypto.js";
import { decrypt, encrypt } from "../lib/encryption.js";
import { rateLimitByAccount } from "../lib/rateLimit.js";
import {
  base32Encode,
  buildOtpAuthUrl,
  generateRecoveryCode,
  generateTotpSecret,
  normalizeRecoveryCode,
  verifyTotp,
} from "../lib/totp.js";
import { createSession, type ClientInfo, type TokenPair } from "./session.service.js";

export const MFA_CHALLENGE_TTL_SECONDS = 300;
const MAX_CHALLENGE_ATTEMPTS = 5;
const RECOVERY_CODE_COUNT = 10;

function invalidMfa(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Invalid MFA code or challenge");
}

// --- 1. Activation : générer le secret et les codes de récupération ---

export type MfaEnrollment = {
  secret: string;
  otpauthUrl: string;
  recoveryCodes: string[];
};

export async function enrollMfa(userId: string, email: string): Promise<MfaEnrollment> {
  const existing = await prisma.mfaSecret.findUnique({ where: { userId } });
  if (existing?.confirmedAt) {
    throw new AppError(409, "CONFLICT", "MFA is already enabled");
  }

  const secret = generateTotpSecret();
  const secretEncrypted = encrypt(secret, userId);
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => generateRecoveryCode());

  await prisma.$transaction([
    prisma.mfaSecret.upsert({
      where: { userId },
      create: { userId, secretEncrypted },
      update: { secretEncrypted, confirmedAt: null, lastUsedStep: null },
    }),
    prisma.recoveryCode.deleteMany({ where: { userId } }),
    prisma.recoveryCode.createMany({
      data: recoveryCodes.map((code) => ({ userId, codeHash: sha256(normalizeRecoveryCode(code)) })),
    }),
  ]);

  const base32Secret = base32Encode(secret);
  return {
    secret: base32Secret,
    otpauthUrl: buildOtpAuthUrl(env.JWT_ISSUER, email, base32Secret),
    recoveryCodes,
  };
}

// --- 2. Confirmation de l'activation (parcours 1) ---

export async function confirmMfaEnrollment(userId: string, code: string): Promise<void> {
  const record = await prisma.mfaSecret.findUnique({ where: { userId } });
  if (!record) {
    throw new AppError(400, "MFA_NOT_ENROLLED", "Start MFA enrolment first");
  }
  if (record.confirmedAt) {
    throw new AppError(409, "CONFLICT", "MFA is already enabled");
  }

  const step = verifyTotp(decrypt(record.secretEncrypted, userId), code);
  if (step === null) {
    throw new AppError(400, "INVALID_CODE", "Invalid MFA code");
  }

  const confirmed = await prisma.mfaSecret.updateMany({
    where: { userId, confirmedAt: null },
    data: { confirmedAt: new Date(), lastUsedStep: step },
  });
  if (confirmed.count !== 1) {
    throw new AppError(409, "CONFLICT", "MFA is already enabled");
  }
}

// --- 3. Création d'un challenge au login (appelé par loginUser) ---

export async function createMfaChallenge(userId: string, client: ClientInfo): Promise<string> {
  const mfaToken = generateToken();
  await prisma.mfaChallenge.create({
    data: {
      userId,
      tokenHash: sha256(mfaToken),
      expiresAt: new Date(Date.now() + MFA_CHALLENGE_TTL_SECONDS * 1000),
      ipAddress: client.ipAddress,
      userAgent: client.userAgent,
    },
  });
  return mfaToken;
}

// --- Vérification d'un code TOTP avec protection anti-rejeu ---

async function consumeTotp(userId: string, code: string): Promise<boolean> {
  const record = await prisma.mfaSecret.findUnique({ where: { userId } });
  if (!record?.confirmedAt) {
    return false;
  }

  const step = verifyTotp(decrypt(record.secretEncrypted, userId), code);
  if (step === null) {
    return false;
  }

  // N'accepte ce step que s'il est PLUS RÉCENT que le dernier utilisé
  const claimed = await prisma.mfaSecret.updateMany({
    where: { userId, OR: [{ lastUsedStep: null }, { lastUsedStep: { lt: step } }] },
    data: { lastUsedStep: step },
  });
  return claimed.count === 1;
}

// --- Vérification d'un code de récupération (usage unique) ---

async function consumeRecoveryCode(userId: string, input: string): Promise<boolean> {
  const claimed = await prisma.recoveryCode.updateMany({
    where: { userId, codeHash: sha256(normalizeRecoveryCode(input)), usedAt: null },
    data: { usedAt: new Date() },
  });
  return claimed.count === 1;
}

// --- 4. Terminer un login avec la MFA (parcours 2) ---

export type MfaChallengeInput = {
  mfaToken: string;
  code?: string;
  recoveryCode?: string;
};

export async function completeMfaChallenge(input: MfaChallengeInput, client: ClientInfo): Promise<TokenPair> {
  const challenge = await prisma.mfaChallenge.findUnique({
    where: { tokenHash: sha256(input.mfaToken) },
  });
  if (!challenge) {
    throw invalidMfa();
  }

  await rateLimitByAccount("mfaVerify", challenge.userId);

  // Compte l'essai, seulement si le challenge est encore valide et n'a pas épuisé ses essais
  const attempt = await prisma.mfaChallenge.updateMany({
    where: {
      id: challenge.id,
      usedAt: null,
      expiresAt: { gt: new Date() },
      attempts: { lt: MAX_CHALLENGE_ATTEMPTS },
    },
    data: { attempts: { increment: 1 } },
  });
  if (attempt.count !== 1) {
    throw invalidMfa();
  }

  const factorIsValid =
    input.code !== undefined
      ? await consumeTotp(challenge.userId, input.code)
      : await consumeRecoveryCode(challenge.userId, input.recoveryCode ?? "");
  if (!factorIsValid) {
    throw invalidMfa();
  }

  // Le challenge ne sert qu'une fois
  const completed = await prisma.mfaChallenge.updateMany({
    where: { id: challenge.id, usedAt: null },
    data: { usedAt: new Date() },
  });
  if (completed.count !== 1) {
    throw invalidMfa();
  }

  return createSession(challenge.userId, client);
}