import { Prisma } from "../generated/prisma/client.js";
import { prisma } from "../lib/prisma.js";
import { AppError } from "../lib/errors.js";
import { sha256 } from "../lib/crypto.js";
import {
  assertPasswordNotBreached,
  hashPassword,
  verifyAgainstDummyHash,
  verifyPassword,
} from "../lib/password.js";
import { audit } from "./audit.service.js";
import { createMfaChallenge } from "./mfa.service.js";
import { createSession, type ClientInfo, type TokenPair } from "./session.service.js";

export type PublicUser = {
  id: string;
  email: string;
  role: "USER" | "ADMIN";
};

function invalidCredentials(): AppError {
  return new AppError(401, "UNAUTHORIZED", "Invalid email or password");
}

// --- Verrouillage du compte ---

const LOCKOUT_THRESHOLD = 5;
const BASE_LOCKOUT_SECONDS = 60;
const MAX_LOCKOUT_SECONDS = 15 * 60;

function lockoutDurationSeconds(failures: number): number {
  const doublings = failures - LOCKOUT_THRESHOLD;
  return Math.min(BASE_LOCKOUT_SECONDS * 2 ** doublings, MAX_LOCKOUT_SECONDS);
}

async function recordFailedLogin(userId: string): Promise<void> {
  const { failedLoginCount } = await prisma.user.update({
    where: { id: userId },
    data: { failedLoginCount: { increment: 1 } },
    select: { failedLoginCount: true },
  });

  if (failedLoginCount >= LOCKOUT_THRESHOLD) {
    const lockSeconds = lockoutDurationSeconds(failedLoginCount);
    await prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: new Date(Date.now() + lockSeconds * 1000) },
    });

    // AUDIT : le compte vient d'être verrouillé
    await audit({
      event: "auth.account_lock",
      outcome: "SUCCESS",
      reason: "too_many_failed_logins",
      userId,
      metadata: { failedLoginCount, lockSeconds },
    });
  }
}

async function clearFailedLogins(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { failedLoginCount: 0, lockedUntil: null },
  });
}

// --- Inscription ---

export async function registerUser(email: string, password: string): Promise<PublicUser> {
  const emailHash = sha256(email);

  // Le travail coûteux est fait AVANT de savoir si l'email existe :
  // un doublon et un nouvel email prennent le même temps.
  try {
    await assertPasswordNotBreached(password);
  } catch (error) {
    // AUDIT
    await audit({ event: "auth.register", outcome: "FAILURE", reason: "breached_password", metadata: { emailHash } });
    throw error;
  }

  const passwordHash = await hashPassword(password);

  try {
    const user = await prisma.user.create({
      data: { email, passwordHash, role: "USER" },
    });

    // AUDIT
    await audit({ event: "auth.register", outcome: "SUCCESS", userId: user.id });
    return { id: user.id, email: user.email, role: user.role };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      // AUDIT
      await audit({
        event: "auth.register",
        outcome: "FAILURE",
        reason: "email_already_registered",
        metadata: { emailHash },
      });
      throw new AppError(409, "CONFLICT", "Unable to register with these details");
    }
    throw error;
  }
}

// --- Connexion ---

export type LoginResult =
  | { mfaRequired: false; tokens: TokenPair }
  | { mfaRequired: true; mfaToken: string };

export async function loginUser(
  email: string,
  password: string,
  client: ClientInfo,
): Promise<LoginResult> {
  const user = await prisma.user.findUnique({
    where: { email },
    include: { mfaSecret: { select: { confirmedAt: true } } },
  });

  if (!user) {
    // Même coût qu'une vraie vérification : le temps de réponse ne trahit rien
    await verifyAgainstDummyHash(password);
    // AUDIT : on ne stocke que le hash d'un email inconnu
    await audit({ event: "auth.login", outcome: "FAILURE", reason: "unknown_email", metadata: { emailHash: sha256(email) } });
    throw invalidCredentials();
  }

  // On vérifie TOUJOURS le mot de passe, même si le compte est verrouillé,
  // pour que le temps de réponse soit le même dans tous les cas.
  const passwordIsValid = await verifyPassword(user.passwordHash, password);

  const isLocked = user.lockedUntil !== null && user.lockedUntil > new Date();
  if (isLocked) {
    // AUDIT : refus pendant le verrou (rien n'est compté, le verrou n'est pas prolongé)
    await audit({
      event: "auth.login",
      outcome: "FAILURE",
      reason: "account_locked",
      userId: user.id,
      metadata: { passwordWasCorrect: passwordIsValid },
    });
    throw invalidCredentials();
  }

  if (!passwordIsValid) {
    // AUDIT
    await audit({ event: "auth.login", outcome: "FAILURE", reason: "invalid_password", userId: user.id });
    await recordFailedLogin(user.id);
    throw invalidCredentials();
  }

  if (user.failedLoginCount > 0 || user.lockedUntil !== null) {
    await clearFailedLogins(user.id);
  }

  // Mot de passe correct : si la MFA est active, on demande le second facteur
  if (user.mfaSecret?.confirmedAt) {
    const mfaToken = await createMfaChallenge(user.id, client);
    // AUDIT
    await audit({ event: "auth.login", outcome: "SUCCESS", reason: "mfa_required", userId: user.id });
    return { mfaRequired: true, mfaToken };
  }

  const tokens = await createSession(user.id, client);
  // AUDIT
  await audit({
    event: "auth.login",
    outcome: "SUCCESS",
    reason: "password_verified",
    userId: user.id,
    metadata: { sessionId: tokens.sessionId },
  });
  return { mfaRequired: false, tokens };
}