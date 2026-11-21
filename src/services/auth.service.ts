import { Prisma } from "../generated/prisma/client.js";
import { prisma } from "../lib/prisma.js";
import { AppError } from "../lib/errors.js";
import {
  hashPassword,
  isPasswordBreached,
  verifyAgainstDummyHash,
  verifyPassword,
} from "../lib/password.js";
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
    await prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: new Date(Date.now() + lockoutDurationSeconds(failedLoginCount) * 1000) },
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
  // Le travail coûteux est fait AVANT de savoir si l'email existe :
  // un doublon et un nouvel email prennent le même temps.
  if (await isPasswordBreached(password)) {
    throw new AppError(
      400,
      "WEAK_PASSWORD",
      "This password appears in a known data breach. Please choose another one.",
    );
  }

  const passwordHash = await hashPassword(password);

  try {
    const user = await prisma.user.create({
      data: { email, passwordHash, role: "USER" },
    });
    return { id: user.id, email: user.email, role: user.role };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      throw new AppError(409, "CONFLICT", "Unable to register with these details");
    }
    throw error;
  }
}

// --- Connexion ---

export async function loginUser(
  email: string,
  password: string,
  client: ClientInfo,
): Promise<TokenPair> {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    // Même coût qu'une vraie vérification : le temps de réponse ne trahit rien
    await verifyAgainstDummyHash(password);
    throw invalidCredentials();
  }

  // On vérifie TOUJOURS le mot de passe, même si le compte est verrouillé,
  // pour que le temps de réponse soit le même dans tous les cas.
  const passwordIsValid = await verifyPassword(user.passwordHash, password);

  const isLocked = user.lockedUntil !== null && user.lockedUntil > new Date();
  if (isLocked) {
    // Pendant le verrou : refus générique, rien n'est compté, le verrou n'est pas prolongé
    throw invalidCredentials();
  }

  if (!passwordIsValid) {
    await recordFailedLogin(user.id);
    throw invalidCredentials();
  }

  if (user.failedLoginCount > 0 || user.lockedUntil !== null) {
    await clearFailedLogins(user.id);
  }

  // Étape 10 : MFA. Étape 12 : audit.
  return createSession(user.id, client);
}