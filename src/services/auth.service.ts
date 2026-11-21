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

  const passwordIsValid = await verifyPassword(user.passwordHash, password);
  if (!passwordIsValid) {
    throw invalidCredentials();
  }

  // Étape 8 : verrouillage du compte. Étape 10 : MFA. Étape 12 : audit.
  return createSession(user.id, client);
}