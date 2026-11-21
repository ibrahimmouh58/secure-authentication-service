import * as argon2 from "argon2";
import { createHash } from "node:crypto";
import { z } from "zod";
import { AppError } from "./errors.js";
import { logger } from "./logger.js";

// --- 1. Hachage argon2id ---

const HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, HASH_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// --- 2. Hash factice pour égaliser le temps de réponse ---

let dummyHash: Promise<string> | undefined;

export async function verifyAgainstDummyHash(password: string): Promise<void> {
  dummyHash ??= hashPassword("dummy-password-used-only-to-equalise-timing");
  await verifyPassword(await dummyHash, password);
}

// --- 3. Politique de mot de passe ---

export const passwordSchema = z.string().min(12).max(128);

// --- 4. Vérification contre les mots de passe compromis (Have I Been Pwned) ---

export async function isPasswordBreached(password: string): Promise<boolean> {
  const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" },
      signal: AbortSignal.timeout(3000),
    });

    if (!response.ok) {
            logger.warn({ httpStatus: response.status }, "breached-password check unavailable");
      return false;
    }

    const body = await response.text();

    return body.split("\n").some((line) => {
      const [hashSuffix, count] = line.trim().split(":");
      return hashSuffix === suffix && Number(count) > 0;
    });
  } catch {
        logger.warn("breached-password check unavailable: network error or timeout");
    return false;
  }
}

export async function assertPasswordNotBreached(password: string): Promise<void> {
  if (await isPasswordBreached(password)) {
    throw new AppError(
      400,
      "WEAK_PASSWORD",
      "This password appears in a known data breach. Please choose another one.",
    );
  }
}