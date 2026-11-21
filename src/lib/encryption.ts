import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { env } from "./env.js";

const ALGORITHM = "aes-256-gcm";
const VERSION = "v1";
const key = Buffer.from(env.MFA_ENCRYPTION_KEY, "base64");

export function encrypt(plaintext: Buffer, associatedData: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(associatedData, "utf8"));

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [VERSION, iv.toString("base64url"), authTag.toString("base64url"), ciphertext.toString("base64url")].join(":");
}

export function decrypt(payload: string, associatedData: string): Buffer {
  const [version, iv, authTag, ciphertext] = payload.split(":");
  if (version !== VERSION || !iv || !authTag || !ciphertext) {
    throw new Error("Unsupported ciphertext format");
  }

  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, "base64url"));
  decipher.setAAD(Buffer.from(associatedData, "utf8"));
  decipher.setAuthTag(Buffer.from(authTag, "base64url"));

  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]);
}