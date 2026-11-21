import { createHmac, randomBytes } from "node:crypto";
import { safeEqual } from "./crypto.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PERIOD_SECONDS = 30;
const DIGITS = 6;
const ALLOWED_DRIFT_STEPS = 1;

// --- Base32 : le format dans lequel les applis d'authentification lisent le secret ---

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(input: string): Buffer {
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of input.toUpperCase().replace(/=+$/, "")) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32 input");
    }
    value = ((value << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

// --- Génération d'un secret ---

export function generateTotpSecret(): Buffer {
  return randomBytes(20);
}

// --- HOTP (RFC 4226) : le code pour un compteur donné ---

function hotp(secret: Buffer, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac("sha1", secret).update(message).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];

  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

// --- TOTP (RFC 6238) : le compteur est le numéro de la période de 30 s ---

export function timeStep(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / PERIOD_SECONDS);
}

export function generateTotp(secret: Buffer, nowMs: number = Date.now()): string {
  return hotp(secret, timeStep(nowMs));
}

// Renvoie le numéro du step qui correspond, ou null si le code est faux
export function verifyTotp(secret: Buffer, code: string, nowMs: number = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) {
    return null;
  }

  const current = timeStep(nowMs);
  let matchedStep: number | null = null;

  for (let step = current - ALLOWED_DRIFT_STEPS; step <= current + ALLOWED_DRIFT_STEPS; step++) {
    if (safeEqual(hotp(secret, step), code)) {
      matchedStep = step;
    }
  }

  return matchedStep;
}

// --- URL otpauth:// (ce que contient le QR code) ---

export function buildOtpAuthUrl(issuer: string, accountName: string, base32Secret: string): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// --- Codes de récupération ---

// 32 caractères sans les ambigus (pas de 0/O ni de 1/I) : 5 bits par caractère
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generateRecoveryCode(): string {
  const chars = [...randomBytes(16)].map((byte) => RECOVERY_ALPHABET[byte & 31]).join("");
  return chars.match(/.{4}/g)!.join("-");
}

export function normalizeRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z0-9]/g, "");
}