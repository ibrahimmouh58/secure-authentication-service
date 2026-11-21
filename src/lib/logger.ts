import { pino } from "pino";
import { env } from "./env.js";

// Tout champ portant l'un de ces noms est masqué, où qu'il se trouve dans l'objet loggé
const SENSITIVE_KEYS = [
  "password",
  "newPassword",
  "currentPassword",
  "passwordHash",
  "token",
  "accessToken",
  "refreshToken",
  "mfaToken",
  "code",
  "recoveryCode",
  "secret",
  "secretEncrypted",
  "authorization",
  "cookie",
];

export const logger = pino({
  level: env.LOG_LEVEL,
  base: { service: "secure-auth-service" },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: SENSITIVE_KEYS.flatMap((key) => [key, `*.${key}`, `*.*.${key}`]),
    censor: "[REDACTED]",
  },
});