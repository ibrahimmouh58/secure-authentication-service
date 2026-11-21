import "dotenv/config";
import { z } from "zod";

// Une clé publique Ed25519 au format JWK, avec son identifiant
const publicJwkSchema = z.object({
  kty: z.literal("OKP"),
  crv: z.literal("Ed25519"),
  x: z.string().min(1),
  kid: z.string().min(1),
});

// La clé privée : les mêmes champs + "d" (la partie secrète)
const privateJwkSchema = publicJwkSchema.extend({
  d: z.string().min(1),
});

// Lit une variable qui contient du JSON, puis vérifie sa forme
function jsonEnv<T extends z.ZodType>(schema: T) {
  return z
    .string()
    .transform((value, ctx) => {
      try {
        return JSON.parse(value) as unknown;
      } catch {
        ctx.addIssue({ code: "custom", message: "Invalid JSON" });
        return z.NEVER;
      }
    })
    .pipe(schema);
}

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(7766),
  DATABASE_URL: z.string().min(1),
  CORS_ORIGINS: z.string().min(1),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).default(0),

  JWT_ISSUER: z.string().min(1),
  JWT_AUDIENCE: z.string().min(1),
  JWT_PRIVATE_KEY: jsonEnv(privateJwkSchema),
  JWT_PUBLIC_KEYS: jsonEnv(z.array(publicJwkSchema).min(1)),

  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(1209600),
  SESSION_MAX_AGE_SECONDS: z.coerce.number().int().positive().default(2592000),

  MFA_ENCRYPTION_KEY: z
    .string()
    .refine((value) => Buffer.from(value, "base64").length === 32, {
      message: "Must be 32 bytes, base64-encoded",
    }),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const names = parsed.error.issues.map((issue) => issue.path.join("."));
  console.error(`Invalid or missing environment variables: ${[...new Set(names)].join(", ")}`);
  process.exit(1);
}

const data = parsed.data;

// La clé publique de la clé active doit faire partie de la liste
const activeKid = data.JWT_PRIVATE_KEY.kid;
if (!data.JWT_PUBLIC_KEYS.some((key) => key.kid === activeKid)) {
  console.error("JWT_PUBLIC_KEYS must contain the public key of JWT_PRIVATE_KEY (same kid)");
  process.exit(1);
}

export const env = {
  ...data,
  CORS_ORIGINS: data.CORS_ORIGINS.split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0),
};