import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(7766),
  DATABASE_URL: z.string().min(1),
  CORS_ORIGINS: z.string().min(1),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const names = parsed.error.issues.map((issue) => issue.path.join("."));
  console.error(`Invalid or missing environment variables: ${names.join(", ")}`);
  process.exit(1);
}

export const env = {
  ...parsed.data,
  CORS_ORIGINS: parsed.data.CORS_ORIGINS.split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0),
};