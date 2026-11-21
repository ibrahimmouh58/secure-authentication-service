import "dotenv/config";
import { defineConfig } from "vitest/config";

const baseUrl = process.env.DATABASE_URL;
if (!baseUrl) {
  throw new Error("DATABASE_URL must be set in .env to run the tests");
}

// Même serveur PostgreSQL, base séparée : "auth" → "auth_test"
const testUrl = new URL(baseUrl);
testUrl.pathname = `${testUrl.pathname}_test`;
process.env.DATABASE_URL = testUrl.toString();

export default defineConfig({
  test: {
    environment: "node",
    globalSetup: ["./tests/globalSetup.ts"],
    setupFiles: ["./tests/setup.ts"],
    env: {
      DATABASE_URL: testUrl.toString(),
      NODE_ENV: "test",
      LOG_LEVEL: "silent",
    },
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 60_000,
  },
});