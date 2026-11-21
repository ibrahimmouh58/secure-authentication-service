import { execSync } from "node:child_process";
import pg from "pg";

export default async function setup(): Promise<void> {
  const testUrl = new URL(process.env.DATABASE_URL!);
  const databaseName = testUrl.pathname.slice(1);

  if (!/^[A-Za-z0-9_]+$/.test(databaseName)) {
    throw new Error(`Unexpected test database name: ${databaseName}`);
  }

  // On se connecte à la base système "postgres" pour pouvoir créer la base de test
  const adminUrl = new URL(testUrl);
  adminUrl.pathname = "/postgres";
  adminUrl.search = "";

  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  const existing = await client.query("SELECT 1 FROM pg_database WHERE datname = $1", [databaseName]);
  if (existing.rowCount === 0) {
    await client.query(`CREATE DATABASE "${databaseName}"`);
  }
  await client.end();

  // Applique toutes les migrations sur la base de test
  execSync("npx prisma migrate deploy", {
    stdio: "inherit",
    env: { ...process.env, DATABASE_URL: testUrl.toString() },
  });
}