import { readdir, readFile } from "node:fs/promises";
import { prisma } from "./src/lib/prisma.js";

const BASE = "http://localhost:7766/api/v1/auth";

async function call(label: string, method: string, path: string, opts: { body?: unknown; token?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const start = performance.now();
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const ms = Math.round(performance.now() - start);
  const json = await res.json();
  console.log(`${res.status} | ${ms} ms | ${label}\n      ${JSON.stringify(json).slice(0, 130)}`);
  return json.data;
}

// Lit le dernier email envoyé à cette adresse et en extrait le token
async function lastResetToken(email: string): Promise<string> {
  await new Promise((resolve) => setTimeout(resolve, 500)); // laisse le travail d'arrière-plan finir
  const files = (await readdir("mail-outbox")).sort().reverse();
  for (const file of files) {
    const content = await readFile(`mail-outbox/${file}`, "utf8");
    if (content.includes(`To: ${email}`)) {
      return content.match(/Reset token: (\S+)/)![1];
    }
  }
  throw new Error("Aucun email trouvé");
}

await prisma.rateLimit.deleteMany();

const email = `erin-${Date.now()}@example.com`;
const pw1 = `Test-${crypto.randomUUID()}`;
const pw2 = `Test-${crypto.randomUUID()}`;
const pw3 = `Test-${crypto.randomUUID()}`;

await call("register (201)", "POST", "/register", { body: { email, password: pw1 } });
const sessionA = await call("login → session A (200)", "POST", "/login", { body: { email, password: pw1 } });

console.log("\n--- FORGOT : même réponse, que le compte existe ou non ---");
await call("forgot email EXISTANT (200)", "POST", "/password/forgot", { body: { email } });
await call("forgot email INCONNU (200)", "POST", "/password/forgot", { body: { email: "nobody-" + email } });

console.log("\n--- RESET ---");
const token = await lastResetToken(email);
console.log("      (token lu dans mail-outbox, longueur :", token.length, ")");
await call("reset avec un faux token (400)", "POST", "/password/reset", { body: { token: "faux", newPassword: pw2 } });
await call("reset avec un mot de passe trop court (400)", "POST", "/password/reset", { body: { token, newPassword: "short" } });
await call("reset avec un mot de passe compromis (400)", "POST", "/password/reset", { body: { token, newPassword: "password1234" } });
await call("reset valide, MÊME token (200)", "POST", "/password/reset", { body: { token, newPassword: pw2 } });
await call("RÉUTILISER le même token (400)", "POST", "/password/reset", { body: { token, newPassword: pw3 } });

console.log("\n--- Après le reset : toutes les sessions sont révoquées ---");
await call("/me avec la session A (401)", "GET", "/me", { token: sessionA.accessToken });
await call("refresh de la session A (401)", "POST", "/refresh", { body: { refreshToken: sessionA.refreshToken } });
await call("login avec l'ANCIEN mot de passe (401)", "POST", "/login", { body: { email, password: pw1 } });
const sessionB = await call("login avec le NOUVEAU mot de passe (200)", "POST", "/login", { body: { email, password: pw2 } });

console.log("\n--- CHANGE ---");
await call("forgot (pour obtenir un lien qui sera invalidé)", "POST", "/password/forgot", { body: { email } });
const pendingToken = await lastResetToken(email);
await call("change sans token (401)", "POST", "/password/change", { body: { currentPassword: pw2, newPassword: pw3 } });
await call("change avec un mauvais mot de passe actuel (401)", "POST", "/password/change", { token: sessionB.accessToken, body: { currentPassword: "wrong password!!", newPassword: pw3 } });
const sessionC = await call("change valide (200, nouveaux tokens)", "POST", "/password/change", { token: sessionB.accessToken, body: { currentPassword: pw2, newPassword: pw3 } });
await call("/me avec l'ANCIENNE session B (401)", "GET", "/me", { token: sessionB.accessToken });
await call("/me avec la NOUVELLE session C (200)", "GET", "/me", { token: sessionC.accessToken });
await call("lien de reset demandé AVANT le change (400)", "POST", "/password/reset", { body: { token: pendingToken, newPassword: pw1 } });

await prisma.rateLimit.deleteMany();
await prisma.$disconnect();