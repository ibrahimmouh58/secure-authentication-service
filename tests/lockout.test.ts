import { describe, expect, it } from "vitest";
import { prisma } from "../src/lib/prisma.js";
import { api, createUser, uniqueEmail } from "./helpers.js";

// Pourquoi ces tests : le verrouillage et la limite de débit sont la défense contre
// la force brute. Mal réglés, ils deviennent soit inutiles (contournables), soit une arme
// (bloquer le compte de quelqu'un d'autre), soit un oracle d'énumération.

const WRONG_PASSWORD = "definitely-wrong-password";
const attemptLogin = (email: string, password: string, headers: Record<string, string> = {}) =>
  api().post("/api/v1/auth/login").set(headers).send({ email, password });

async function failLogins(email: string, times: number) {
  for (let i = 0; i < times; i++) {
    expect((await attemptLogin(email, WRONG_PASSWORD)).status).toBe(401);
  }
}

describe("account lockout", () => {
  it("locks after 5 consecutive failures and then refuses even the correct password", async () => {
    const user = await createUser("lock");
    await failLogins(user.email, 5);

    const stored = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(stored.lockedUntil!.getTime()).toBeGreaterThan(Date.now());

    const withCorrectPassword = await attemptLogin(user.email, user.password);
    const withWrongPassword = await attemptLogin(user.email, WRONG_PASSWORD);
    expect(withCorrectPassword.status).toBe(401);
    // Le verrou n'est pas révélé : même réponse qu'un mauvais mot de passe
    expect(withCorrectPassword.body).toEqual(withWrongPassword.body);
  });

  it("does not extend the lock while it is active (the lockout is not a DoS amplifier)", async () => {
    const user = await createUser("no-extend");
    await failLogins(user.email, 5);
    const before = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });

    await failLogins(user.email, 3);
    const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });

    expect(after.lockedUntil).toEqual(before.lockedUntil);
    expect(after.failedLoginCount).toBe(before.failedLoginCount);
  });

  it("backs off exponentially once a lock has expired", async () => {
    const user = await createUser("backoff");
    await failLogins(user.email, 5);
    await prisma.user.update({ where: { id: user.id }, data: { lockedUntil: new Date(Date.now() - 1000) } });

    await failLogins(user.email, 1);
    const stored = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    const lockSeconds = (stored.lockedUntil!.getTime() - Date.now()) / 1000;

    // 6e échec : 60 s × 2 = environ 120 s
    expect(lockSeconds).toBeGreaterThan(100);
    expect(lockSeconds).toBeLessThanOrEqual(120);
  });

  it("clears the failure counter after a successful login", async () => {
    const user = await createUser("clear");
    await failLogins(user.email, 3);

    expect((await attemptLogin(user.email, user.password)).status).toBe(200);
    const stored = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(stored.failedLoginCount).toBe(0);
    expect(stored.lockedUntil).toBeNull();
  });
});

describe("rate limiting", () => {
  it("returns 429 with Retry-After after 10 login attempts on one account", async () => {
    const user = await createUser("throttle");
    await failLogins(user.email, 10);

    const res = await attemptLogin(user.email, WRONG_PASSWORD);
    expect(res.status).toBe(429);
    expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("throttles an unknown email exactly like an existing one (no enumeration)", async () => {
    const existing = await createUser("throttle-real");
    const ghost = uniqueEmail("throttle-ghost");

    await failLogins(existing.email, 10);
    await failLogins(ghost, 10);

    const forExisting = await attemptLogin(existing.email, WRONG_PASSWORD);
    const forGhost = await attemptLogin(ghost, WRONG_PASSWORD);
    expect(forExisting.status).toBe(429);
    expect(forGhost.status).toBe(429);
    expect(forGhost.body).toEqual(forExisting.body);
  });

  it("limits a single IP across many different emails (password spraying)", async () => {
    for (let i = 0; i < 50; i++) {
      expect((await attemptLogin(uniqueEmail(`spray-${i}`), WRONG_PASSWORD)).status).toBe(401);
    }
    expect((await attemptLogin(uniqueEmail("spray-51"), WRONG_PASSWORD)).status).toBe(429);
  });

  it("ignores a spoofed X-Forwarded-For header", async () => {
    for (let i = 0; i < 50; i++) {
      await attemptLogin(uniqueEmail(`spoof-${i}`), WRONG_PASSWORD);
    }
    const spoofed = await attemptLogin(uniqueEmail("spoof-x"), WRONG_PASSWORD, { "X-Forwarded-For": "203.0.113.7" });
    expect(spoofed.status).toBe(429);
  });
});