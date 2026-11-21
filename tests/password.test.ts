import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { prisma } from "../src/lib/prisma.js";
import { api, createUser, login, strongPassword, uniqueEmail } from "./helpers.js";

// Pourquoi ces tests : le reset de mot de passe contourne l'authentification par conception.
// S'il fuit l'existence des comptes, si un token peut servir deux fois, ou si un changement
// laisse des sessions ouvertes, c'est une prise de contrôle de compte.

const forgot = (email: string) => api().post("/api/v1/auth/password/forgot").send({ email });
const reset = (token: string, newPassword: string) =>
  api().post("/api/v1/auth/password/reset").send({ token, newPassword });
const me = (accessToken: string) => api().get("/api/v1/auth/me").set("Authorization", `Bearer ${accessToken}`);

// Joue le rôle de l'utilisateur qui ouvre sa boîte mail (la boîte d'envoi locale)
async function waitForResetToken(email: string, notThisOne?: string): Promise<string> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const files = (await readdir("mail-outbox").catch(() => [] as string[])).sort().reverse();
    for (const file of files) {
      const content = await readFile(join("mail-outbox", file), "utf8");
      if (content.includes(`To: ${email}`)) {
        const token = content.match(/Reset token: (\S+)/)?.[1];
        if (token && token !== notThisOne) {
          return token;
        }
        break; // le plus récent pour cet email n'est pas encore le nouveau
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`No reset email found for ${email}`);
}

describe("password forgot", () => {
  it("answers identically whether or not the account exists", async () => {
    const user = await createUser("forgot");
    const existing = await forgot(user.email);
    const unknown = await forgot(uniqueEmail("forgot-ghost"));

    expect(existing.status).toBe(200);
    expect(unknown.status).toBe(200);
    expect(unknown.body).toEqual(existing.body);
  });
});

describe("password reset", () => {
  it("uses a hashed, single-use token and revokes every existing session", async () => {
    const user = await createUser("reset");
    const session = await login(user.email, user.password);
    await forgot(user.email);
    const token = await waitForResetToken(user.email);

    // Stocké haché, jamais en clair
    const stored = await prisma.passwordResetToken.findMany({ where: { userId: user.id } });
    expect(stored.map((t) => t.tokenHash)).toContain(createHash("sha256").update(token).digest("hex"));

    const newPassword = strongPassword();
    expect((await reset(token, newPassword)).status).toBe(200);

    // Usage unique
    expect((await reset(token, strongPassword())).status).toBe(400);
    // Toutes les sessions d'avant sont mortes
    expect((await me(session.accessToken)).status).toBe(401);
    expect((await api().post("/api/v1/auth/refresh").send({ refreshToken: session.refreshToken })).status).toBe(401);
    // Ancien mot de passe refusé, nouveau accepté
    expect((await api().post("/api/v1/auth/login").send({ email: user.email, password: user.password })).status).toBe(401);
    await login(user.email, newPassword);
  });

  it("does not burn the token when the new password is rejected", async () => {
    const user = await createUser("reset-retry");
    await forgot(user.email);
    const token = await waitForResetToken(user.email);

    expect((await reset(token, "too-short")).status).toBe(400);
    expect((await reset(token, strongPassword())).status).toBe(200);
  });
});

describe("password change", () => {
  it("requires the current password", async () => {
    const user = await createUser("change-wrong");
    const { accessToken } = await login(user.email, user.password);

    const res = await api()
      .post("/api/v1/auth/password/change")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ currentPassword: "not-my-password", newPassword: strongPassword() });
    expect(res.status).toBe(401);
  });

  it("revokes every existing session and invalidates pending reset tokens", async () => {
    const user = await createUser("change");
    const sessionA = await login(user.email, user.password);
    const sessionB = await login(user.email, user.password);
    await forgot(user.email);
    const pendingResetToken = await waitForResetToken(user.email);

    const res = await api()
      .post("/api/v1/auth/password/change")
      .set("Authorization", `Bearer ${sessionA.accessToken}`)
      .send({ currentPassword: user.password, newPassword: strongPassword() });
    expect(res.status).toBe(200);

    // Les deux anciennes sessions, y compris celle qui a fait le changement, sont révoquées
    expect((await me(sessionA.accessToken)).status).toBe(401);
    expect((await me(sessionB.accessToken)).status).toBe(401);
    // Les nouveaux tokens renvoyés fonctionnent
    expect((await me(res.body.data.accessToken)).status).toBe(200);
    // Le lien de reset demandé avant le changement ne marche plus
    expect((await reset(pendingResetToken, strongPassword())).status).toBe(400);
  });
});