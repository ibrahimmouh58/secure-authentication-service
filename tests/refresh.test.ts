import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { prisma } from "../src/lib/prisma.js";
import { api, createUser, login } from "./helpers.js";

// Pourquoi ces tests : le PDF exige explicitement la rotation, l'usage unique,
// le stockage haché et la révocation de toute la famille en cas de rejeu.
// Un vol de refresh token donne un accès de longue durée : c'est le pire cas.

const refresh = (refreshToken: string) => api().post("/api/v1/auth/refresh").send({ refreshToken });
const me = (accessToken: string) => api().get("/api/v1/auth/me").set("Authorization", `Bearer ${accessToken}`);

describe("refresh token rotation", () => {
  it("issues a new pair and makes the previous refresh token single-use", async () => {
    const user = await createUser("rotate");
    const first = await login(user.email, user.password);

    const rotated = await refresh(first.refreshToken);
    expect(rotated.status).toBe(200);
    expect(rotated.body.data.refreshToken).not.toBe(first.refreshToken);
    expect((await me(rotated.body.data.accessToken)).status).toBe(200);
  });

  it("revokes the WHOLE family when a rotated token is replayed", async () => {
    const user = await createUser("replay");
    const tokenA = await login(user.email, user.password);
    const tokenB = (await refresh(tokenA.refreshToken)).body.data;
    const tokenC = (await refresh(tokenB.refreshToken)).body.data;

    // Un attaquant rejoue le token A, déjà échangé
    expect((await refresh(tokenA.refreshToken)).status).toBe(401);

    // Le token le plus récent (C), jamais utilisé, est lui aussi révoqué…
    expect((await refresh(tokenC.refreshToken)).status).toBe(401);
    // …et son access token est refusé immédiatement
    expect((await me(tokenC.accessToken)).status).toBe(401);
  });

  it("detects reuse even when the same token is sent twice concurrently", async () => {
    const user = await createUser("race");
    const { refreshToken } = await login(user.email, user.password);

    const results = await Promise.all([refresh(refreshToken), refresh(refreshToken)]);
    const statuses = results.map((r) => r.status).sort();

    // Au plus une requête gagne : jamais deux nouvelles paires pour un même token
    expect(statuses.filter((s) => s === 200).length).toBeLessThanOrEqual(1);
  });

  it("stores only a SHA-256 hash of refresh tokens, never the token itself", async () => {
    const user = await createUser("hashed");
    const { refreshToken } = await login(user.email, user.password);

    const expectedHash = createHash("sha256").update(refreshToken).digest("hex");
    const stored = await prisma.refreshToken.findMany({
      where: { session: { userId: user.id } },
      select: { tokenHash: true },
    });

    expect(stored.map((t) => t.tokenHash)).toContain(expectedHash);
    expect(JSON.stringify(stored)).not.toContain(refreshToken);
  });

  it("rejects unknown refresh tokens and malformed bodies", async () => {
    expect((await refresh("not-a-real-token")).status).toBe(401);
    expect((await api().post("/api/v1/auth/refresh").send({})).status).toBe(400);
  });
});