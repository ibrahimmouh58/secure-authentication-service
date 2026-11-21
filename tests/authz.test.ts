import { describe, expect, it } from "vitest";
import { prisma } from "../src/lib/prisma.js";
import { api, createUser, login } from "./helpers.js";

// Pourquoi ces tests : l'autorisation cassée par objet (BOLA) est la faille n°1 des API
// selon l'OWASP. Un contrôle de rôle seul ne suffit pas, et une route oubliée ne doit
// jamais être ouverte par défaut.

const get = (path: string, accessToken?: string) => {
  const req = api().get(path);
  if (accessToken) req.set("Authorization", `Bearer ${accessToken}`);
  return req;
};

async function signedInUser(prefix: string, role: "USER" | "ADMIN" = "USER") {
  const user = await createUser(prefix);
  if (role === "ADMIN") {
    await prisma.user.update({ where: { id: user.id }, data: { role: "ADMIN" } });
  }
  const { accessToken } = await login(user.email, user.password);
  return { ...user, accessToken };
}

describe("deny by default", () => {
  it("requires authentication on unknown routes instead of revealing they don't exist", async () => {
    const user = await signedInUser("deny");
    expect((await get("/api/v1/does-not-exist")).status).toBe(401);
    expect((await get("/api/v1/does-not-exist", user.accessToken)).status).toBe(404);
  });

  it("keeps /health public", async () => {
    expect((await get("/health")).status).toBe(200);
  });
});

describe("GET /users (role check)", () => {
  it("returns 401 without a token and 403 for a USER", async () => {
    const user = await signedInUser("role-user");
    expect((await get("/api/v1/users")).status).toBe(401);
    expect((await get("/api/v1/users", user.accessToken)).status).toBe(403);
  });

  it("lets an ADMIN list users, exposing only safe fields", async () => {
    const admin = await signedInUser("role-admin", "ADMIN");
    const res = await get("/api/v1/users", admin.accessToken);

    expect(res.status).toBe(200);
    for (const listed of res.body.data.users) {
      expect(Object.keys(listed).sort()).toEqual(["createdAt", "email", "id", "role"]);
    }
  });

  it("takes a demotion into account immediately, without waiting for token expiry", async () => {
    const admin = await signedInUser("demoted", "ADMIN");
    expect((await get("/api/v1/users", admin.accessToken)).status).toBe(200);

    await prisma.user.update({ where: { id: admin.id }, data: { role: "USER" } });
    expect((await get("/api/v1/users", admin.accessToken)).status).toBe(403);
  });
});

describe("GET /users/:id (object-level check)", () => {
  it("lets a user read only their own profile", async () => {
    const alice = await signedInUser("alice");
    const bob = await signedInUser("bob");

    expect((await get(`/api/v1/users/${alice.id}`, alice.accessToken)).status).toBe(200);
    expect((await get(`/api/v1/users/${bob.id}`, alice.accessToken)).status).toBe(403);
  });

  it("does not reveal whether another id exists", async () => {
    const alice = await signedInUser("alice-enum");
    const res = await get("/api/v1/users/00000000-0000-0000-0000-000000000000", alice.accessToken);
    expect(res.status).toBe(403);
  });

  it("lets an ADMIN read any profile", async () => {
    const admin = await signedInUser("admin-reader", "ADMIN");
    const alice = await signedInUser("alice-read");
    expect((await get(`/api/v1/users/${alice.id}`, admin.accessToken)).status).toBe(200);
  });
});

describe("session ownership", () => {
  it("logout revokes only the calling session, not the user's other sessions", async () => {
    const user = await createUser("two-sessions");
    const sessionA = await login(user.email, user.password);
    const sessionB = await login(user.email, user.password);

    await api().post("/api/v1/auth/logout").set("Authorization", `Bearer ${sessionA.accessToken}`);

    expect((await get("/api/v1/auth/me", sessionA.accessToken)).status).toBe(401);
    expect((await get("/api/v1/auth/me", sessionB.accessToken)).status).toBe(200);
  });
});