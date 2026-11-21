import { describe, expect, it } from "vitest";
import { prisma } from "../src/lib/prisma.js";
import { api, createUser, login, strongPassword, uniqueEmail } from "./helpers.js";

// Pourquoi ces tests : l'inscription est la porte d'entrée de l'escalade de privilèges,
// et le login est la cible principale de l'énumération de comptes.

describe("register", () => {
  it("never lets a user self-register as ADMIN", async () => {
    const email = uniqueEmail("admin-attempt");
    const res = await api()
      .post("/api/v1/auth/register")
      .send({ email, password: strongPassword(), role: "ADMIN" });

    expect(res.status).toBe(403);
    expect(await prisma.user.findUnique({ where: { email } })).toBeNull();
  });

  it("creates USER accounts and never returns the password hash", async () => {
    const email = uniqueEmail("plain");
    const res = await api().post("/api/v1/auth/register").send({ email, password: strongPassword() });

    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      success: true,
      data: { id: expect.any(String), email, role: "USER" },
    });

    const stored = await prisma.user.findUnique({ where: { email } });
    expect(stored?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it("returns 409 on a duplicate email, regardless of letter case", async () => {
    const user = await createUser("dup");

    const same = await api().post("/api/v1/auth/register").send({ email: user.email, password: strongPassword() });
    const upper = await api()
      .post("/api/v1/auth/register")
      .send({ email: user.email.toUpperCase(), password: strongPassword() });

    expect(same.status).toBe(409);
    expect(upper.status).toBe(409);
  });

  it("rejects passwords shorter than 12 characters", async () => {
    const res = await api().post("/api/v1/auth/register").send({ email: uniqueEmail(), password: "short-pw" });
    expect(res.status).toBe(400);
  });
});

describe("login", () => {
  it("returns an access token and a refresh token for valid credentials", async () => {
    const user = await createUser("login-ok");
    const res = await api().post("/api/v1/auth/login").send({ email: user.email, password: user.password });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      accessToken: expect.any(String),
      refreshToken: expect.any(String),
      tokenType: "Bearer",
    });
  });

  it("gives an unknown email and a wrong password the exact same response (no enumeration)", async () => {
    const user = await createUser("enum");

    const wrongPassword = await api()
      .post("/api/v1/auth/login")
      .send({ email: user.email, password: "definitely-wrong-password" });
    const unknownEmail = await api()
      .post("/api/v1/auth/login")
      .send({ email: uniqueEmail("ghost"), password: "definitely-wrong-password" });

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(unknownEmail.body).toEqual(wrongPassword.body);
  });
});

describe("GET /auth/me", () => {
  it("requires a valid access token", async () => {
    expect((await api().get("/api/v1/auth/me")).status).toBe(401);
    expect((await api().get("/api/v1/auth/me").set("Authorization", "Bearer abc.def.ghi")).status).toBe(401);
  });

  it("returns exactly { id, email, role }", async () => {
    const user = await createUser("me");
    const { accessToken } = await login(user.email, user.password);

    const res = await api().get("/api/v1/auth/me").set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ id: user.id, email: user.email, role: "USER" });
  });
});