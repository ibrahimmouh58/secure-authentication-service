import { describe, expect, it } from "vitest";
import { env } from "../src/lib/env.js";
import { api } from "./helpers.js";

// Pourquoi ces tests : ce sont des propriétés transversales que n'importe quelle
// modification pourrait casser sans qu'aucun test fonctionnel ne s'en aperçoive :
// fuite d'informations dans les erreurs, en-têtes de sécurité, CORS.

describe("error responses", () => {
  it("returns 400 in the envelope for malformed JSON, without leaking internals", async () => {
    const res = await api()
      .post("/api/v1/auth/login")
      .set("Content-Type", "application/json")
      .send("{ this is not json");

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ success: false, error: { code: "BAD_REQUEST", message: expect.any(String) } });
    expect(res.text).not.toMatch(/node_modules|at \w+ \(|SyntaxError/);
  });

  it("rejects oversized bodies", async () => {
    const res = await api()
      .post("/api/v1/auth/login")
      .send({ email: "a@example.com", password: "x".repeat(20_000) });
    expect(res.status).toBe(413);
  });

  it("uses the envelope for every error status", async () => {
    const responses = [
      await api().post("/api/v1/auth/register").send({}), // 400
      await api().get("/api/v1/auth/me"), // 401
      await api().post("/api/v1/auth/register").send({ email: "x@example.com", password: "a-long-password-1", role: "ADMIN" }), // 403
    ];
    for (const res of responses) {
      expect(res.body).toEqual({
        success: false,
        error: { code: expect.any(String), message: expect.any(String) },
      });
    }
  });
});

describe("security headers", () => {
  it("sends strict API security headers and no framework fingerprint", async () => {
    const res = await api().get("/health");

    expect(res.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });

  it("gives every request its own server-generated request id", async () => {
    const first = await api().get("/health").set("X-Request-Id", "attacker-controlled");
    const second = await api().get("/health");

    expect(first.headers["x-request-id"]).not.toBe("attacker-controlled");
    expect(first.headers["x-request-id"]).not.toBe(second.headers["x-request-id"]);
  });
});

describe("CORS", () => {
  it("reflects only allow-listed origins and never uses a wildcard", async () => {
    const allowedOrigin = env.CORS_ORIGINS[0];

    const allowed = await api().get("/health").set("Origin", allowedOrigin);
    const denied = await api().get("/health").set("Origin", "https://evil.example");

    expect(allowed.headers["access-control-allow-origin"]).toBe(allowedOrigin);
    expect(denied.headers["access-control-allow-origin"]).toBeUndefined();
  });
});