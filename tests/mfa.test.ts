import { describe, expect, it } from "vitest";
import { prisma } from "../src/lib/prisma.js";
import { base32Decode, generateTotp } from "../src/lib/totp.js";
import { api, createUser, login } from "./helpers.js";

// Pourquoi ces tests : le second facteur n'a de valeur que si un code intercepté
// ne peut pas être rejoué, si les codes de récupération ne servent qu'une fois,
// et si un challenge ne permet pas d'essayer indéfiniment.

const verify = (body: Record<string, unknown>, accessToken?: string) => {
  const req = api().post("/api/v1/auth/mfa/verify");
  if (accessToken) req.set("Authorization", `Bearer ${accessToken}`);
  return req.send(body);
};

async function userWithMfa() {
  const user = await createUser("mfa");
  const { accessToken } = await login(user.email, user.password);

  const enroll = await api().post("/api/v1/auth/mfa/enroll").set("Authorization", `Bearer ${accessToken}`);
  expect(enroll.status).toBe(200);
  const secret = base32Decode(enroll.body.data.secret);
  const recoveryCodes: string[] = enroll.body.data.recoveryCodes;

  const confirmCode = generateTotp(secret);
  expect((await verify({ code: confirmCode }, accessToken)).status).toBe(200);

  return { ...user, accessToken, secret, recoveryCodes, confirmCode };
}

async function startMfaLogin(email: string, password: string): Promise<string> {
  const res = await api().post("/api/v1/auth/login").send({ email, password });
  expect(res.status).toBe(200);
  expect(res.body.data.mfaRequired).toBe(true);
  expect(res.body.data.accessToken).toBeUndefined();
  return res.body.data.mfaToken;
}

describe("TOTP implementation", () => {
  it("matches the RFC 6238 SHA-1 test vectors", () => {
    const rfcSecret = Buffer.from("12345678901234567890", "ascii");
    expect(generateTotp(rfcSecret, 59_000)).toBe("287082");
    expect(generateTotp(rfcSecret, 1_111_111_109_000)).toBe("081804");
    expect(generateTotp(rfcSecret, 1_234_567_890_000)).toBe("005924");
    expect(generateTotp(rfcSecret, 2_000_000_000_000)).toBe("279037");
  });
});

describe("MFA login", () => {
  it("stores the TOTP secret encrypted, never in clear", async () => {
    const user = await userWithMfa();
    const stored = await prisma.mfaSecret.findUniqueOrThrow({ where: { userId: user.id } });
    expect(stored.secretEncrypted.startsWith("v1:")).toBe(true);
    expect(stored.secretEncrypted).not.toContain(user.secret.toString("base64url"));
  });

  it("requires the second factor once MFA is confirmed", async () => {
    const user = await userWithMfa();
    await startMfaLogin(user.email, user.password);
  });

  it("rejects a replayed TOTP code, even on a new challenge", async () => {
    const user = await userWithMfa();

    // Le code utilisé pour confirmer l'activation ne peut pas resservir
    const challenge1 = await startMfaLogin(user.email, user.password);
    expect((await verify({ mfaToken: challenge1, code: user.confirmCode })).status).toBe(401);

    // Un code neuf (période suivante) est accepté une fois…
    const freshCode = generateTotp(user.secret, Date.now() + 30_000);
    const ok = await verify({ mfaToken: challenge1, code: freshCode });
    expect(ok.status).toBe(200);
    expect(ok.body.data.accessToken).toEqual(expect.any(String));

    // …mais pas deux fois, même sur un nouveau challenge
    const challenge2 = await startMfaLogin(user.email, user.password);
    expect((await verify({ mfaToken: challenge2, code: freshCode })).status).toBe(401);
  });

  it("accepts each recovery code exactly once", async () => {
    const user = await userWithMfa();
    const [code] = user.recoveryCodes;

    const challenge1 = await startMfaLogin(user.email, user.password);
    expect((await verify({ mfaToken: challenge1, recoveryCode: code })).status).toBe(200);

    const challenge2 = await startMfaLogin(user.email, user.password);
    expect((await verify({ mfaToken: challenge2, recoveryCode: code })).status).toBe(401);
  });

  it("burns a challenge after 5 attempts, even if a valid factor comes next", async () => {
    const user = await userWithMfa();
    const challenge = await startMfaLogin(user.email, user.password);

    for (let i = 0; i < 5; i++) {
      expect((await verify({ mfaToken: challenge, code: "000000" })).status).toBe(401);
    }
    expect((await verify({ mfaToken: challenge, recoveryCode: user.recoveryCodes[1] })).status).toBe(401);
  });

  it("refuses to replace an already-enabled MFA secret", async () => {
    const user = await userWithMfa();
    const res = await api().post("/api/v1/auth/mfa/enroll").set("Authorization", `Bearer ${user.accessToken}`);
    expect(res.status).toBe(409);
  });
});