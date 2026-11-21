import { describe, expect, it } from "vitest";
import { importJWK, SignJWT, UnsecuredJWT } from "jose";
import { env } from "../src/lib/env.js";
import { signAccessToken, verifyAccessToken } from "../src/lib/jwt.js";

// Pourquoi ces tests : si l'une de ces vérifications régressait,
// n'importe qui pourrait fabriquer un access token valide pour n'importe quel utilisateur.

const kid = env.JWT_PRIVATE_KEY.kid;
const privateKey = await importJWK(env.JWT_PRIVATE_KEY, "EdDSA");
const nowSeconds = () => Math.floor(Date.now() / 1000);

function validClaims(builder: SignJWT): SignJWT {
  return builder
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setSubject("user-1")
    .setJti("jti-1")
    .setIssuedAt();
}

async function expectRejected(token: string) {
  await expect(verifyAccessToken(token)).rejects.toMatchObject({ status: 401 });
}

describe("access token verification", () => {
  it("accepts a token it issued, with the expected claims", async () => {
    const token = await signAccessToken("user-1", "session-1");
    await expect(verifyAccessToken(token)).resolves.toMatchObject({
      userId: "user-1",
      sessionId: "session-1",
    });
  });

  it("rejects an unsigned token (alg: none)", async () => {
    const token = new UnsecuredJWT({ sid: "session-1" })
      .setIssuer(env.JWT_ISSUER)
      .setAudience(env.JWT_AUDIENCE)
      .setSubject("user-1")
      .setJti("jti-1")
      .setIssuedAt()
      .setExpirationTime("15m")
      .encode();
    await expectRejected(token);
  });

  it("rejects a symmetric HS256 token (algorithm confusion)", async () => {
    const token = await validClaims(new SignJWT({ sid: "session-1" }))
      .setProtectedHeader({ alg: "HS256", kid, typ: "at+jwt" })
      .setExpirationTime("15m")
      .sign(new TextEncoder().encode("attacker-chosen-secret-of-32-bytes!"));
    await expectRejected(token);
  });

  it("rejects a token whose signature was tampered with", async () => {
    const token = await signAccessToken("user-1", "session-1");
    const [header, payload] = token.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(payload, "base64url").toString()), sub: "admin-id" }),
    ).toString("base64url");
    await expectRejected(`${header}.${forgedPayload}.${token.split(".")[2]}`);
  });

  it("rejects a token for another audience, even if correctly signed", async () => {
    const token = await new SignJWT({ sid: "session-1" })
      .setProtectedHeader({ alg: "EdDSA", kid, typ: "at+jwt" })
      .setIssuer(env.JWT_ISSUER)
      .setAudience("another-service")
      .setSubject("user-1")
      .setJti("jti-1")
      .setIssuedAt()
      .setExpirationTime("15m")
      .sign(privateKey);
    await expectRejected(token);
  });

  it("rejects an expired token", async () => {
    const token = await new SignJWT({ sid: "session-1" })
      .setProtectedHeader({ alg: "EdDSA", kid, typ: "at+jwt" })
      .setIssuer(env.JWT_ISSUER)
      .setAudience(env.JWT_AUDIENCE)
      .setSubject("user-1")
      .setJti("jti-1")
      .setIssuedAt(nowSeconds() - 3600)
      .setExpirationTime(nowSeconds() - 60)
      .sign(privateKey);
    await expectRejected(token);
  });

  it("rejects a token without exp (would never expire)", async () => {
    const token = await validClaims(new SignJWT({ sid: "session-1" }))
      .setProtectedHeader({ alg: "EdDSA", kid, typ: "at+jwt" })
      .sign(privateKey);
    await expectRejected(token);
  });

  it("rejects a token signed with an unknown kid", async () => {
    const token = await validClaims(new SignJWT({ sid: "session-1" }))
      .setProtectedHeader({ alg: "EdDSA", kid: "unknown-kid", typ: "at+jwt" })
      .setExpirationTime("15m")
      .sign(privateKey);
    await expectRejected(token);
  });

  it("rejects a JWT that is not an access token (wrong typ)", async () => {
    const token = await validClaims(new SignJWT({ sid: "session-1" }))
      .setProtectedHeader({ alg: "EdDSA", kid, typ: "JWT" })
      .setExpirationTime("15m")
      .sign(privateKey);
    await expectRejected(token);
  });
});