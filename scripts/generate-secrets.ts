import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";

const date = new Date().toISOString().slice(0, 10);
const kid = `ed25519-${date}-${randomUUID().slice(0, 8)}`;

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const publicJwk = { ...publicKey.export({ format: "jwk" }), kid };
const privateJwk = { ...privateKey.export({ format: "jwk" }), kid };

console.log("# Paste these lines into your .env (replace the existing empty ones)");
console.log(`JWT_PRIVATE_KEY='${JSON.stringify(privateJwk)}'`);
console.log(`JWT_PUBLIC_KEYS='${JSON.stringify([publicJwk])}'`);
console.log(`MFA_ENCRYPTION_KEY=${randomBytes(32).toString("base64")}`);