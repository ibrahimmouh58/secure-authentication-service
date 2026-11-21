import request from "supertest";
import { app } from "../src/app.js";

export function api() {
  return request(app);
}

export function uniqueEmail(prefix = "user"): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

export function strongPassword(): string {
  return `Test-${crypto.randomUUID()}`;
}

export async function createUser(prefix = "user") {
  const email = uniqueEmail(prefix);
  const password = strongPassword();
  const res = await api().post("/api/v1/auth/register").send({ email, password });
  if (res.status !== 201) {
    throw new Error(`createUser failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return { id: res.body.data.id as string, email, password };
}

export async function login(email: string, password: string) {
  const res = await api().post("/api/v1/auth/login").send({ email, password });
  if (res.status !== 200) {
    throw new Error(`login failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.data as { accessToken: string; refreshToken: string };
}