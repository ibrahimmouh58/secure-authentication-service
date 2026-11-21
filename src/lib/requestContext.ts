import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { RequestHandler } from "express";

export type RequestContext = {
  requestId: string;
  ipAddress?: string;
  userAgent?: string;
};

const storage = new AsyncLocalStorage<RequestContext>();

export function getRequestContext(): RequestContext | undefined {
  return storage.getStore();
}

export const requestContext: RequestHandler = (req, res, next) => {
  const requestId = randomUUID();
  res.setHeader("X-Request-Id", requestId);

  storage.run(
    {
      requestId,
      ipAddress: req.ip,
      userAgent: req.get("user-agent")?.slice(0, 512),
    },
    next,
  );
};