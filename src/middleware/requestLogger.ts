import type { RequestHandler } from "express";
import { logger } from "../lib/logger.js";
import { getRequestContext } from "../lib/requestContext.js";

export const requestLogger: RequestHandler = (req, res, next) => {
  const start = process.hrtime.bigint();
  const requestId = getRequestContext()?.requestId;

  res.on("finish", () => {
    const durationMs = Math.round(Number(process.hrtime.bigint() - start) / 1_000_000);
    const entry = {
      requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs,
      ip: req.ip,
    };

    if (res.statusCode >= 500) {
      logger.error(entry, "request completed");
    } else {
      logger.info(entry, "request completed");
    }
  });

  next();
};