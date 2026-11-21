import type { ErrorRequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { fail } from "../lib/response.js";
import { logger } from "../lib/logger.js";
import { getRequestContext } from "../lib/requestContext.js";


export const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  if (err instanceof AppError) {
    for (const [name, value] of Object.entries(err.headers)) {
      res.setHeader(name, value);
    }
    fail(res, err.status, err.code, err.message);
    return;
  }

  if (err?.type === "entity.parse.failed") {
    fail(res, 400, "BAD_REQUEST", "Malformed JSON body");
    return;
  }

  if (err?.type === "entity.too.large") {
    fail(res, 413, "PAYLOAD_TOO_LARGE", "Request body too large");
    return;
  }

  logger.error(
    {
      requestId: getRequestContext()?.requestId,
      errorName: err instanceof Error ? err.name : "unknown",
      stack: err instanceof Error ? err.stack?.split("\n").slice(1).join("\n") : undefined,
    },
    "unhandled error",
  );
};