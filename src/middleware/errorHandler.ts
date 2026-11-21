import type { ErrorRequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { fail } from "../lib/response.js";

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

  console.error("Unhandled error:", err instanceof Error ? err.stack : "unknown error");
  fail(res, 500, "INTERNAL_ERROR", "An unexpected error occurred");
};