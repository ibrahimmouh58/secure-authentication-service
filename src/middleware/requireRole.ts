import type { RequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { getAuth } from "./requireAuth.js";

type Role = "USER" | "ADMIN";

export function requireRole(...allowedRoles: Role[]): RequestHandler {
  return (req, _res, next) => {
    const auth = getAuth(req);

    if (!allowedRoles.includes(auth.role)) {
      throw new AppError(403, "FORBIDDEN", "You do not have permission to access this resource");
    }

    next();
  };
}