import type { RequestHandler } from "express";
import { AppError } from "../lib/errors.js";
import { audit } from "../services/audit.service.js";
import { getAuth } from "./requireAuth.js";

type Role = "USER" | "ADMIN";

export function requireRole(...allowedRoles: Role[]): RequestHandler {
  return async (req, _res, next) => {
    const auth = getAuth(req);

    if (!allowedRoles.includes(auth.role)) {
      // AUDIT
      await audit({
        event: "authz.access",
        outcome: "FAILURE",
        reason: "insufficient_role",
        userId: auth.userId,
        metadata: { path: req.baseUrl + req.path, requiredRoles: allowedRoles.join(","), actualRole: auth.role },
      });
      throw new AppError(403, "FORBIDDEN", "You do not have permission to access this resource");
    }

    next();
  };
}