import type { Request } from "express";
import type { ClientInfo } from "../services/session.service.js";

export function getClientInfo(req: Request): ClientInfo {
  return {
    ipAddress: req.ip,
    userAgent: req.get("user-agent")?.slice(0, 512),
  };
}