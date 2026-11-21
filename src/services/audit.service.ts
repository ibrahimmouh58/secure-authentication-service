import { prisma } from "../lib/prisma.js";
import { logger } from "../lib/logger.js";
import { getRequestContext } from "../lib/requestContext.js";

export type AuditEvent =
  | "auth.register"
  | "auth.login"
  | "auth.refresh"
  | "auth.logout"
  | "auth.logout_all"
  | "auth.token"
  | "auth.account_lock"
  | "auth.password.forgot"
  | "auth.password.reset"
  | "auth.password.change"
  | "mfa.enroll"
  | "mfa.confirm"
  | "mfa.verify"
  | "authz.access"
  | "rate_limit";

export type AuditEntry = {
  event: AuditEvent;
  outcome: "SUCCESS" | "FAILURE";
  reason?: string;
  userId?: string | null;
  metadata?: Record<string, string | number | boolean | null>;
};

export async function audit(entry: AuditEntry): Promise<void> {
  const context = getRequestContext();

  // 1. Une copie structurée dans les logs (alertes en temps réel)
  logger.info(
    {
      audit: {
        event: entry.event,
        outcome: entry.outcome,
        reason: entry.reason,
        userId: entry.userId ?? null,
        requestId: context?.requestId,
        ip: context?.ipAddress,
        ...entry.metadata,
      },
    },
    "audit event",
  );

  // 2. L'enregistrement durable en base (enquête)
  try {
    await prisma.auditLog.create({
      data: {
        event: entry.event,
        outcome: entry.outcome,
        reason: entry.reason,
        userId: entry.userId ?? null,
        ipAddress: context?.ipAddress,
        userAgent: context?.userAgent,
        metadata: { requestId: context?.requestId ?? null, ...entry.metadata },
      },
    });
  } catch (error) {
    // Fail open : une panne de l'audit ne bloque pas l'authentification
    logger.error(
      { errorName: error instanceof Error ? error.name : "unknown", event: entry.event },
      "failed to write audit log",
    );
  }
}