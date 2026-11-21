import { Router } from "express";
import { prisma } from "../lib/prisma.js";
import { AppError } from "../lib/errors.js";
import { ok } from "../lib/response.js";
import { parseBody } from "../lib/validation.js";
import { getAuth, requireAuth } from "../middleware/requireAuth.js";
import { requireRole } from "../middleware/requireRole.js";
import { listUsersQuerySchema } from "../schemas/auth.schemas.js";
import { audit } from "../services/audit.service.js";

export const usersRouter = Router();

// Toutes les routes de ce routeur exigent une authentification
usersRouter.use(requireAuth);

// Les seuls champs jamais renvoyés au client (pas de passwordHash, pas d'état de verrouillage)
const publicUserFields = { id: true, email: true, role: true, createdAt: true } as const;

// GET /api/v1/users → 200 (ADMIN uniquement, 403 pour un USER)
usersRouter.get("/", requireRole("ADMIN"), async (req, res) => {
  const auth = getAuth(req);
  const query = parseBody(listUsersQuerySchema, req.query);

  const [users, total] = await prisma.$transaction([
    prisma.user.findMany({
      select: publicUserFields,
      orderBy: { createdAt: "asc" },
      take: query.limit,
      skip: query.offset,
    }),
    prisma.user.count(),
  ]);

  // AUDIT : un admin a consulté la liste des utilisateurs
  await audit({
    event: "authz.access",
    outcome: "SUCCESS",
    reason: "admin_list_users",
    userId: auth.userId,
    metadata: { returned: users.length },
  });

  ok(res, { users, total, limit: query.limit, offset: query.offset });
});

// GET /api/v1/users/:id → 200 (soi-même, ou un ADMIN)
usersRouter.get("/:id", async (req, res) => {
  const auth = getAuth(req);
  const { id } = req.params;

  // Contrôle au niveau de l'OBJET, fait AVANT toute lecture en base
  if (auth.role !== "ADMIN" && auth.userId !== id) {
    // AUDIT : tentative d'accès à l'objet d'un autre utilisateur (BOLA)
    await audit({
      event: "authz.access",
      outcome: "FAILURE",
      reason: "not_resource_owner",
      userId: auth.userId,
      metadata: { targetUserId: id.slice(0, 64) },
    });
    throw new AppError(403, "FORBIDDEN", "You do not have permission to access this resource");
  }

  const user = await prisma.user.findUnique({ where: { id }, select: publicUserFields });
  if (!user) {
    throw new AppError(404, "NOT_FOUND", "User not found");
  }

  ok(res, user);
});