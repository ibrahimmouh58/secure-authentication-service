import express from "express";
import helmet from "helmet";
import { ok, fail } from "./lib/response.js";
import { errorHandler } from "./middleware/errorHandler.js";

export const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

app.get("/health", (_req, res) => {
  ok(res, { status: "ok" });
});

// Toute route inconnue → 404 dans l'enveloppe
app.use((_req, res) => {
  fail(res, 404, "NOT_FOUND", "Route not found");
});

// Gestionnaire d'erreurs : toujours en DERNIER
app.use(errorHandler);