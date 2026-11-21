import express from "express";
import helmet from "helmet";
import cors from "cors";
import { env } from "./lib/env.js";
import { ok, fail } from "./lib/response.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { authRouter } from "./routes/auth.routes.js";

export const app = express();

app.disable("x-powered-by");

// 1. En-têtes de sécurité
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
      },
    },
    frameguard: { action: "deny" },
  }),
);

app.use((_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// 2. CORS : liste blanche, jamais *
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        callback(null, true);
        return;
      }
      callback(null, env.CORS_ORIGINS.includes(origin));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
    maxAge: 600,
  }),
);

// 3. Lecture du body JSON (limité à 10 ko)
app.use(express.json({ limit: "10kb" }));

// 4. Routes
app.get("/health", (_req, res) => {
  ok(res, { status: "ok" });
});
app.use("/api/v1/auth", authRouter);

// 5. Route inconnue → 404
app.use((_req, res) => {
  fail(res, 404, "NOT_FOUND", "Route not found");
});

// 6. Gestionnaire d'erreurs : toujours en dernier
app.use(errorHandler);