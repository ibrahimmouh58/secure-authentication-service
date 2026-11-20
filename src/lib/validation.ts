import { z } from "zod";
import { AppError } from "./errors.js";

export function parseBody<T extends z.ZodType>(schema: T, body: unknown): z.infer<T> {
  const result = schema.safeParse(body);

  if (!result.success) {
    throw new AppError(400, "BAD_REQUEST", "Invalid request body");
  }

  return result.data;
}