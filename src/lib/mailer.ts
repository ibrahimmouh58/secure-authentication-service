import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { env } from "./env.js";
import { logger } from "./logger.js";

const OUTBOX_DIR = path.resolve("mail-outbox");

export async function sendMail(to: string, subject: string, text: string): Promise<void> {
  if (env.NODE_ENV === "production") {
    // Pas de transport configuré : on n'écrit JAMAIS un token sur le disque en production
        logger.error("no mail transport configured; email not sent");
    return;
  }

  await mkdir(OUTBOX_DIR, { recursive: true });
  const fileName = `${Date.now()}-${randomUUID()}.txt`;
  const content = `To: ${to}\nSubject: ${subject}\n\n${text}\n`;
  await writeFile(path.join(OUTBOX_DIR, fileName), content, { mode: 0o600 });
}