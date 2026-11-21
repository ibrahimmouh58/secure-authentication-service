import { afterAll, beforeEach } from "vitest";
import { prisma } from "../src/lib/prisma.js";

// Chaque test part de compteurs de limite de débit vides
beforeEach(async () => {
  await prisma.rateLimit.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});