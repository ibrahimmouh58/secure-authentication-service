import { prisma } from "../src/lib/prisma.js";
import { hashPassword } from "../src/lib/password.js";
import { generateToken } from "../src/lib/crypto.js";

const email = process.argv[2]?.trim().toLowerCase();

if (!email || !email.includes("@")) {
  console.error("Usage: npm run admin:create -- <email>");
  process.exit(1);
}

const existing = await prisma.user.findUnique({ where: { email } });

if (existing) {
  await prisma.user.update({ where: { email }, data: { role: "ADMIN" } });
  console.log(`Existing user ${email} promoted to ADMIN.`);
} else {
  const temporaryPassword = generateToken(18);
  await prisma.user.create({
    data: { email, passwordHash: await hashPassword(temporaryPassword), role: "ADMIN" },
  });
  console.log(`Admin ${email} created.`);
  console.log(`Temporary password (shown once, change it after first login): ${temporaryPassword}`);
}

await prisma.$disconnect();