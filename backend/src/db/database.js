const { PrismaClient } = require("@prisma/client");

/** Singleton Prisma Client instance. */
let prisma;

/**
 * Returns the shared PrismaClient instance (lazy-initialized).
 */
function getDb() {
  if (!prisma) {
    prisma = new PrismaClient();
  }
  return prisma;
}

/**
 * Connect to the database (call once on startup).
 * With Prisma the schema is managed via `prisma db push` / migrations,
 * so no CREATE TABLE statements are needed at runtime.
 */
async function initDb() {
  const client = getDb();
  await client.$connect();
  console.log("Database connected (Prisma + Neon PostgreSQL)");
}

/**
 * Disconnect Prisma client gracefully.
 */
async function closeDb() {
  if (prisma) {
    await prisma.$disconnect();
    prisma = null;
  }
}

module.exports = { getDb, initDb, closeDb };
