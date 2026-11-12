// Database seed logic.
//
// This file exports `runSeed()` so the CLI (`prisma db seed` →
// prisma/seed.cli.ts) can invoke it. Keep the function idempotent: use
// `upsert` (not `create`) and guard against duplicate rows / unique-constraint
// crashes on re-run. Push a human-readable line into `summary` for each thing
// the seed does — the CLI logs them.
//
// Reuses the shared, adapter-configured Prisma client (one connection, correct
// driver wiring) instead of `new PrismaClient()`. Do NOT call `$disconnect()`
// here — the client is shared with the worker/server process. The CLI wrapper
// (seed.cli.ts) owns disconnect for the standalone `prisma db seed` case.
import prisma from "../src/index";

export type SeedResult = {
  /** One line per thing the seed did, logged by the CLI. */
  summary: string[];
};

export async function runSeed(): Promise<SeedResult> {
  void prisma;
  return { summary: [] };
}
