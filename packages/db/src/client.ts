import { PrismaPg } from "@prisma/adapter-pg";

export { Prisma } from "../prisma/generated/client";

import { PrismaClient } from "../prisma/generated/client";

/**
 * Session parameters sent in every connection's startup packet. DateTime
 * columns are UTC `timestamp`s and the pg adapter reads a `timestamptz` by
 * replacing (not converting) the session offset, so every session runs in
 * UTC whatever the server, database or role default is. That also covers SQL
 * the application does not write itself (committed migration triggers
 * stamping `clock_timestamp()`). Startup options win
 * over `ALTER DATABASE`/`ALTER ROLE` defaults. A connection pooler must pass
 * the `options` startup parameter through (PgBouncer rejects it unless it is
 * listed in `ignore_startup_parameters`, which drops it).
 */
export const DATABASE_SESSION_OPTIONS = "-c TimeZone=UTC";

/**
 * node-postgres lets an `options=` query parameter in the connection string
 * REPLACE a separately supplied `options`, so an unrelated
 * `options=-c statement_timeout=5000` would silently restore a non-UTC
 * default. Merge instead: keep the URL's options and append the UTC setting
 * last, so it also wins over a conflicting `-c TimeZone=…` (PostgreSQL applies
 * repeated `-c` settings in order). A string that is not a URL carries no
 * query parameters, so the option is passed alongside it.
 */
export function utcConnectionConfig(connectionString: string): {
  connectionString: string;
  options?: string;
} {
  let url: URL;
  try {
    url = new URL(connectionString);
  } catch {
    return { connectionString, options: DATABASE_SESSION_OPTIONS };
  }
  const existing = url.searchParams.get("options")?.trim();
  url.searchParams.set(
    "options",
    existing ? `${existing} ${DATABASE_SESSION_OPTIONS}` : DATABASE_SESSION_OPTIONS,
  );
  return { connectionString: url.toString() };
}

/** The one PrismaClient construction (adapter and options). Production and the
 * PostgreSQL test harness both call this, so tests exercise the same driver. */
export function createPrismaClient(options: { connectionString: string; max: number }) {
  const adapter = new PrismaPg({
    ...utcConnectionConfig(options.connectionString),
    max: options.max,
  });
  return new PrismaClient({ adapter });
}
