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
 * default. Merge instead: keep the URL's options, then `extra` session
 * settings (for example `-c statement_timeout=2000`), and append the UTC
 * setting last, so it also wins over a conflicting `-c TimeZone=…`
 * (PostgreSQL applies repeated `-c` settings in order). A string that is not
 * a URL carries no query parameters, so the options are passed alongside it.
 */
export function utcConnectionConfig(
  connectionString: string,
  extra?: string,
): {
  connectionString: string;
  options?: string;
} {
  const ours = extra ? `${extra} ${DATABASE_SESSION_OPTIONS}` : DATABASE_SESSION_OPTIONS;
  let url: URL;
  try {
    url = new URL(connectionString);
  } catch {
    return { connectionString, options: ours };
  }
  const existing = url.searchParams.get("options")?.trim();
  url.searchParams.set("options", existing ? `${existing} ${ours}` : ours);
  return { connectionString: url.toString() };
}

/**
 * Optional node-postgres pool settings. They reach `pg.Pool` unchanged: the
 * installed `@prisma/adapter-pg` (7.10.1, `PrismaPgAdapterFactory`) keeps a
 * config object as `this.config` and `connect()` calls `new pg.Pool(this.config)`;
 * pg-pool 3.14 applies `connectionTimeoutMillis` both to waiting for a busy
 * pool's free client (the pending item is removed and fails) and to opening a
 * new connection (the socket is destroyed), `idleTimeoutMillis` to idle
 * clients, and hands the same options to each `pg.Client`, whose
 * `query_timeout` (pg 8.23 `client.js` `readTimeout`) fails a query, BEGIN
 * included, client-side. `statementTimeoutMs` is sent as a startup
 * `-c statement_timeout=…` session setting (merged by `utcConnectionConfig`),
 * so it holds from the first statement of every connection, before any
 * transaction starts.
 */
export type DriverSettings = {
  connectionTimeoutMillis?: number;
  query_timeout?: number;
  idleTimeoutMillis?: number;
  statementTimeoutMs?: number;
};

/** The `pg.Pool` config for one client (the URL options merged, UTC last). */
export function poolConfig(options: {
  connectionString: string;
  max: number;
  driver?: DriverSettings;
}) {
  const { statementTimeoutMs, ...pool } = options.driver ?? {};
  const session =
    statementTimeoutMs === undefined
      ? undefined
      : `-c statement_timeout=${Math.trunc(statementTimeoutMs)}`;
  return {
    ...utcConnectionConfig(options.connectionString, session),
    ...pool,
    max: options.max,
  };
}

/** The one PrismaClient construction (adapter and options). Production and the
 * PostgreSQL test harness both call this, so tests exercise the same driver. */
export function createPrismaClient(options: {
  connectionString: string;
  max: number;
  driver?: DriverSettings;
}) {
  const adapter = new PrismaPg(poolConfig(options));
  return new PrismaClient({ adapter });
}

/**
 * The connect audit's own small pool (wssp-ssh §10), isolated from the
 * shared one so a stalled database can never make audit writes hold, or wait
 * for, connections that relay authorization reads need: at most
 * `CONNECT_AUDIT_POOL.max` connections per server process, a 2 s bound on
 * acquiring or opening one, a 2 s session `statement_timeout`, a 3 s
 * client-side query bound and a short idle timeout.
 */
export const CONNECT_AUDIT_POOL = {
  max: 2,
  driver: {
    connectionTimeoutMillis: 2_000,
    statementTimeoutMs: 2_000,
    query_timeout: 3_000,
    idleTimeoutMillis: 5_000,
  },
} as const satisfies { max: number; driver: DriverSettings };

/** Builds a connect audit client (production: once, lazily, in `index.ts`). */
export function createConnectAuditPrismaClient(connectionString: string) {
  return createPrismaClient({ connectionString, ...CONNECT_AUDIT_POOL });
}
