/**
 * Real-PostgreSQL test harness for `*.pg.test.ts` (run only by `pnpm test:pg`).
 *
 * Isolation: each test file gets its own database, cloned with
 * `CREATE DATABASE … TEMPLATE` from the template that scripts/test-pg.mjs
 * applied through the production migration runner. Files never share rows.
 * When the file finishes, its clone and any `<clone>_<suffix>` database the
 * file created beside it are dropped (`dropFileDatabases`), so the disposable
 * container holds only the databases of the files still running.
 *
 * Clients: `prisma` is built by the production factory (`createPrismaClient`,
 * same adapter and options as `@wssp/db`), then wrapped so a test can pause a
 * named actor's statements. Hand it to production code with
 * `vi.mock("@wssp/db", async () => ({ default: (await pgTestDatabase()).prisma }))`.
 * With no pause registered the wrapper returns Prisma's own promises untouched.
 *
 * Barriers are promises plus real row locks, never sleeps: `pauseAt` parks an
 * actor at a named statement, `waitUntilBlocked` observes PostgreSQL's own
 * lock wait (`pg_stat_activity.wait_event_type = 'Lock'` and
 * `pg_blocking_pids`) for that actor's backend.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { sharedVars } from "@wssp/env/vars/shared";
import { afterAll, afterEach, inject } from "vitest";

import { createPrismaClient } from "../client";

declare module "vitest" {
  export interface ProvidedContext {
    wsspPgAdminUrl: string;
    wsspPgTemplateDb: string;
    wsspPgContainer: string;
  }
}

type RealClient = ReturnType<typeof createPrismaClient>;

/** `"<model>.<method>"` (e.g. `"user.deleteMany"`) or `"sql:<text>"` for raw SQL,
 * with tagged-template holes as `?` and whitespace collapsed. */
export type StatementMatcher = string | RegExp;
export type PausePoint = { before: StatementMatcher } | { after: StatementMatcher };

export type PauseGate = {
  /** Resolves with the matched statement name once the actor is parked there. */
  readonly reached: Promise<string>;
  /** `reached`, but rejects (naming actor and point) if the statement never
   * runs within `timeoutMs`: a missing lock fails the test instead of hanging. */
  waitReached(timeoutMs?: number): Promise<string>;
  /** Lets the parked actor continue. */
  release(): void;
  /** Resumes the actor by throwing `error` from the parked statement (injection). */
  fail(error: Error): void;
};

type PendingPause = {
  actor: string;
  phase: "before" | "after";
  matcher: StatementMatcher;
  consumed: boolean;
  reached: (point: string) => void;
  resume: Promise<void>;
  release: () => void;
};

export type BlockedObservation = {
  waitEventType: string;
  waitEvent: string;
  blockers: number[];
  /** The statement the blocked backend is executing (`pg_stat_activity.query`). */
  query: string;
};

export type PgTestDatabase = {
  /** Database name and URL of this file's clone. */
  readonly name: string;
  readonly url: string;
  /** Instrumented production client; pass it to production code. */
  readonly prisma: RealClient;
  /** Separate, never-paused client for fixtures, assertions and lock inspection. */
  readonly inspect: RealClient;
  /** Runs `work` as `actor`; statements it issues can be paused and observed. */
  run<T>(actor: string, work: () => Promise<T>): Promise<T>;
  /** Parks the next matching statement of `actor` (one-shot). */
  pauseAt(actor: string, point: PausePoint): PauseGate;
  /** Backend pid of `actor`'s most recent transaction, if it began one. */
  backendPid(actor: string): number | undefined;
  /**
   * Resolves once `actor`'s transaction is waiting on a PostgreSQL lock (and,
   * with `by`, one held by that actor's backend). Rejects after `timeoutMs`
   * with the last observed state — a failure, never a pass by timing.
   */
  waitUntilBlocked(
    actor: string,
    options?: { by?: string; timeoutMs?: number },
  ): Promise<BlockedObservation>;
  close(): Promise<void>;
};

const RAW_METHODS = new Set(["$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe"]);

function sqlPoint(args: unknown[]): string {
  const first = args[0];
  const text =
    typeof first === "string"
      ? first
      : Array.isArray(first)
        ? (first as readonly string[]).join("?")
        : String(first);
  return `sql:${text.replace(/\s+/g, " ").trim()}`;
}

function matches(matcher: StatementMatcher, point: string): boolean {
  return typeof matcher === "string" ? matcher === point : matcher.test(point);
}

function isDelegate(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { findFirst?: unknown }).findFirst === "function"
  );
}

class Probe {
  readonly actors = new AsyncLocalStorage<string>();
  readonly pids = new Map<string, number>();
  private readonly pauses: PendingPause[] = [];

  pauseAt(actor: string, point: PausePoint): PauseGate {
    let reached!: (point: string) => void;
    let release!: () => void;
    let fail!: (error: Error) => void;
    const reachedPromise = new Promise<string>((resolve) => {
      reached = resolve;
    });
    const resume = new Promise<void>((resolve, reject) => {
      release = resolve;
      fail = reject;
    });
    // A never-released failure must not surface as an unhandled rejection.
    resume.catch(() => undefined);
    const phase = "before" in point ? "before" : "after";
    const matcher = "before" in point ? point.before : point.after;
    this.pauses.push({
      actor,
      phase,
      matcher,
      consumed: false,
      reached,
      resume,
      release,
    });
    const waitReached = (timeoutMs = 10_000) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const expired = new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Actor "${actor}" never reached ${phase} ${String(matcher)}.`)),
          timeoutMs,
        );
      });
      return Promise.race([reachedPromise, expired]).finally(() => clearTimeout(timer));
    };
    return { reached: reachedPromise, waitReached, release, fail };
  }

  /** Between tests: a pause a failed test never consumed must not capture the
   * next test's statements, and a parked actor is let go. */
  reset(): void {
    for (const pause of this.pauses.splice(0)) {
      pause.consumed = true;
      pause.release();
    }
    this.pids.clear();
  }

  private pending(actor: string | undefined, point: string): boolean {
    return (
      actor !== undefined &&
      this.pauses.some((p) => !p.consumed && p.actor === actor && matches(p.matcher, point))
    );
  }

  private async hit(actor: string, phase: "before" | "after", point: string): Promise<void> {
    const pause = this.pauses.find(
      (p) => !p.consumed && p.actor === actor && p.phase === phase && matches(p.matcher, point),
    );
    if (!pause) return;
    pause.consumed = true;
    pause.reached(point);
    await pause.resume;
  }

  /** Returns Prisma's own (lazy) promise unless a pause targets this statement. */
  hooked(actor: string | undefined, point: string, run: () => unknown): unknown {
    if (actor === undefined || !this.pending(actor, point)) return run();
    return (async () => {
      await this.hit(actor, "before", point);
      const result = await run();
      await this.hit(actor, "after", point);
      return result;
    })();
  }

  instrument<T extends object>(target: T, actorOf: () => string | undefined): T {
    return new Proxy(target, {
      get: (object, property) => {
        const value: unknown = Reflect.get(object, property, object);
        if (typeof property !== "string") return value;
        if (RAW_METHODS.has(property) && typeof value === "function") {
          return (...args: unknown[]) =>
            this.hooked(actorOf(), sqlPoint(args), () => Reflect.apply(value, object, args));
        }
        if (isDelegate(value)) {
          return new Proxy(value, {
            get: (delegate, method) => {
              const fn: unknown = Reflect.get(delegate, method, delegate);
              if (typeof fn !== "function" || typeof method !== "string") return fn;
              return (...args: unknown[]) =>
                this.hooked(actorOf(), `${property}.${method}`, () =>
                  Reflect.apply(fn, delegate, args),
                );
            },
          });
        }
        return typeof value === "function" ? value.bind(object) : value;
      },
    });
  }

  instrumentClient(client: RealClient): RealClient {
    const outer = this.instrument(client, () => this.actors.getStore());
    return new Proxy(outer, {
      get: (object, property, receiver) => {
        if (property !== "$transaction") return Reflect.get(object, property, receiver);
        return (work: unknown, options?: unknown) => {
          // Array (batch) transactions pass through untouched.
          if (typeof work !== "function")
            return (client.$transaction as (...a: unknown[]) => unknown)(work, options);
          // The actor is captured at the call site, not re-read inside the
          // driver's callbacks, so pool scheduling cannot misattribute it.
          const actor = this.actors.getStore();
          return (client.$transaction as (...a: unknown[]) => unknown)(async (tx: object) => {
            if (actor !== undefined) {
              const rows = await (tx as RealClient).$queryRawUnsafe<{ pid: number }[]>(
                "SELECT pg_backend_pid() AS pid",
              );
              this.pids.set(actor, Number(rows[0]?.pid));
            }
            const out = await (work as (tx: object) => unknown)(this.instrument(tx, () => actor));
            // Pause point "$transaction.commit": every statement has run, but
            // the driver has not issued COMMIT yet — the window in which a
            // concurrent reader still observes pre-commit state.
            if (actor !== undefined) await this.hit(actor, "before", "$transaction.commit");
            return out;
          }, options);
        };
      },
    });
  }
}

function databaseUrl(base: string, name: string): string {
  const url = new URL(base);
  url.pathname = `/${name}`;
  return url.toString();
}

/**
 * The production pool size: the default of the `DATABASE_POOL_MAX`
 * declaration `@wssp/db` is built with (`env.DATABASE_POOL_MAX` in
 * ../index.ts), read from that declaration, never copied. Parsing
 * `undefined` yields the schema default without reading or validating the
 * process environment.
 */
export const PRODUCTION_DEFAULT_POOL_MAX: number = sharedVars.DATABASE_POOL_MAX.parse(undefined);

/** A file's clone: `wssp_t_` plus 32 hex digits (a dashless random UUID). */
export const CLONE_DATABASE = /^wssp_t_[0-9a-f]{32}$/;
/** A database a file creates beside its clone (an upgrade-apply target):
 * `<clone>_<suffix>`, within PostgreSQL's 63-byte identifier limit. */
export const SATELLITE_DATABASE = /^wssp_t_[0-9a-f]{32}_[a-z0-9_]{1,23}$/;
/** `startDisposablePostgres` names the `pnpm test:pg` container
 * `<prefix>-test-pg-<uuid>` (prefix `wssp`, or TEST_CONTAINER_PREFIX; see
 * scripts/lib/test-container-prefix.mjs) and sets its server's
 * `cluster_name` to that name. */
const TEST_PG_CONTAINER =
  /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*-test-pg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Why `adminUrl` may not be used to drop `clone`, or undefined when it may.
 * `container` is `<name>:<port>` as scripts/test-pg.mjs published it: the
 * URL must reach that container's loopback-published port, and `clone` must
 * be a per-file clone this process created. The live session then has to
 * prove it is that container's server (`cluster_name`) before any drop.
 */
export function dropRefusal(input: {
  adminUrl: string;
  container: string;
  clone: string;
  created: ReadonlySet<string>;
}): string | undefined {
  const separator = input.container.lastIndexOf(":");
  const name = input.container.slice(0, separator);
  const port = input.container.slice(separator + 1);
  if (separator < 0 || !TEST_PG_CONTAINER.test(name) || !/^[1-9][0-9]{0,4}$/.test(port))
    return "the container is not one `pnpm test:pg` started";
  let url: URL;
  try {
    url = new URL(input.adminUrl);
  } catch {
    return "the admin URL does not parse";
  }
  if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1" || url.port !== port)
    return "the admin URL is not the container's loopback-published port";
  if (!CLONE_DATABASE.test(input.clone)) return "the name is not a per-file clone";
  if (!input.created.has(input.clone)) return "this process did not create that clone";
  return undefined;
}

/** Clones this process created and has not dropped yet. */
const createdClones = new Set<string>();

/**
 * Drops this file's clone and its `<clone>_<suffix>` satellites. Only the
 * disposable `pnpm test:pg` container is reachable: `dropRefusal` checks the
 * URL and the name, and the one admin session (max 1) proves its server is
 * that container before dropping. `WITH (FORCE)` ends connections a test left
 * open; nothing else uses these databases.
 */
export async function dropFileDatabases(adminUrl: string, container: string, clone: string) {
  const refusal = dropRefusal({ adminUrl, container, clone, created: createdClones });
  if (refusal) throw new Error(`test:pg refused to drop ${clone}: ${refusal}.`);
  const admin = createPrismaClient({ connectionString: adminUrl, max: 1 });
  try {
    const [server] = await admin.$queryRawUnsafe<{ cluster: string }[]>(
      "SELECT current_setting('cluster_name') AS cluster",
    );
    if (server?.cluster !== container.slice(0, container.lastIndexOf(":")))
      throw new Error(`test:pg refused to drop ${clone}: the server is not the test container.`);
    const satellites = await admin.$queryRawUnsafe<{ datname: string }[]>(
      "SELECT datname FROM pg_database WHERE starts_with(datname, $1)",
      `${clone}_`,
    );
    const targets = [...satellites.map((row) => row.datname), clone];
    const unexpected = targets.find((t) => t !== clone && !SATELLITE_DATABASE.test(t));
    if (unexpected) throw new Error(`test:pg refused to drop unexpected database ${unexpected}.`);
    // The one reviewed drop (pinned in scripts/policy-checks.sh): every
    // target is this file's clone or one of its satellites, on the container.
    for (const target of targets)
      await admin.$executeRawUnsafe(`DROP DATABASE ${target} WITH (FORCE)`);
    createdClones.delete(clone);
  } finally {
    await admin.$disconnect();
  }
}

export function newCloneName(): string {
  return `wssp_t_${randomUUID().replaceAll("-", "")}`;
}

/** Clones `template` as `name` and records it as droppable by this process. */
export async function createClone(adminUrl: string, template: string, name: string) {
  if (!/^[a-z_][a-z0-9_]*$/.test(template)) throw new Error("Unexpected template name.");
  if (!CLONE_DATABASE.test(name)) throw new Error("Unexpected clone name.");
  // One admin session (max 1): the advisory lock serializes clones across
  // parallel files, and is released when this session ends.
  const admin = createPrismaClient({ connectionString: adminUrl, max: 1 });
  try {
    await admin.$executeRawUnsafe("SELECT pg_advisory_lock(20260925)");
    await admin.$executeRawUnsafe(`CREATE DATABASE ${name} TEMPLATE ${template}`);
    createdClones.add(name);
  } finally {
    await admin.$disconnect();
  }
}

async function open(): Promise<PgTestDatabase> {
  const adminUrl = inject("wsspPgAdminUrl");
  const template = inject("wsspPgTemplateDb");
  const container = inject("wsspPgContainer");
  if (!adminUrl || !template || !container) {
    throw new Error("pgTestDatabase() needs `pnpm test:pg` (vitest.pg.config.ts global setup).");
  }
  const name = newCloneName();
  // Registered before any await, while the file is still being collected.
  // Hooks run in reverse registration order, so this runs after the file's
  // own afterAll (which usually closes its clients). Close ours first.
  let opened: PgTestDatabase | undefined;
  afterAll(async () => {
    if (!createdClones.has(name)) return;
    await opened?.close();
    await dropFileDatabases(adminUrl, container, name);
  });
  await createClone(adminUrl, template, name);
  const url = databaseUrl(adminUrl, name);
  const real = createPrismaClient({ connectionString: url, max: PRODUCTION_DEFAULT_POOL_MAX });
  const inspect = createPrismaClient({ connectionString: url, max: 2 });
  const probe = new Probe();
  const prisma = probe.instrumentClient(real);
  afterEach(() => probe.reset());

  opened = {
    name,
    url,
    prisma,
    inspect,
    run: (actor, work) => probe.actors.run(actor, work),
    pauseAt: (actor, point) => probe.pauseAt(actor, point),
    backendPid: (actor) => probe.pids.get(actor),
    async waitUntilBlocked(actor, options = {}) {
      const deadline = Date.now() + (options.timeoutMs ?? 10_000);
      let last = "no transaction started";
      for (;;) {
        const pid = probe.pids.get(actor);
        const holder = options.by === undefined ? undefined : probe.pids.get(options.by);
        // A named holder with no recorded backend (typo, or its transaction
        // never started) must not degrade into "blocked by anyone": keep
        // polling, and name the missing holder at the deadline.
        const holderMissing = options.by !== undefined && holder === undefined;
        if (holderMissing) last = `holder "${options.by}" has no recorded transaction backend`;
        else if (pid !== undefined) {
          const rows = await inspect.$queryRawUnsafe<
            {
              wait_event_type: string | null;
              wait_event: string | null;
              blockers: number[];
              query: string;
            }[]
          >(
            "SELECT wait_event_type, wait_event, pg_blocking_pids(pid) AS blockers, query FROM pg_stat_activity WHERE pid = $1",
            pid,
          );
          const row = rows[0];
          if (row) {
            const blockers = row.blockers.map(Number);
            last = `wait_event_type=${row.wait_event_type} blockers=[${blockers.join(",")}]`;
            if (
              row.wait_event_type === "Lock" &&
              (holder === undefined || blockers.includes(holder))
            ) {
              return {
                waitEventType: row.wait_event_type,
                waitEvent: row.wait_event ?? "",
                blockers,
                query: row.query,
              };
            }
          } else last = "backend not found";
        }
        if (Date.now() > deadline) {
          throw new Error(
            `Actor "${actor}" was never observed blocked on a lock${options.by ? ` held by "${options.by}"` : ""} (${last}).`,
          );
        }
        // Yield between catalog polls; correctness never depends on this delay.
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    },
    async close() {
      await Promise.allSettled([real.$disconnect(), inspect.$disconnect()]);
    },
  };
  return opened;
}

let database: Promise<PgTestDatabase> | undefined;

/** This test file's cloned database (created on first use, one per file). */
export function pgTestDatabase(): Promise<PgTestDatabase> {
  database ??= open();
  return database;
}
