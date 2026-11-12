import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { setImmediate } from "node:timers/promises";
import { parse } from "@babel/parser";
import { expect, it, vi } from "vitest";
import { deviceRow, deviceStore } from "./device-code-test-harness";

vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "test-secret" } }));
const { default: prisma } = await import("@wssp/db");
const { mintHostDeviceCredentialFromApprovedDeviceCode: exchange } = await import(
  "./host-device-credential-access"
);
const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");

// Codex c2's real pg.Pool / PrismaPg probe, with only the SQL socket replaced.
// No TCP connection: the normal test I/O guard remains active.
class SqlSocket extends EventEmitter {
  _queryable = true;
  _ending = false;
  connect(callback: (error: null) => void) {
    queueMicrotask(() => callback(null));
  }
  query(_query: unknown, values?: unknown, callback?: (error: null, result: unknown) => void) {
    const cb = typeof values === "function" ? values : callback;
    const result = { fields: [], rows: [], rowCount: 0 };
    if (cb) {
      queueMicrotask(() => cb(null, result));
      return;
    }
    return Promise.resolve(result);
  }
  end(callback?: () => void) {
    this._ending = true;
    this.emit("end");
    callback?.();
  }
  ref() {}
  unref() {}
}
type Transport = {
  queryRaw(query: { sql: string; args: unknown[]; argTypes: unknown[] }): Promise<unknown>;
};
type TransactionTransport = Transport & { commit(): Promise<void>; rollback(): Promise<void> };
type Pool = { totalCount: number; idleCount: number; waitingCount: number; end(): Promise<void> };
const requireDb = createRequire(new URL("../../../db/package.json", import.meta.url));
const { Pool: PgPool } = requireDb("pg") as {
  Pool: new (options: { max: number; Client: typeof SqlSocket; idleTimeoutMillis: number }) => Pool;
};
const { PrismaPg } = requireDb("@prisma/adapter-pg") as {
  PrismaPg: new (
    pool: Pool,
  ) => {
    connect(): Promise<
      Transport & { startTransaction(): Promise<TransactionTransport>; dispose(): Promise<void> }
    >;
  };
};

it.each([1, 2])(
  "cold settings enrollment completes with all %s pool permits occupied by transactions",
  async (capacity) => {
    invalidateForceTwoFactorSettingsCache();
    const pool = new PgPool({ max: capacity, Client: SqlSocket, idleTimeoutMillis: 0 });
    const adapter = await new PrismaPg(pool).connect();
    const store = deviceStore();
    Object.assign(prisma, store.db);
    for (let index = 1; index <= capacity; index++) {
      store.state.deviceCode.set(
        `code-${index}`,
        deviceRow({ id: `code-${index}`, deviceCode: `secret-${index}`, userId: `user-${index}` }),
      );
      store.state.user.set(`user-${index}`, {
        id: `user-${index}`,
        emailVerified: true,
        banned: false,
        banExpires: null,
        twoFactorEnabled: false,
        role: "user",
        createdAt: new Date("2020-01-01"),
      });
    }
    const query = (connection: Transport) =>
      connection.queryRaw({ sql: "SELECT key, value FROM app_setting", args: [], argTypes: [] });
    // A global settings read really queues on the installed pool, as in the review probe.
    const globalSettings = vi.fn(async () => {
      await query(adapter);
      return [];
    });
    Object.assign(prisma, { appSetting: { findMany: globalSettings } });
    const transports: TransactionTransport[] = [];
    let startAll!: () => void;
    const allStarted = new Promise<void>((resolve) => {
      startAll = resolve;
    });
    const originalTransaction = store.db.$transaction.getMockImplementation();
    if (!originalTransaction) throw new Error("Missing store transaction");
    store.db.$transaction.mockImplementation(async (work) => {
      const transport = await adapter.startTransaction();
      transports.push(transport);
      if (transports.length === capacity) startAll();
      await allStarted;
      try {
        const result = await deviceStoreTransaction(work, transport);
        await transport.commit();
        return result;
      } catch (error) {
        await transport.rollback();
        throw error;
      }
    });
    const outcomes: Promise<unknown>[] = [];
    let completed = 0;
    function connected(target: object, transport: Transport): object {
      return new Proxy(target, {
        get(object, key) {
          const value: unknown = Reflect.get(object, key);
          if (typeof value === "function")
            return async (...args: unknown[]) => {
              await query(transport);
              return Reflect.apply(value, object, args);
            };
          return value && typeof value === "object" ? connected(value, transport) : value;
        },
      });
    }
    async function deviceStoreTransaction(
      work: (tx: unknown) => Promise<unknown>,
      transport: Transport,
    ) {
      if (!originalTransaction) throw new Error("Missing store transaction");
      return originalTransaction((tx) => work(connected(tx as object, transport)));
    }
    try {
      for (let index = 1; index <= capacity; index++)
        outcomes.push(
          exchange({ deviceCode: `secret-${index}`, hostSlug: "desk-01" }).finally(() => {
            completed++;
          }),
        );
      const settled = Promise.allSettled(outcomes);
      await allStarted;
      for (let turns = 0; turns < 100 && completed < capacity && pool.waitingCount === 0; turns++)
        await setImmediate();
      expect({ completed, waiting: pool.waitingCount }).toEqual({
        completed: capacity,
        waiting: 0,
      });
      expect((await settled).filter((result) => result.status === "fulfilled")).toHaveLength(
        capacity,
      );
      expect(globalSettings).not.toHaveBeenCalled();
      expect(store.state.hostDeviceCredential.size).toBe(capacity);
    } finally {
      // Release real permits even for the deliberately defective scratch mutation.
      for (const transport of transports) await transport.rollback().catch(() => undefined);
      await Promise.allSettled(outcomes);
      await adapter.dispose();
      await pool.end();
    }
  },
);

it("the entire device transaction path never calls the global Prisma client inside a callback", () => {
  for (const name of ["device-code-transitions.ts", "host-device-credential-access.ts"]) {
    const source = readFileSync(new URL(name, import.meta.url), "utf8");
    const file = parse(source, { sourceType: "module", plugins: ["typescript"] });
    let callbacks = 0;
    function visit(value: unknown) {
      if (!value || typeof value !== "object") return;
      const node = value as Record<string, unknown>;
      const callee = node.callee as { property?: { name?: string } } | undefined;
      if (node.type === "CallExpression" && callee?.property?.name === "$transaction") {
        const callback = (node.arguments as { type: string; body: unknown }[])[0];
        if (callback?.type !== "ArrowFunctionExpression")
          throw new Error("Uninspected device transaction callback");
        callbacks++;
        expect(JSON.stringify(callback.body), name).not.toContain('"name":"prisma"');
      }
      for (const child of Object.values(node)) {
        if (Array.isArray(child)) child.forEach(visit);
        else if (child && typeof child === "object") visit(child);
      }
    }
    visit(file);
    expect(callbacks).toBe(name === "device-code-transitions.ts" ? 1 : 2);
  }
});
