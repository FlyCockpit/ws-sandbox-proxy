import { vi } from "vitest";

type Row = Record<string, unknown> & { id: string };
type Model = "session" | "deviceCode" | "user" | "sandboxHost" | "hostDeviceCredential";
type Where = Record<string, unknown>;

export function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

function matches(row: Row, where: Where): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (value instanceof Date) return Number(row[key]) === Number(value);
    if (value && typeof value === "object") {
      if ("lte" in value) return Number(row[key]) <= Number(value.lte);
      if ("gt" in value) return Number(row[key]) > Number(value.gt);
      if ("not" in value) return row[key] !== value.not;
      if ("in" in value) return (value.in as unknown[]).includes(row[key]);
    }
    return row[key] === value;
  });
}

/** READ COMMITTED statement views + row/unique locks + staged commit/rollback.
 * Based on the server's fenced-prisma-harness, limited to the device write inventory.
 * Unsupported SQL fails rather than pretending to implement Postgres. */
export function deviceStore() {
  const state: Record<Model, Map<string, Row>> = {
    session: new Map(),
    deviceCode: new Map(),
    user: new Map(),
    sandboxHost: new Map(),
    hostDeviceCredential: new Map(),
  };
  const hooks: {
    beforeLock?: (key: string) => Promise<void>;
    onWait?: (key: string) => void;
    afterConsume?: () => Promise<void>;
    beforeSettings?: () => Promise<void>;
    beforeRevoke?: () => Promise<void>;
    beforeCredential?: () => Promise<void>;
  } = {};
  const events: string[] = [];
  let now = new Date("2026-07-01T00:00:00Z");
  const tails = new Map<string, Promise<void>>();
  let serial = 0;
  async function transaction(work: (tx: unknown) => Promise<unknown>) {
    const staged = new Map<Model, Map<string, Row | null>>();
    const releases = new Map<string, () => void>();
    const view = (model: Model) =>
      new Map(
        [...state[model], ...(staged.get(model) ?? [])].filter(
          (entry): entry is [string, Row] => entry[1] !== null,
        ),
      );
    function stage(model: Model, id: string, row: Row | null) {
      if (!staged.has(model)) staged.set(model, new Map());
      staged.get(model)?.set(id, row);
    }
    async function lock(key: string) {
      if (releases.has(key)) return;
      await hooks.beforeLock?.(key);
      const previous = tails.get(key);
      const release = gate();
      tails.set(key, release.promise);
      if (previous) hooks.onWait?.(key);
      await previous;
      releases.set(key, () => {
        release.open();
        if (tails.get(key) === release.promise) tails.delete(key);
      });
      events.push(`lock:${key}`);
    }
    function model(name: Model) {
      const find = async ({ where }: { where: Where }) =>
        structuredClone([...view(name).values()].find((row) => matches(row, where)) ?? null);
      return {
        findFirst: find,
        findUnique: find,
        count: async ({ where }: { where: Where }) =>
          [...view(name).values()].filter((row) => matches(row, where)).length,
        updateMany: async ({ where, data }: { where: Where; data: Where }) => {
          if (name === "hostDeviceCredential") await hooks.beforeRevoke?.();
          let count = 0;
          for (const candidate of view(name).values()) {
            if (!matches(candidate, where)) continue;
            await lock(`${name}:${candidate.id}`);
            const row = view(name).get(candidate.id);
            if (!row || !matches(row, where)) continue;
            stage(name, row.id, { ...row, ...data });
            count++;
          }
          return { count };
        },
        deleteMany: async ({ where }: { where: Where }) => {
          let count = 0;
          for (const candidate of view(name).values()) {
            if (!matches(candidate, where)) continue;
            await lock(`${name}:${candidate.id}`);
            const row = view(name).get(candidate.id);
            if (!row || !matches(row, where)) continue;
            stage(name, row.id, null);
            count++;
            if (name === "deviceCode") {
              events.push("consume");
              await hooks.afterConsume?.();
            }
          }
          return { count };
        },
        create: async ({ data }: { data: Where }) => {
          if (name === "hostDeviceCredential") await hooks.beforeCredential?.();
          if (name === "sandboxHost") {
            await lock(`slug:${data.userId}:${data.slug}`);
            if (
              [...view(name).values()].some((r) => r.userId === data.userId && r.slug === data.slug)
            ) {
              throw Object.assign(new Error("unique slug"), {
                code: "P2002",
                meta: { target: ["userId", "slug"] },
              });
            }
          }
          const id = String(data.id ?? `${name}-${++serial}`);
          await lock(`${name}:${id}`);
          const row = {
            revokedAt: null,
            ...(name === "sandboxHost"
              ? { memoryReservedMiB: 0, daemonMemoryBudgetMiB: 65536, daemonMaxCpuCount: 32 }
              : {}),
            ...data,
            id,
          };
          stage(name, id, row);
          events.push(`create:${name}`);
          return structuredClone(row);
        },
      };
    }
    const tx = {
      appSetting: {
        findMany: async () => {
          await hooks.beforeSettings?.();
          events.push("settings:tx");
          return [];
        },
      },
      session: model("session"),
      deviceCode: model("deviceCode"),
      user: model("user"),
      sandboxHost: model("sandboxHost"),
      hostDeviceCredential: model("hostDeviceCredential"),
      $queryRaw: async (parts: TemplateStringsArray, ...values: unknown[]) => {
        const sql = parts.join("?");
        if (sql === "SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now")
          return [{ now: new Date(now) }];
        if (sql === "SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(?, 0))") {
          // C52-R2-3 per-owner host-creation lock: exclusive, transaction scoped.
          const [, ownerId] = JSON.parse(String(values[0])) as [string, string];
          await lock(`hostcap:${ownerId}`);
          return [{ locked: 1 }];
        }
        if (sql.includes("FROM host_device_credential") && sql.includes("LIMIT 100 FOR UPDATE")) {
          const rows = [...view("hostDeviceCredential").values()]
            .filter((r) => r.sandboxHostId === values[0] && r.id > String(values[1]))
            .sort((a, b) => a.id.localeCompare(b.id))
            .slice(0, 100);
          for (const row of rows) await lock(`hostDeviceCredential:${row.id}`);
          return rows.map((row) => ({ id: row.id }));
        }
        if (sql === "SELECT id FROM session WHERE id = ? FOR SHARE") {
          events.push(`share:session:${values[0]}`);
          return view("session").has(String(values[0])) ? [{ id: values[0] }] : [];
        }
        const name = sql.includes("FROM device_code")
          ? "deviceCode"
          : sql.includes('FROM "user"')
            ? "user"
            : sql.includes("FROM sandbox_host")
              ? "sandboxHost"
              : null;
        if (name === "user" && sql === 'SELECT id FROM "user" WHERE id = ? FOR SHARE') {
          // Shared owner lock (C21-13): recorded for ordering; shared locks never block here.
          events.push(`share:user:${values[0]}`);
          return view("user").has(String(values[0])) ? [{ id: values[0] }] : [];
        }
        if (!name || !sql.includes("FOR UPDATE")) throw new Error(`Unsupported SQL: ${sql}`);
        // SQL WHERE filters before lock acquisition; recheck after waiting like READ COMMITTED.
        const predicate: Where = { id: values[0] };
        if (sql.includes('AND "userId" =')) {
          predicate.userId = values[1];
          predicate.slug = values[2];
        }
        const candidate = view(name).get(String(values[0]));
        if (!candidate || !matches(candidate, predicate)) return [];
        await lock(`${name}:${values[0]}`);
        const current = view(name).get(String(values[0]));
        return current && matches(current, predicate) ? [{ id: values[0] }] : [];
      },
    };
    try {
      const result = await work(tx);
      for (const [name, rows] of staged)
        for (const [id, row] of rows) {
          if (row) state[name].set(id, row);
          else state[name].delete(id);
        }
      events.push("commit");
      return result;
    } catch (error) {
      events.push("rollback");
      throw error;
    } finally {
      for (const release of releases.values()) release();
    }
  }
  const db = {
    $transaction: vi.fn(transaction),
    sandboxHost: {
      count: vi.fn(
        async ({ where }: { where: Where }) =>
          [...state.sandboxHost.values()].filter((r) => matches(r, where)).length,
      ),
    },
    deviceCode: {
      findUnique: vi.fn(async ({ where }: { where: Where }) =>
        structuredClone([...state.deviceCode.values()].find((r) => matches(r, where)) ?? null),
      ),
      findFirst: vi.fn(async ({ where }: { where: Where }) =>
        structuredClone([...state.deviceCode.values()].find((r) => matches(r, where)) ?? null),
      ),
      deleteMany: vi.fn(async ({ where }: { where: Where }) => {
        let count = 0;
        for (const [id, row] of state.deviceCode)
          if (matches(row, where)) {
            state.deviceCode.delete(id);
            count++;
          }
        return { count };
      }),
    },
  };
  return {
    db,
    state,
    events,
    hooks,
    get now() {
      return now;
    },
    set now(value: Date) {
      now = value;
    },
  };
}

export function deviceRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "code-1",
    deviceCode: "secret-code-1",
    userCode: "ABCDEFGH",
    userId: "user-1",
    status: "approved",
    scope: "host-slug:desk-01",
    expiresAt: new Date("2026-07-01T00:10:00Z"),
    lastPolledAt: null,
    pollingInterval: 5000,
    enrollmentIntent: "create",
    replaceHostId: null,
    ...overrides,
  };
}
