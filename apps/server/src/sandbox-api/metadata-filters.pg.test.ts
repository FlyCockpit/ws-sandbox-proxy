import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import type { Prisma } from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { metadataSchema, SANDBOX_STATES, sandboxPageSchema } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, expect, it, vi } from "vitest";
import { offloadSandboxForTest } from "../../../../packages/api/src/sandbox/testing/offload-fixtures";
import {
  seedAcceptedOperation,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { createWsspClient } from "../../../../packages/sdk/src/client";

// Trace actual production-client SQL calls, without substituting their results.
const { listQueries } = vi.hoisted(() => ({
  listQueries: [] as Prisma.SandboxFindManyArgs[],
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma.$extends({
    query: {
      sandbox: {
        async findMany({ args, query }) {
          listQueries.push(args);
          return query(args);
        },
      },
    },
  }),
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "metadata-pg-fixture",
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30000,
    RATE_LIMIT_SDK_KEY_POINTS: 10000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.92" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { createSandboxApi } = await import("./middleware");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
const { createSandbox, listSandboxes } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const app = new Hono().route("/v1", createSandboxApi());
afterAll(() => db.close());
const T = new Date("2026-09-26T12:00:00.000Z");

async function fixture() {
  const id = `metadata-${randomUUID()}`;
  const user = await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "local:base",
      incusFingerprint: `sha256:${"c".repeat(64)}`,
    },
  });
  const principal = { kind: "session" as const, ownerId: id };
  const key = await createSdkKey(principal, {
    name: "sdk",
    scopes: ["sandboxes:read", "sandboxes:write", "operations:read"],
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session: {
        id: `session-${id}`,
        userId: id,
        token: "fixture",
        expiresAt: new Date(Date.now() + 60000),
        createdAt: T,
        updatedAt: T,
        ipAddress: null,
        userAgent: null,
      },
    },
  } as Context;
  const browser = createRouterClient(sandboxesRouter, { context });
  const sdk = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: key.secret,
    fetch: async (url, init) => app.request(url, init),
  });
  const seed = (data: Partial<Prisma.SandboxUncheckedCreateInput> = {}) =>
    seedSandboxInstance(db.inspect, {
      data: {
        userId: id,
        sandboxHostId: host.id,
        originHostId: host.id,
        templateId: template.id,
        originPoolId: null,
        state: "READY",
        metadata: { team: "infra", tier: "gold" },
        createdAt: T,
        startedAt: T,
        ...data,
      },
    });
  return { id, host, template, principal, key, browser, sdk, seed };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
function get(f: Fixture, query: Record<string, string> = {}, secret = f.key.secret) {
  return app.request(`/v1/sandboxes?${new URLSearchParams(query)}`, {
    headers: { Authorization: `Bearer ${secret}` },
  });
}
async function page(f: Fixture, query: Record<string, string> = {}, secret = f.key.secret) {
  const response = await get(f, query, secret);
  expect(response.status).toBe(200);
  return sandboxPageSchema.parse(await response.json());
}

it("SQL exact-match AND filters before take across more than one page, including Unicode and literal JSON keys", async () => {
  const f = await fixture();
  // More than a page of newer partial matches must not consume the page budget.
  for (let i = 0; i < 26; i++)
    await f.seed({
      createdAt: new Date(T.getTime() + 1000 + i),
      metadata: i % 2 ? { team: "infra", tier: "silver" } : { team: "other", tier: "gold" },
    });
  const metadata = { team: "infra", tier: "gold", "a.b[0]'": "雪😀", empty: "" };
  const wanted = [];
  for (let i = 0; i < 9; i++) wanted.push(await f.seed({ metadata }));
  // A valid matching key must not hide non-string values elsewhere in the map.
  for (let i = 0; i < 12; i++)
    await f.seed({
      metadata: { ...metadata, legacy: i % 2 ? 1 : { privateValue: true } },
      createdAt: new Date(T.getTime() + 2000 + i),
    });
  // Exact string equality: these JSON scalar/null/missing/normalization variants do not match.
  for (const values of [
    { ...metadata, tier: "Gold" },
    { ...metadata, tier: 1 },
    { ...metadata, tier: null },
    { team: "infra" },
    { ...metadata, "a.b[0]'": "雪" },
  ])
    await f.seed({ metadata: values });
  const filters = { metadata: JSON.stringify(metadata), limit: "3" };
  const seen: string[] = [];
  let cursor: string | undefined;
  for (let n = 0; n < 10; n++) {
    const before = listQueries.length;
    const result = await page(f, { ...filters, ...(cursor ? { cursor } : {}) });
    const statements = listQueries.slice(before);
    expect(statements).toHaveLength(1); // no scan/accumulation to fill a filtered page
    expect(statements[0]?.take).toBe(4);
    expect(statements[0]?.where?.AND).toEqual(
      expect.arrayContaining(
        Object.entries(metadata).map(([key, value]) => ({
          metadata: { path: [key], equals: value },
        })),
      ),
    );
    expect(result.items.length).toBeLessThanOrEqual(3);
    seen.push(...result.items.map((row) => row.id));
    cursor = result.nextCursor ?? undefined;
    if (!cursor) break;
  }
  expect(cursor).toBeUndefined();
  expect(seen).toEqual(
    wanted
      .map((row) => row.id)
      .sort()
      .reverse(),
  );
  const browser = await f.browser.list({ limit: 100, metadata });
  expect(browser.items.map((row) => row.id)).toEqual(seen);
  const sdk = await f.sdk.sandboxes.list({ limit: 100, metadata });
  expect(sdk.items.map((row) => row.id)).toEqual(seen);
});

it("READY discovery default and explicit dashboard history preserve every state", async () => {
  const f = await fixture();
  const all = [];
  for (const state of SANDBOX_STATES) {
    if (state === "OFFLOADED") {
      // Hostless with a stored disk (schema CHECK): built through the real key path.
      const row = await f.seed({ state: "STOPPED", sandboxHostId: null, hostOwnerId: null });
      await db.inspect.$transaction((tx) =>
        offloadSandboxForTest(tx, { userId: f.id, sandboxId: row.id, hostId: f.host.id }),
      );
      all.push(row);
      continue;
    }
    all.push(
      await f.seed(
        // A waiting create holds no host (schema CHECK).
        state === "WAITING_FOR_CAPACITY"
          ? { state, sandboxHostId: null, originHostId: null, hostOwnerId: null }
          : { state },
      ),
    );
  }
  expect((await page(f)).items.map((row) => row.state)).toEqual(["READY"]);
  expect((await f.browser.list({ limit: 100 })).items.map((row) => row.state)).toEqual(["READY"]);
  expect((await f.sdk.sandboxes.list()).items.map((row) => row.state)).toEqual(["READY"]);
  expect(
    (await f.browser.list({ limit: 100, status: "deleted", states: ["READY"] })).items,
  ).toEqual([]);
  await expect(f.browser.list({ limit: 1, states: [] })).rejects.toMatchObject({
    code: "BAD_REQUEST",
  });
  expect((await f.browser.list({ limit: 1, poolId: "future" })).items).toEqual([]);
  expect((await listSandboxes(f.principal, { limit: 1, poolId: "future" })).items).toEqual([]);
  const history = await f.browser.list({ limit: 100, status: "all" });
  expect(history.items.length).toBe(all.length);
  expect((await f.browser.list({ limit: 100, status: "active" })).items).toHaveLength(
    all.length - 1,
  );
  expect(
    (await f.browser.list({ limit: 100, status: "deleted" })).items.map((row) => row.state),
  ).toEqual(["DELETED"]);
  expect((await page(f, { states: SANDBOX_STATES.join(","), limit: "100" })).items).toHaveLength(
    all.length,
  );
});

it("SQL states, current template and strict startedAfter filters precede ascending cursor/take", async () => {
  const f = await fixture();
  const otherTemplate = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.id,
      sandboxHostId: f.host.id,
      slug: "other",
      label: "Other",
      imageRef: "local:other",
      incusFingerprint: `sha256:${"d".repeat(64)}`,
    },
  });
  const wanted = [];
  for (let i = 0; i < 7; i++)
    wanted.push(await f.seed({ state: "STOPPED", startedAt: new Date(T.getTime() + 1) }));
  for (let i = 0; i < 7; i++) {
    await f.seed({ state: "READY", startedAt: new Date(T.getTime() + 1) });
    await f.seed({
      state: "STOPPED",
      templateId: otherTemplate.id,
      templateRevisionId: otherTemplate.id,
      originPoolId: null,
      startedAt: new Date(T.getTime() + 1),
    });
    await f.seed({ state: "STOPPED", startedAt: T });
    await f.seed({ state: "STOPPED", startedAt: null });
  }
  const filters = {
    states: "STOPPED",
    metadata: '{"team":"infra"}',
    templateId: f.template.templateId,
    startedAfter: T.toISOString(),
    order: "asc",
    limit: "3",
  };
  const first = await page(f, filters);
  const second = await page(f, {
    ...filters,
    startedAfter: T.toISOString().replace(".000Z", "Z"),
    cursor: first.nextCursor ?? "",
  });
  const third = await page(f, { ...filters, cursor: second.nextCursor ?? "" });
  expect([...first.items, ...second.items, ...third.items].map((row) => row.id)).toEqual(
    wanted.map((row) => row.id).sort(),
  );
  expect(third.nextCursor).toBeNull();
  expect(
    (
      await f.browser.list({
        ...filters,
        metadata: { team: "infra" },
        states: ["STOPPED"],
        order: "asc",
        limit: 100,
      })
    ).items.map((row) => row.id),
  ).toEqual(wanted.map((row) => row.id).sort());
});

it("context cursors reject different owner, metadata, states, template, time and order", async () => {
  const f = await fixture();
  const foreign = await fixture();
  for (let i = 0; i < 3; i++) await f.seed();
  const first = await page(f, { limit: "1", metadata: '{"tier":"gold","team":"infra"}' });
  const cursor = first.nextCursor ?? "";
  expect(cursor.length).toBeGreaterThan(128);
  const changes: Record<string, string>[] = [
    { metadata: '{"team":"other","tier":"gold"}' },
    { states: "STOPPED" },
    { templateId: f.template.id },
    { startedAfter: T.toISOString() },
    { order: "asc" },
  ];
  for (const change of changes) {
    expect(
      (await get(f, { metadata: '{"tier":"gold","team":"infra"}', cursor, ...change })).status,
    ).toBe(400);
  }
  expect((await get(foreign, { metadata: '{"team":"infra","tier":"gold"}', cursor })).status).toBe(
    400,
  );
  await expect(
    f.browser.list({ limit: 1, cursor, metadata: { team: "other", tier: "gold" } }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  await expect(
    f.sdk.sandboxes.list({ cursor, metadata: { team: "other", tier: "gold" } }),
  ).rejects.toMatchObject({ kind: "invalid_request" });
  // Equivalent normalized maps/defaults and a different page size resume correctly.
  expect(
    (
      await page(f, {
        cursor,
        metadata: '{"team":"infra","tier":"gold"}',
        states: "READY,READY",
        order: "desc",
        limit: "2",
      })
    ).items,
  ).toHaveLength(2);
  const historyCursor = (await page(f, { states: "STOPPED,READY", limit: "1" })).nextCursor ?? "";
  expect(
    (await page(f, { states: "READY,STOPPED,READY", cursor: historyCursor })).items,
  ).toHaveLength(2);
  // Keysets do not require the anchor row to remain visible or present.
  await db.inspect.sandbox.delete({ where: { id: first.items[0]!.id } });
  expect(
    (await page(f, { cursor, metadata: '{"team":"infra","tier":"gold"}' })).items,
  ).toHaveLength(2);
  const parts = Buffer.from(cursor, "base64url").toString("utf8").split("|");
  const encode = (values: string[]) => Buffer.from(values.join("|")).toString("base64url");
  const maxIdParts = [...parts];
  maxIdParts[2] = "z".repeat(64);
  const canonical = encode(maxIdParts);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  // Change only unused base64 pad bits: decoded position/context remain identical.
  const noncanonical = canonical.slice(0, -1) + alphabet[alphabet.indexOf(canonical.at(-1)!) + 1];
  expect(Buffer.from(noncanonical, "base64url")).toEqual(Buffer.from(canonical, "base64url"));
  expect(
    (await get(f, { cursor: canonical, metadata: '{"team":"infra","tier":"gold"}' })).status,
  ).toBe(200);
  for (const malformed of [
    "abc",
    Buffer.from(`${T.toISOString()}|legacy`).toString("base64url"),
    `${cursor}A`,
    encode(["s2", ...parts.slice(1)]),
    encode([parts[0]!, "not-a-date", ...parts.slice(2)]),
    encode([parts[0]!, T.toISOString().replace(".000Z", "Z"), ...parts.slice(2)]),
    encode([parts[0]!, parts[1]!, "invalid id", parts[3]!]),
    encode([...parts, "extra"]),
    noncanonical,
  ])
    expect(
      (await get(f, { cursor: malformed, metadata: '{"team":"infra","tier":"gold"}' })).status,
    ).toBe(400);
});

it("SQL selected visibility follows the immutable creating key before pagination, including retained rows", async () => {
  const f = await fixture();
  const foreign = await fixture();
  const otherHost = await seedLaunchHost(db.inspect, {
    data: { userId: f.id, slug: "other", label: "Other" },
  });
  const otherTemplate = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.id,
      sandboxHostId: otherHost.id,
      slug: "other",
      label: "Other",
      imageRef: "local:other",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  for (let i = 0; i < 12; i++) {
    await f.seed({ originHostId: otherHost.id, createdAt: new Date(T.getTime() + 1) });
    await f.seed({ templateId: otherTemplate.id, createdAt: new Date(T.getTime() + 1) });
    await foreign.seed();
  }
  const wanted = [];
  for (let i = 0; i < 5; i++) wanted.push(await f.seed({ sandboxHostId: null }));
  const key = await createSdkKey(f.principal, {
    name: "allow",
    scopes: ["sandboxes:read"],
    resourceMode: "ALLOWLIST",
    hostIds: [f.host.id],
    templateRevisionIds: [f.template.id],
  });
  for (const row of wanted) {
    await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.id,
        sandboxId: row.id,
        kind: "CREATE_SANDBOX" as const,
        generation: row.generation,
        state: "SUCCEEDED" as const,
        authorizingKeyId: key.key.id,
        idempotencyKey: randomUUID(),
        requestBodyHash: "fixture",
      },
    });
  }
  const seen: string[] = [];
  let cursor: string | undefined;
  for (let n = 0; n < 4; n++) {
    const result = await page(
      f,
      { limit: "2", metadata: '{"team":"infra","tier":"gold"}', ...(cursor ? { cursor } : {}) },
      key.secret,
    );
    seen.push(...result.items.map((row) => row.id));
    cursor = result.nextCursor ?? undefined;
    if (!cursor) break;
  }
  expect(seen).toEqual(
    wanted
      .map((row) => row.id)
      .sort()
      .reverse(),
  );
  await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
  expect((await page(f, { metadata: '{"team":"infra"}' }, key.secret)).items).toHaveLength(5);
  expect((await f.browser.list({ limit: 100, status: "all" })).items).toHaveLength(29);
});

it.each([
  ["duplicate query values", "metadata=%7B%7D&metadata=%7B%7D"],
  [
    "duplicate decoded keys",
    `metadata=${encodeURIComponent('{"team":"infra","t\\u0065am":"other"}')}`,
  ],
  ["malformed JSON", "metadata=%7B"],
  ["non-string JSON", `metadata=${encodeURIComponent('{"count":1}')}`],
  ["prototype key", `metadata=${encodeURIComponent('{"__proto__":"x"}')}`],
  ["unknown filter", "unknownPoolId=future"],
  ["empty states", "states="],
  ["invalid time", "startedAfter=yesterday"],
  ["invalid template", "templateId=!"],
  [
    "too many states",
    `states=${Array.from({ length: SANDBOX_STATES.length + 1 }, () => "READY").join(",")}`,
  ],
  ["oversized JSON whitespace", `metadata=${encodeURIComponent(" ".repeat(8191) + "{}")}`],
  ["invalid order", "order=sideways"],
  ["oversized JSON", `metadata=${encodeURIComponent(JSON.stringify({ key: "😀".repeat(3000) }))}`],
])("HTTP list rejects %s", async (_label, query) => {
  const f = await fixture();
  expect(
    (
      await app.request(`/v1/sandboxes?${query}`, {
        headers: { Authorization: `Bearer ${f.key.secret}` },
      })
    ).status,
  ).toBe(400);
});

it("all create entry points reject scalar metadata before any allocation, and accept bounded strings", async () => {
  const f = await fixture();
  for (const value of [1, true, null, {}, []]) {
    const body = {
      sandboxHostId: f.host.id,
      template: "revision/" + f.template.id,
      metadata: { value },
    };
    const response = await app.request("/v1/sandboxes", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${f.key.secret}`,
        "Content-Type": "application/json",
        "Idempotency-Key": randomUUID(),
      },
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "sandbox.metadata_invalid" } });
    await expect(
      f.browser.createSandbox({ ...body, idempotencyKey: randomUUID() } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      createSandbox(f.principal, { ...body, idempotencyKey: randomUUID() } as never),
    ).rejects.toMatchObject({ data: { code: "sandbox.metadata_invalid" } });
  }
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.id },
    }),
  ).toBe(0);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
  const metadata = Object.fromEntries(
    Array.from({ length: 32 }, (_, i) => [`雪${i}`, i === 0 ? "😀".repeat(512) : ""]),
  );
  const created = await f.browser.createSandbox({
    sandboxHostId: f.host.id,
    template: "revision/" + f.template.id,
    metadata,
    idempotencyKey: randomUUID(),
  });
  expect(created.metadata).toEqual(metadata);
  expect((await f.browser.getSandbox({ id: created.id })).metadata).toEqual(metadata);
  expect((await f.sdk.sandboxes.get(created.id)).metadata).toEqual(metadata);
  expect(
    (await listSandboxes(f.principal, { limit: 1, states: ["REQUESTED"], metadata })).items.map(
      (row) => row.id,
    ),
  ).toEqual([created.id]);
});

it("raw native create refuses duplicate decoded metadata keys and containers before persistence", async () => {
  const f = await fixture();
  for (const tail of [
    '"metadata":{"team":"a","t\\u0065am":"b"}',
    '"metadata":{"team":"a"},"metadata":{"team":"b"}',
  ]) {
    const body = `{"sandboxHostId":"${f.host.id}","templateId":"${f.template.id}",${tail}}`;
    const response = await app.request("/v1/sandboxes", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${f.key.secret}`,
        "Content-Type": "application/json",
        "Idempotency-Key": randomUUID(),
      },
      body,
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "sandbox.metadata_invalid" } });
  }
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});

it("context cursors bind normalized SQL grant visibility as well as explicit filters", async () => {
  const f = await fixture();
  for (let i = 0; i < 3; i++) await f.seed();
  const key = await createSdkKey(f.principal, {
    name: "allow",
    scopes: ["sandboxes:read"],
    resourceMode: "ALLOWLIST",
    hostIds: [f.host.id],
    templateRevisionIds: [f.template.id],
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { userId: f.id, kind: "CREATE_SANDBOX" },
    data: { authorizingKeyId: key.key.id },
  });
  const first = await page(f, { limit: "1" }, key.secret);
  const cursor = first.nextCursor ?? "";
  // ALL_OWNED is a different SQL filter even if it currently matches the same rows.
  expect((await get(f, { cursor })).status).toBe(400);
  const equivalent = await createSdkKey(f.principal, {
    name: "equivalent",
    scopes: ["sandboxes:read"],
    resourceMode: "ALLOWLIST",
    hostIds: [f.host.id],
    templateRevisionIds: [f.template.id],
  });
  expect((await get(f, { cursor }, equivalent.secret)).status).toBe(400);
  await db.inspect.sdkKeyHostAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
  expect((await get(f, { cursor }, key.secret)).status).toBe(400);
  expect((await page(f, {}, key.secret)).items).toHaveLength(3);
});

it("HTTP metadata query accepts exactly 8192 raw JSON bytes and rejects the next byte", async () => {
  const f = await fixture();
  const row = await f.seed();
  const map = '{"team":"infra","tier":"gold"}';
  const source = " ".repeat(8192 - map.length) + map;
  expect((await page(f, { metadata: source })).items.map((item) => item.id)).toEqual([row.id]);
  expect((await get(f, { metadata: " " + source })).status).toBe(400);
});

it("SQL metadata equality distinguishes string values from JSON scalars and substrings without Unicode normalization", async () => {
  const f = await fixture();
  const numericText = await f.seed({ metadata: { label: "1" } });
  for (const value of [1, true, null, [], { nested: "1" }, "11", "prefix-1"])
    await f.seed({ metadata: { label: value } });
  expect((await page(f, { metadata: '{"label":"1"}' })).items.map((row) => row.id)).toEqual([
    numericText.id,
  ]);
  const composed = await f.seed({ metadata: { label: "é" } });
  await f.seed({ metadata: { label: "e\u0301" } });
  expect(
    (await page(f, { metadata: JSON.stringify({ label: "é" }) })).items.map((row) => row.id),
  ).toEqual([composed.id]);
});

it("bounded metadata page validation matches string-map bounds including UTF-16 units and canonical bytes", async () => {
  const f = await fixture();
  const bytes: Record<string, string> = { team: "infra" };
  for (let i = 0; i < 8; i++) bytes[`k${i}`] = "x".repeat(1024);
  bytes.k7 = bytes.k7!.slice(0, 1024 - (JSON.stringify(bytes).length - 8192));
  expect(JSON.stringify(bytes)).toHaveLength(8192);
  const units = { team: "infra", ["😀".repeat(32)]: "😀".repeat(512) };
  const keys = {
    team: "infra",
    ...Object.fromEntries(Array.from({ length: 31 }, (_, i) => [`k${i}`, ""])),
  };
  const valid = [];
  for (const metadata of [
    bytes,
    units,
    keys,
    { team: "infra", text: ' spaces: commas, quotes" \\ \b\t\n\r\f\u0001\u2028雪😀 ' },
  ])
    valid.push(await f.seed({ metadata }));
  for (const metadata of [
    { ...bytes, k7: bytes.k7 + "x" },
    { ...units, ["😀".repeat(32)]: "😀".repeat(513) },
    { ...units, ["😀".repeat(33)]: "" },
    { ...keys, extra: "" },
    { team: "infra", "": "" },
    { team: "infra", ["k".repeat(65)]: "" },
    { team: "infra", value: "v".repeat(1025) },
    Object.fromEntries([
      ["team", "infra"],
      ["__proto__", "private-stored-value"],
    ]),
    { team: "infra", constructor: "private-stored-value" },
    { team: "infra", prototype: "private-stored-value" },
  ]) {
    const row = await f.seed();
    // Preserve prototype-related JSON keys exactly; object serialization by
    // Prisma can otherwise discard them before they reach PostgreSQL.
    await db.inspect
      .$executeRaw`UPDATE sandbox_instance SET metadata = ${JSON.stringify(metadata)}::jsonb WHERE id = ${row.id}`;
    const stored = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: row.id } });
    expect(metadataSchema.safeParse(stored.metadata).success).toBe(false);
  }
  const expected = valid
    .map((row) => row.id)
    .sort()
    .reverse();
  const filters: Record<string, string>[] = [{ team: "infra" }, {}];
  for (const metadata of filters) {
    expect(
      (await page(f, { metadata: JSON.stringify(metadata) })).items.map((row) => row.id),
    ).toEqual(expected);
    expect((await f.browser.list({ limit: 100, metadata })).items.map((row) => row.id)).toEqual(
      expected,
    );
    expect((await f.sdk.sandboxes.list({ metadata })).items.map((row) => row.id)).toEqual(expected);
  }
});

it("filtered cursors retain positions when selected rows are deleted between pages", async () => {
  const f = await fixture();
  const rows = [];
  for (let i = 0; i < 5; i++) rows.push(await f.seed());
  const ids = rows.map((row) => row.id).sort();
  const query = { metadata: '{"team":"infra"}', order: "asc", limit: "2" };
  const first = await page(f, query);
  expect(first.items.map((row) => row.id)).toEqual(ids.slice(0, 2));
  await db.inspect.sandbox.deleteMany({ where: { id: { in: ids.slice(0, 2) }, userId: f.id } });
  expect(first.nextCursor).not.toBeNull();
  const second = await page(f, { ...query, cursor: first.nextCursor! });
  const third = await page(f, { ...query, cursor: second.nextCursor! });
  expect([...second.items, ...third.items].map((row) => row.id)).toEqual(ids.slice(2));
  expect(third.nextCursor).toBeNull();
});

it("empty metadata filters cannot reuse unfiltered cursors", async () => {
  const f = await fixture();
  await f.seed();
  await f.seed();
  await f.seed({ metadata: { team: "infra", count: "1" } });
  const unfiltered = await page(f, { limit: "1" });
  const filtered = await page(f, { limit: "1", metadata: "{}" });
  expect((await get(f, { metadata: "{}", cursor: unfiltered.nextCursor! })).status).toBe(400);
  expect((await get(f, { cursor: filtered.nextCursor! })).status).toBe(400);
});
