import { randomBytes } from "node:crypto";
import http from "node:http";
import { type Duplex, duplexPair } from "node:stream";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("./budgets", () => ({
  consumeWebhookWrite: async () => {},
  consumeWebhookTest: async () => {},
  consumeWebhookRedeliver: async () => {},
}));

const db = await pgTestDatabase();
const { seedEndpoint, seedOwner, seedSandbox } = await import("./testing/fixtures");
const ledger = await import("./ledger");
const { runDeliveryJob } = await import("./deliver");
const { sealSecret, WEBHOOK_SECRET_PURPOSE } = await import("./crypto");
const { dataRootKey, deriveSubkey } = await import("../crypto/data-key");
const { parseAllowedCidrs } = await import("./destination-policy");
const service = await import("./service");
const { resetWebhookConfigForTests } = await import("./config");
const { sessionPrincipal } = await import("../sandbox/contracts");
const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
const schedule = await import("./schedule");
afterAll(() => db.close());

const ROOT_HEX = randomBytes(32).toString("hex");
const subkey = deriveSubkey(dataRootKey(ROOT_HEX), WEBHOOK_SECRET_PURPOSE);
const config = (privateScope: "admins" | "all" = "all") => ({
  keys: [subkey],
  current: subkey,
  privateScope,
  deliveryConcurrency: 8,
  allowlist: {
    cidrs: parseAllowedCidrs("192.168.50.0/24", true),
    hosts: new Set<string>(),
    allowPlaintext: true,
    allowLoopback: false,
  },
});

/** In-memory receiver: every request answered with `status`. */
function transport(status: () => number) {
  const received: { headers: http.IncomingHttpHeaders; body: string }[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.writeHead(status()).end();
    });
  });
  return {
    received,
    resolve: async () => ["192.168.50.10"],
    connect: async ({ address }: { address: string }) => {
      const [client, side] = duplexPair();
      Object.defineProperty(client, "remoteAddress", { value: address });
      server.emit("connection", side);
      return client as Duplex & { remoteAddress?: string };
    },
  };
}

async function endpointFor(
  owner: string,
  extra: Record<string, unknown> = {},
  sealKey: typeof subkey = subkey,
) {
  const id = typeof extra.id === "string" ? extra.id : `whe_${randomBytes(8).toString("hex")}`;
  const sealed = sealSecret(
    Buffer.alloc(32, 5),
    { endpointId: id, userId: owner, version: 1 },
    sealKey,
  );
  return seedEndpoint(db.inspect, owner, {
    id,
    url: "http://192.168.50.10:8080/hook",
    secretCiphertext: new Uint8Array(sealed.ciphertext),
    secretNonce: new Uint8Array(sealed.nonce),
    secretKeyId: sealed.keyId,
    ...extra,
  });
}

async function eventFor(owner: string, at = new Date()) {
  const id = `evt_${randomBytes(16).toString("hex")}`;
  await db.inspect.webhookEvent.create({
    data: {
      id,
      userId: owner,
      type: "webhook.test",
      occurredAt: at,
      facts: {},
      body: '{"hello":"world"}',
      fannedOutAt: at,
    },
  });
  return id;
}

async function pending(owner: string, endpointId: string, extra: Record<string, unknown> = {}) {
  const eventId = await eventFor(owner);
  return db.inspect.webhookDelivery.create({
    data: {
      eventId,
      endpointId,
      userId: owner,
      kind: "event",
      maxAttempts: schedule.WEBHOOK_MAX_ATTEMPTS,
      nextAttemptAt: new Date(),
      expiresAt: new Date(Date.now() + schedule.WEBHOOK_DELIVERY_WINDOW_MS),
      ...extra,
    },
    select: { id: true, eventId: true, enqueueSeq: true },
  });
}

beforeEach(() => {
  vi.unstubAllEnvs();
  resetWebhookConfigForTests();
});

describe("fan-out (real PostgreSQL)", () => {
  it("two concurrent dispatchers never create duplicate deliveries", async () => {
    const owner = await seedOwner(db.inspect);
    await endpointFor(owner, { createdAt: new Date(Date.now() - 60_000) });
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: sandbox.id } });
    for (let i = 0; i < 5; i++) {
      await db.inspect.sandbox.update({
        where: { id: sandbox.id },
        data: { state: "READY", readyAt: new Date() },
      });
      await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "STOPPING" } });
      await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "STOPPED" } });
    }
    const gate = db.pauseAt("dispatcher-a", { before: /^webhookEvent\.update$/ });
    const a = db.run("dispatcher-a", () => ledger.fanOutEvents(db.prisma));
    await gate.waitReached();
    // B skips A's locked rows instead of waiting or duplicating them.
    const fannedByB = await db.run("dispatcher-b", () => ledger.fanOutEvents(db.prisma));
    gate.release();
    const fannedByA = await a;
    expect(fannedByA + fannedByB).toBe(10);
    const deliveries = await db.inspect.webhookDelivery.findMany({ where: { userId: owner } });
    expect(deliveries).toHaveLength(10);
    expect(new Set(deliveries.map((d) => d.eventId)).size).toBe(10);
    const events = await db.inspect.webhookEvent.findMany({ where: { userId: owner } });
    expect(events.every((event) => event.fannedOutAt && event.body)).toBe(true);
  });

  it("excludes endpoints created after the event and honours the backlog cap", async () => {
    const owner = await seedOwner(db.inspect);
    const old = await endpointFor(owner, { createdAt: new Date(Date.now() - 60_000) });
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: sandbox.id } });
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { state: "READY", readyAt: new Date() },
    });
    const late = await endpointFor(owner, { createdAt: new Date(Date.now() + 60_000) });
    // Fill the old endpoint's backlog past the cap.
    const eventId = await eventFor(owner);
    await db.inspect.webhookDelivery.createMany({
      data: Array.from({ length: schedule.ENDPOINT_BACKLOG_CAP + 1 }, () => ({
        eventId,
        endpointId: old.id,
        userId: owner,
        kind: "event",
        maxAttempts: 1,
        nextAttemptAt: new Date(Date.now() + 3_600_000),
        enqueuedAt: new Date(),
        expiresAt: new Date(Date.now() + 86_400_000),
      })),
    });
    await ledger.fanOutEvents(db.prisma);
    const fresh = await db.inspect.webhookDelivery.findMany({
      where: { userId: owner, NOT: { eventId } },
      select: { endpointId: true, state: true, lastErrorClass: true },
    });
    expect(fresh).toEqual([
      { endpointId: old.id, state: "CANCELLED", lastErrorClass: "backlog_overflow" },
    ]);
    expect(fresh.some((row) => row.endpointId === late.id)).toBe(false);
    await db.inspect.webhookDelivery.deleteMany({ where: { eventId } });
  });
});

describe("claim, record and recovery (real PostgreSQL)", () => {
  it("the claim CAS rejects a stale attempt or seq and enforces the in-flight cap", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const first = await pending(owner, endpoint.id);
    const opts = { configured: true, privateScope: "all" as const, client: db.prisma };
    expect(
      (await ledger.claimDelivery({ deliveryId: first.id, attempt: 2, seq: 0 }, opts)).kind,
    ).toBe("skipped");
    expect(
      (await ledger.claimDelivery({ deliveryId: first.id, attempt: 1, seq: 7 }, opts)).kind,
    ).toBe("skipped");
    expect(
      (await ledger.claimDelivery({ deliveryId: first.id, attempt: 1, seq: 0 }, opts)).kind,
    ).toBe("claimed");
    // Replaying the same job after it claimed is a no-op.
    expect(
      (await ledger.claimDelivery({ deliveryId: first.id, attempt: 1, seq: 0 }, opts)).kind,
    ).toBe("skipped");
    const second = await pending(owner, endpoint.id);
    expect(
      (await ledger.claimDelivery({ deliveryId: second.id, attempt: 1, seq: 0 }, opts)).kind,
    ).toBe("claimed");
    const third = await pending(owner, endpoint.id);
    const before = await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: third.id } });
    const capped = await ledger.claimDelivery({ deliveryId: third.id, attempt: 1, seq: 0 }, opts);
    // At the cap the row goes back to the Postgres backlog unreleased: no job,
    // no 2-5 s reschedule; its due time is unchanged.
    expect(capped).toEqual({ kind: "deferred", reason: "at_cap" });
    const row = await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: third.id } });
    expect(row).toMatchObject({ state: "PENDING", enqueueSeq: 1, enqueuedAt: null });
    expect(row.nextAttemptAt).toEqual(before.nextAttemptAt);
  });

  it("lease expiry returns IN_FLIGHT work to PENDING as worker_lost with a fresh seq", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const delivery = await pending(owner, endpoint.id);
    await ledger.claimDelivery(
      { deliveryId: delivery.id, attempt: 1, seq: 0 },
      { configured: true, privateScope: "all", client: db.prisma },
    );
    const later = new Date(Date.now() + schedule.DELIVERY_LEASE_MS + 1000);
    const result = await ledger.runMaintenance({ client: db.prisma, now: later });
    expect(result.reclaimed).toBeGreaterThanOrEqual(1);
    expect(
      await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: delivery.id } }),
    ).toMatchObject({
      state: "PENDING",
      attemptCount: 1,
      lastErrorClass: "worker_lost",
      enqueueSeq: 1,
      enqueuedAt: null,
      leaseUntil: null,
    });
  });

  it("releases never-released and lost rows, never future retries, and recovers a Redis failure", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const neverEnqueued = await pending(owner, endpoint.id, {
      nextAttemptAt: new Date(Date.now() - 60_000),
    });
    const lost = await pending(owner, endpoint.id, {
      enqueuedAt: new Date(Date.now() - 10 * 60_000),
      nextAttemptAt: new Date(Date.now() - 5 * 60_000),
    });
    const retryLater = await pending(owner, endpoint.id, {
      nextAttemptAt: new Date(Date.now() + 3_600_000),
    });
    const added: { deliveryId: string; seq: number; attempt: number }[] = [];
    await ledger.enqueuePending(async (requests) => {
      added.push(...[requests].flat());
    }, db.prisma);
    const mine = added.filter((r) =>
      [neverEnqueued.id, lost.id, retryLater.id].includes(r.deliveryId),
    );
    expect(mine.map((r) => r.deliveryId).sort()).toEqual([neverEnqueued.id, lost.id].sort());
    expect(mine.every((r) => r.seq === 1 && r.attempt === 1)).toBe(true);
    const rows = await db.inspect.webhookDelivery.findMany({
      where: { id: { in: [neverEnqueued.id, lost.id] } },
    });
    expect(rows.every((row) => row.enqueuedAt !== null && row.enqueueSeq === 1)).toBe(true);
    // enqueuedAt is database time, whatever the worker clock says.
    const other = await endpointFor(owner);
    const skewed = await pending(owner, other.id, {
      nextAttemptAt: new Date(Date.now() - 60_000),
    });
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3_600_000);
    try {
      await ledger.enqueuePending(async () => {}, db.prisma);
    } finally {
      vi.useRealTimers();
    }
    const [clock] = await db.inspect.$queryRaw<{ now: Date }[]>`
      SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    const skewedRow = await db.inspect.webhookDelivery.findUniqueOrThrow({
      where: { id: skewed.id },
    });
    expect(Math.abs(skewedRow.enqueuedAt!.getTime() - clock!.now.getTime())).toBeLessThan(60_000);
    // A Redis failure un-releases exactly that seq (one batched statement), so
    // the next sweep releases it again under a fresh seq.
    const third = await endpointFor(owner);
    const again = await pending(owner, third.id, { nextAttemptAt: new Date(Date.now() - 60_000) });
    await ledger.enqueuePending(async () => {
      throw new Error("redis down");
    }, db.prisma);
    expect(
      await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: again.id } }),
    ).toMatchObject({ enqueuedAt: null, enqueueSeq: 1 });
    const retried: { deliveryId: string; seq: number }[] = [];
    await ledger.enqueuePending(
      async (requests) => void retried.push(...[requests].flat()),
      db.prisma,
    );
    expect(retried.filter((r) => r.deliveryId === again.id)).toEqual([
      { deliveryId: again.id, attempt: 1, seq: 2 },
    ]);
  });

  it("delivers end to end: signed body, success resets health; failures retry, exhaust and disable once", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner, {
      consecutiveFailures: 3,
      failingSince: new Date(Date.now() - 3600_000),
    });
    let status = 204;
    const fake = transport(() => status);
    const enqueued: { deliveryId: string; attempt: number; seq: number }[] = [];
    const notify = vi.fn(async () => {});
    const deps = {
      config: config(),
      enqueue: async (
        requests: readonly { deliveryId: string; attempt: number; seq: number }[],
      ) => {
        enqueued.push(...[requests].flat());
      },
      notifyDisabled: notify,
      transport: { resolve: fake.resolve, connect: fake.connect },
      client: db.prisma,
    };
    const ok = await pending(owner, endpoint.id);
    expect(await runDeliveryJob({ deliveryId: ok.id, attempt: 1, seq: 0 }, deps)).toMatchObject({
      outcome: "SUCCEEDED",
      statusCode: 204,
    });
    expect(fake.received[0]?.body).toBe('{"hello":"world"}');
    expect(fake.received[0]?.headers["webhook-id"]).toBe(ok.eventId);
    expect(fake.received[0]?.headers["webhook-signature"]).toMatch(/^v1,[A-Za-z0-9+/]+=*$/);
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({ where: { id: endpoint.id } }),
    ).toMatchObject({ consecutiveFailures: 0, failingSince: null });
    expect(
      await db.inspect.webhookDeliveryAttempt.findMany({ where: { deliveryId: ok.id } }),
    ).toHaveLength(1);

    status = 500;
    const failing = await pending(owner, endpoint.id);
    const retry = await runDeliveryJob({ deliveryId: failing.id, attempt: 1, seq: 0 }, deps);
    expect(retry).toMatchObject({ outcome: "PENDING", errorClass: "http_status", statusCode: 500 });
    // The retry waits unreleased in Postgres (no delayed job in Redis) ...
    expect(enqueued.some((r) => r.deliveryId === failing.id)).toBe(false);
    const waiting = await db.inspect.webhookDelivery.findUniqueOrThrow({
      where: { id: failing.id },
    });
    expect(waiting).toMatchObject({ state: "PENDING", enqueueSeq: 1, enqueuedAt: null });
    expect(waiting.nextAttemptAt!.getTime()).toBeGreaterThan(Date.now());
    // ... and is released as attempt 2 once due.
    await ledger.releaseEndpoints(deps.enqueue, [endpoint.id], { client: db.prisma });
    expect(enqueued.some((r) => r.deliveryId === failing.id)).toBe(false);
    await ledger.releaseEndpoints(deps.enqueue, [endpoint.id], {
      client: db.prisma,
      now: new Date(waiting.nextAttemptAt!.getTime() + 1000),
    });
    expect(enqueued.at(-1)).toEqual({ deliveryId: failing.id, attempt: 2, seq: 2 });

    // Exhaustion: the last allowed attempt fails for good.
    const exhausted = await pending(owner, endpoint.id, { maxAttempts: 1 });
    expect(
      await runDeliveryJob({ deliveryId: exhausted.id, attempt: 1, seq: 0 }, deps),
    ).toMatchObject({ outcome: "FAILED" });

    // Disable: failing for 73 h with 19 failures; the next failure disables, cancels, notifies once.
    await db.inspect.webhookEndpoint.update({
      where: { id: endpoint.id },
      data: { consecutiveFailures: 19, failingSince: new Date(Date.now() - 73 * 3_600_000) },
    });
    const victim = await pending(owner, endpoint.id);
    const bystander = await pending(owner, endpoint.id, {
      nextAttemptAt: new Date(Date.now() + 3_600_000),
    });
    await runDeliveryJob({ deliveryId: victim.id, attempt: 1, seq: 0 }, deps);
    const disabled = await db.inspect.webhookEndpoint.findUniqueOrThrow({
      where: { id: endpoint.id },
    });
    expect(disabled).toMatchObject({
      disabledReason: "sustained_failures",
      consecutiveFailures: 20,
    });
    expect(disabled.disabledAt).not.toBeNull();
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith({
      userId: owner,
      host: "192.168.50.10",
      consecutiveFailures: 20,
    });
    expect(
      (await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: bystander.id } })).state,
    ).toBe("CANCELLED");
    // The pending retry of `failing` is cancelled too; its job is a no-op now.
    expect(await runDeliveryJob({ deliveryId: failing.id, attempt: 2, seq: 2 }, deps)).toEqual({
      outcome: "skipped",
      reason: "terminal",
    });
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it("a worker without the key defers as not configured and never counts a failure", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const delivery = await pending(owner, endpoint.id);
    const enqueued: unknown[] = [];
    const result = await runDeliveryJob(
      { deliveryId: delivery.id, attempt: 1, seq: 0 },
      { config: null, enqueue: async (r) => void enqueued.push(...[r].flat()), client: db.prisma },
    );
    expect(result).toEqual({ outcome: "deferred" });
    // Back to the backlog, due again in 60 s; no job is re-added.
    expect(enqueued).toHaveLength(0);
    const row = await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: delivery.id } });
    expect(row).toMatchObject({
      state: "PENDING",
      attemptCount: 0,
      enqueueSeq: 1,
      enqueuedAt: null,
    });
    expect(row.nextAttemptAt!.getTime()).toBeGreaterThan(Date.now() + 30_000);
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({ where: { id: endpoint.id } }),
    ).toMatchObject({ consecutiveFailures: 0 });
  });

  it("a root rotation re-encrypts under the current root kid; a raw-root row fails closed", async () => {
    const owner = await seedOwner(db.inspect);
    const previousRoot = dataRootKey(randomBytes(32).toString("hex"));
    const previousSubkey = deriveSubkey(previousRoot, WEBHOOK_SECRET_PURPOSE);
    const rotated = await endpointFor(owner, {}, previousSubkey);
    expect(
      (await db.inspect.webhookEndpoint.findUniqueOrThrow({ where: { id: rotated.id } }))
        .secretKeyId,
    ).toBe(previousRoot.id);
    // A dev row sealed directly under the root bytes (the retired raw-key
    // scheme) carries the current root kid but must never authenticate.
    const legacy = await endpointFor(owner, {}, { ...subkey, key: dataRootKey(ROOT_HEX).key });

    const result = await ledger.runMaintenance({
      client: db.prisma,
      keys: [subkey, previousSubkey],
    });
    expect(result.rekeyed).toBe(1);
    const rekeyed = await db.inspect.webhookEndpoint.findUniqueOrThrow({
      where: { id: rotated.id },
    });
    expect(rekeyed.secretKeyId).toBe(subkey.rootKeyId);

    const fake = transport(() => 204);
    const deps = {
      config: config(),
      enqueue: async () => {},
      transport: { resolve: fake.resolve, connect: fake.connect },
      client: db.prisma,
    };
    const ok = await pending(owner, rotated.id);
    expect(await runDeliveryJob({ deliveryId: ok.id, attempt: 1, seq: 0 }, deps)).toMatchObject({
      outcome: "SUCCEEDED",
    });
    const refused = await pending(owner, legacy.id);
    expect(
      await runDeliveryJob({ deliveryId: refused.id, attempt: 1, seq: 0 }, deps),
    ).toMatchObject({ errorClass: "not_configured" });
    expect(fake.received).toHaveLength(1);
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({ where: { id: legacy.id } }),
    ).toMatchObject({ consecutiveFailures: 0, secretKeyId: subkey.rootKeyId });
  });

  it("unopenable rows never starve the rekey batch: the cursor advances past them and wraps", async () => {
    const owner = await seedOwner(db.inspect);
    const previousSubkey = deriveSubkey(
      dataRootKey(randomBytes(32).toString("hex")),
      WEBHOOK_SECRET_PURPOSE,
    );
    const unknownSubkey = deriveSubkey(
      dataRootKey(randomBytes(32).toString("hex")),
      WEBHOOK_SECRET_PURPOSE,
    );
    // More unopenable rows than one batch, all sorting before the recoverable ones.
    const failedCount = ledger.REKEY_BATCH + 10;
    for (let i = 0; i < failedCount; i++)
      await endpointFor(owner, { id: `whe_a${String(i).padStart(4, "0")}` }, unknownSubkey);
    const recoverable: string[] = [];
    for (let i = 0; i < 3; i++)
      recoverable.push((await endpointFor(owner, { id: `whe_z${i}` }, previousSubkey)).id);
    const keys = [subkey, previousSubkey];
    const cursor = ledger.newRekeyCursor();
    const ticks: { rekeyed: number; rekeyFailed: number }[] = [];
    const maxTicks = Math.ceil((failedCount + recoverable.length) / ledger.REKEY_BATCH) + 1;
    for (let tick = 0; tick < maxTicks; tick++)
      ticks.push(await ledger.runMaintenance({ client: db.prisma, keys, rekeyCursor: cursor }));
    const rows = await db.inspect.webhookEndpoint.findMany({
      where: { id: { in: recoverable } },
      select: { secretKeyId: true },
    });
    expect(rows.map((row) => row.secretKeyId)).toEqual(recoverable.map(() => subkey.rootKeyId));
    expect(ticks[0]).toMatchObject({ rekeyed: 0, rekeyFailed: ledger.REKEY_BATCH });
    expect(ticks.reduce((sum, t) => sum + t.rekeyed, 0)).toBe(recoverable.length);
    // The scan wrapped: the next tick starts at the front and meets the failed rows again.
    const again = await ledger.runMaintenance({ client: db.prisma, keys, rekeyCursor: cursor });
    expect(again.rekeyed).toBe(0);
    expect(again.rekeyFailed).toBeGreaterThan(0);
    await db.inspect.webhookEndpoint.deleteMany({ where: { userId: owner } });
  });

  it("a demoted admin loses private delivery on the next attempt (M5)", async () => {
    const owner = await seedOwner(db.inspect, { role: "admin" });
    const endpoint = await endpointFor(owner);
    const fake = transport(() => 204);
    const deps = {
      config: config("admins"),
      enqueue: async () => {},
      transport: { resolve: fake.resolve, connect: fake.connect },
      client: db.prisma,
    };
    const first = await pending(owner, endpoint.id);
    expect(await runDeliveryJob({ deliveryId: first.id, attempt: 1, seq: 0 }, deps)).toMatchObject({
      outcome: "SUCCEEDED",
    });
    await db.inspect.user.update({ where: { id: owner }, data: { role: "user" } });
    const second = await pending(owner, endpoint.id);
    expect(await runDeliveryJob({ deliveryId: second.id, attempt: 1, seq: 0 }, deps)).toMatchObject(
      {
        outcome: "PENDING",
        errorClass: "destination_blocked",
      },
    );
    expect(fake.received).toHaveLength(1);
  });

  it("does not insert an attempt row for a delivery deleted mid-attempt (no P2003)", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const delivery = await pending(owner, endpoint.id);
    await ledger.claimDelivery(
      { deliveryId: delivery.id, attempt: 1, seq: 0 },
      { configured: true, privateScope: "all", client: db.prisma },
    );
    await db.inspect.webhookEndpoint.delete({ where: { id: endpoint.id } });
    const outcome = await ledger.recordAttempt(
      { deliveryId: delivery.id, attempt: 1, endpointId: endpoint.id, kind: "event" },
      {
        startedAt: new Date(),
        durationMs: 1,
        statusCode: 204,
        errorClass: null,
        resolvedAddress: null,
        responseExcerpt: null,
        retryAfterSeconds: null,
      },
      { client: db.prisma },
    );
    expect(outcome.state).toBe("lost");
  });
});

describe("release: Postgres holds the backlog, Redis at most the cap per endpoint (D1)", () => {
  type Job = { deliveryId: string; attempt: number; seq: number };
  /** Records every job added, bulk or single (so a regression to per-row adds is seen). */
  function redis() {
    const jobs: Job[] = [];
    return {
      jobs,
      enqueue: async (requests: readonly Job[]) => void jobs.push(...[requests].flat()),
      of: (ids: readonly string[]) => jobs.filter((job) => ids.includes(job.deliveryId)),
    };
  }
  /** `count` due PENDING rows, oldest first (one event), returned in that order. */
  async function backlog(owner: string, endpointId: string, count: number, oldestMsAgo = 600_000) {
    const eventId = await eventFor(owner);
    const base = Date.now() - oldestMsAgo;
    await db.inspect.webhookDelivery.createMany({
      data: Array.from({ length: count }, (_, i) => ({
        eventId,
        endpointId,
        userId: owner,
        kind: "event",
        maxAttempts: schedule.WEBHOOK_MAX_ATTEMPTS,
        nextAttemptAt: new Date(base + i * 100),
        expiresAt: new Date(Date.now() + schedule.WEBHOOK_DELIVERY_WINDOW_MS),
      })),
    });
    const rows = await db.inspect.webhookDelivery.findMany({
      where: { endpointId, eventId },
      orderBy: [{ nextAttemptAt: "asc" }, { id: "asc" }],
      select: { id: true },
    });
    return rows.map((row) => row.id);
  }
  const claimOpts = { configured: true, privateScope: "all" as const, client: db.prisma };

  it("a slow endpoint with a large backlog holds at most the cap in Redis and does no per-row churn", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 40);
    const r = redis();
    await ledger.enqueuePending(r.enqueue, db.prisma);
    // Exactly the cap, oldest first, attempt 1 under a fresh seq.
    expect(r.of(ids)).toEqual([
      { deliveryId: ids[0], attempt: 1, seq: 1 },
      { deliveryId: ids[1], attempt: 1, seq: 1 },
    ]);
    // Both claimed and still sending (a slow receiver): sweep after sweep adds
    // nothing and touches no backlog row.
    for (const id of ids.slice(0, 2))
      expect(
        (await ledger.claimDelivery({ deliveryId: id, attempt: 1, seq: 1 }, claimOpts)).kind,
      ).toBe("claimed");
    for (let sweep = 0; sweep < 5; sweep++) await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(ids)).toHaveLength(2);
    const rest = await db.inspect.webhookDelivery.findMany({
      where: { id: { in: ids.slice(2) } },
      select: { enqueueSeq: true, enqueuedAt: true, state: true },
    });
    expect(rest).toHaveLength(38);
    expect(rest.every((row) => row.enqueueSeq === 0 && row.enqueuedAt === null)).toBe(true);
    expect(rest.every((row) => row.state === "PENDING")).toBe(true);
  });

  it("another owner's delivery is released in the same sweep as a huge backlog", async () => {
    const busy = await seedOwner(db.inspect);
    const busyEndpoint = await endpointFor(busy);
    const busyIds = await backlog(busy, busyEndpoint.id, 450);
    const quiet = await seedOwner(db.inspect);
    const quietEndpoint = await endpointFor(quiet);
    // Newer than every backlog row, so a global oldest-first batch would starve it.
    const quietIds = await backlog(quiet, quietEndpoint.id, 1, 1_000);
    const r = redis();
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(quietIds)).toEqual([{ deliveryId: quietIds[0], attempt: 1, seq: 1 }]);
    expect(r.of(busyIds)).toHaveLength(2);
  });

  it("a finished attempt (success or failure) releases the endpoint's next row at once", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 5);
    let status = 204;
    const fake = transport(() => status);
    const r = redis();
    const deps = {
      config: config(),
      enqueue: r.enqueue,
      notifyDisabled: async () => {},
      transport: { resolve: fake.resolve, connect: fake.connect },
      client: db.prisma,
    };
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(ids).map((job) => job.deliveryId)).toEqual([ids[0], ids[1]]);
    expect(await runDeliveryJob(r.of([ids[0] as string])[0] as Job, deps)).toMatchObject({
      outcome: "SUCCEEDED",
    });
    // No dispatcher poll in between: the attempt itself handed out the next row.
    expect(r.of(ids).map((job) => job.deliveryId)).toEqual([ids[0], ids[1], ids[2]]);
    status = 500;
    expect(await runDeliveryJob(r.of([ids[1] as string])[0] as Job, deps)).toMatchObject({
      outcome: "PENDING",
    });
    // The failed one waits for its retry time; the slot goes to the next row.
    expect(r.of(ids).map((job) => job.deliveryId)).toEqual([ids[0], ids[1], ids[2], ids[3]]);
  });

  it("a crash between release and the Redis add loses nothing and never double-claims", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 3);
    // The process dies after the release committed, before the add returned.
    void ledger.enqueuePending(() => new Promise<void>(() => {}), db.prisma);
    await vi.waitFor(async () => {
      const released = await db.inspect.webhookDelivery.count({
        where: { id: { in: ids }, enqueuedAt: { not: null } },
      });
      expect(released).toBe(2);
    });
    // The reserved slots hold: a sweep within the grace adds nothing.
    const r = redis();
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(ids)).toEqual([]);
    // Past the lost-job grace the same rows are released again under a new seq.
    const later = new Date(Date.now() + ledger.LOST_JOB_GRACE_MS + 5_000);
    await ledger.enqueuePending(r.enqueue, db.prisma, later);
    expect(r.of(ids)).toEqual([
      { deliveryId: ids[0], attempt: 1, seq: 2 },
      { deliveryId: ids[1], attempt: 1, seq: 2 },
    ]);
    // Had the first add reached Redis after all, that job is now a no-op.
    expect(
      await ledger.claimDelivery({ deliveryId: ids[0] as string, attempt: 1, seq: 1 }, claimOpts),
    ).toEqual({ kind: "skipped", reason: "stale" });
    expect(
      (await ledger.claimDelivery({ deliveryId: ids[0] as string, attempt: 1, seq: 2 }, claimOpts))
        .kind,
    ).toBe("claimed");
  });

  it("concurrent releasers never put more than the cap in Redis", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 12);
    const r = redis();
    await Promise.all([
      ledger.enqueuePending(r.enqueue, db.prisma),
      ledger.enqueuePending(r.enqueue, db.prisma),
      ledger.releaseEndpoints(r.enqueue, [endpoint.id], { client: db.prisma }),
      ledger.releaseEndpoints(r.enqueue, [endpoint.id], { client: db.prisma }),
      ledger.releaseEndpoints(r.enqueue, [endpoint.id], { client: db.prisma }),
    ]);
    expect(r.of(ids)).toHaveLength(2);
    expect(new Set(r.of(ids).map((job) => job.deliveryId)).size).toBe(2);
  });

  it("a job that races into a full endpoint goes back to the backlog without a re-add", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 3);
    for (const id of ids.slice(0, 2))
      await ledger.claimDelivery({ deliveryId: id, attempt: 1, seq: 0 }, claimOpts);
    const r = redis();
    const late = ids[2] as string;
    const before = await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: late } });
    const result = await runDeliveryJob(
      { deliveryId: late, attempt: 1, seq: 0 },
      { config: config(), enqueue: r.enqueue, client: db.prisma },
    );
    expect(result).toEqual({ outcome: "deferred" });
    expect(r.jobs).toEqual([]);
    // Same due time (no 2-5 s reschedule): it keeps its place in the oldest-first order.
    expect(
      await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: late } }),
    ).toMatchObject({
      state: "PENDING",
      enqueueSeq: 1,
      enqueuedAt: null,
      attemptCount: 0,
      nextAttemptAt: before.nextAttemptAt,
    });
    // Both slots are in flight, so the sweep keeps it in Postgres.
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of([late])).toEqual([]);
  });

  it("manual sends (test, redeliver) take the next free slots ahead of an older automatic backlog", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 50);
    const r = redis();
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(ids).map((job) => job.deliveryId)).toEqual([ids[0], ids[1]]);
    for (const id of ids.slice(0, 2))
      expect(
        (await ledger.claimDelivery({ deliveryId: id, attempt: 1, seq: 1 }, claimOpts)).kind,
      ).toBe("claimed");
    // Newer than every backlog row: oldest-due-first alone would queue them last.
    const test = await pending(owner, endpoint.id, { kind: "test" });
    const redeliver = await pending(owner, endpoint.id, {
      kind: "redeliver",
      nextAttemptAt: new Date(Date.now() - 1_000),
    });
    const manual = [redeliver.id, test.id];
    // Both slots are in flight: manual sends still respect the cap.
    await ledger.enqueuePending(r.enqueue, db.prisma);
    expect(r.of(manual)).toEqual([]);
    expect(r.of(ids)).toHaveLength(2);
    // One slot frees: the oldest due manual send takes it, no automatic row.
    await db.inspect.webhookDelivery.update({
      where: { id: ids[0] },
      data: { state: "SUCCEEDED", leaseUntil: null, completedAt: new Date() },
    });
    await ledger.releaseEndpoints(r.enqueue, [endpoint.id], { client: db.prisma });
    expect(r.of(manual)).toEqual([{ deliveryId: redeliver.id, attempt: 1, seq: 1 }]);
    expect(r.of(ids)).toHaveLength(2);
    // Both slots free: the remaining manual send first, then the oldest automatic row.
    await db.inspect.webhookDelivery.updateMany({
      where: { id: { in: [ids[1] as string, redeliver.id] } },
      data: { state: "SUCCEEDED", leaseUntil: null, enqueuedAt: null, completedAt: new Date() },
    });
    await ledger.releaseEndpoints(r.enqueue, [endpoint.id], { client: db.prisma });
    expect(new Set(r.jobs.slice(-2).map((job) => job.deliveryId))).toEqual(
      new Set([test.id, ids[2]]),
    );
    expect(r.of(ids.slice(3))).toEqual([]);
  });

  it("the manual pick reads the partial index, not the automatic backlog", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    await backlog(owner, endpoint.id, 50);
    await pending(owner, endpoint.id, { kind: "test" });
    await db.inspect.$executeRaw`ANALYZE webhook_delivery`;
    // Index use is the point, not the planner's cost guess on a tiny table.
    const plan = await db.inspect.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL enable_seqscan = off");
      return tx.$queryRaw<{ "QUERY PLAN": unknown }[]>`
        EXPLAIN (FORMAT JSON) SELECT d.id FROM webhook_delivery d
        WHERE d."endpointId" = ${endpoint.id} AND d.state = 'PENDING' AND d.kind <> 'event'
          AND d."nextAttemptAt" <= now()
        ORDER BY d."nextAttemptAt", d.id LIMIT 2`;
    });
    expect(JSON.stringify(plan)).toContain('"Index Name":"webhook_delivery_manual_due_idx"');
  });

  it("an expired released row frees its slot for the next one", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const ids = await backlog(owner, endpoint.id, 3);
    const r = redis();
    await ledger.enqueuePending(r.enqueue, db.prisma);
    await db.inspect.webhookDelivery.update({
      where: { id: ids[0] },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    expect(
      await runDeliveryJob(r.of([ids[0] as string])[0] as Job, {
        config: config(),
        enqueue: r.enqueue,
        client: db.prisma,
      }),
    ).toEqual({ outcome: "skipped", reason: "terminal" });
    expect(r.of(ids).map((job) => job.deliveryId)).toEqual([ids[0], ids[1], ids[2]]);
  });
});

describe("fan-out backlog cap (JS-4: counted once per pass, exact at the boundary)", () => {
  it("one pass crossing the cap cancels exactly the delivery past it", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner, { createdAt: new Date(Date.now() - 60_000) });
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: sandbox.id } });
    const filler = await eventFor(owner);
    await db.inspect.webhookDelivery.createMany({
      data: Array.from({ length: schedule.ENDPOINT_BACKLOG_CAP - 1 }, () => ({
        eventId: filler,
        endpointId: endpoint.id,
        userId: owner,
        kind: "event",
        maxAttempts: 1,
        nextAttemptAt: new Date(Date.now() + 3_600_000),
        expiresAt: new Date(Date.now() + 86_400_000),
      })),
    });
    // Three subscribed events (ready, stopped, ready) in one pass: the backlog
    // goes 9,999 -> 10,000 -> 10,001, then the third is past the cap.
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { state: "READY", readyAt: new Date() },
    });
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "STOPPING" } });
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "STOPPED" } });
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { state: "READY", readyAt: new Date() },
    });
    await ledger.fanOutEvents(db.prisma);
    const fresh = await db.inspect.webhookDelivery.findMany({
      where: { endpointId: endpoint.id, NOT: { eventId: filler } },
      select: { state: true, lastErrorClass: true, Event: { select: { seq: true } } },
    });
    const states = fresh.sort((a, b) => Number(a.Event.seq - b.Event.seq)).map((row) => row.state);
    expect(states).toEqual(["PENDING", "PENDING", "CANCELLED"]);
    expect(fresh.filter((row) => row.state === "CANCELLED")[0]?.lastErrorClass).toBe(
      "backlog_overflow",
    );
    await db.inspect.webhookDelivery.deleteMany({ where: { endpointId: endpoint.id } });
  });
});

describe("services against the ledger (real PostgreSQL)", () => {
  function configure() {
    service.setWebhookDestinationResolverForTests(async () => ["93.184.215.14"]);
    vi.stubEnv("DATA_ENCRYPTION_KEY", ROOT_HEX);
    vi.stubEnv("WEBHOOK_ALLOWED_PRIVATE_CIDRS", "");
    resetWebhookConfigForTests();
  }

  it("redeliver creates a new delivery with the same event id", async () => {
    configure();
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const original = await pending(owner, endpoint.id);
    const result = await service.redeliverWebhook(sessionPrincipal(owner), { id: original.id });
    expect(result.eventId).toBe(original.eventId);
    expect(result.deliveryId).not.toBe(original.id);
    expect(
      await db.inspect.webhookDelivery.findUniqueOrThrow({ where: { id: result.deliveryId } }),
    ).toMatchObject({ kind: "redeliver", state: "PENDING", eventId: original.eventId });
  });

  it("the 10-endpoint cap holds under a concurrent create race (advisory lock)", async () => {
    configure();
    const owner = await seedOwner(db.inspect);
    const results = await Promise.allSettled(
      Array.from({ length: 13 }, (_, i) =>
        service.createWebhookEndpoint(sessionPrincipal(owner), {
          url: `https://hooks${i}.example.com/x`,
          events: ["sandbox.ready"],
        }),
      ),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(10);
    for (const r of results.filter((x) => x.status === "rejected"))
      expect((r as PromiseRejectedResult).reason).toMatchObject({
        code: "CONFLICT",
        data: { code: "webhook.endpoint_limit" },
      });
    expect(await db.inspect.webhookEndpoint.count({ where: { userId: owner } })).toBe(10);
  });

  it("an expired rotation overlap stops signing, reads as null, and is cleared by maintenance", async () => {
    configure();
    const owner = await seedOwner(db.inspect);
    const principal = sessionPrincipal(owner);
    const endpoint = await endpointFor(owner);
    const live = await endpointFor(owner);
    const rotated = await service.rotateWebhookSecret(principal, {
      id: endpoint.id,
      overlapSeconds: 60,
    });
    await service.rotateWebhookSecret(principal, { id: live.id, overlapSeconds: 3600 });
    expect(rotated.endpoint.previousSecretExpiresAt).not.toBeNull();
    const claim = async () => {
      const delivery = await pending(owner, endpoint.id);
      const outcome = await ledger.claimDelivery(
        { deliveryId: delivery.id, attempt: 1, seq: 0 },
        { configured: true, privateScope: "all", client: db.prisma },
      );
      if (outcome.kind !== "claimed") throw new Error(`unexpected claim ${outcome.kind}`);
      // Settle it so the per-endpoint in-flight cap never defers the next claim.
      await db.inspect.webhookDelivery.update({
        where: { id: delivery.id },
        data: { state: "SUCCEEDED", leaseUntil: null, completedAt: new Date() },
      });
      return ledger.signingKeys(outcome.delivery, [subkey]);
    };
    // During the overlap both secrets sign.
    expect(await claim()).toHaveLength(2);

    // The overlap expires (moved into the past; no global clock jump).
    await db.inspect.webhookEndpoint.update({
      where: { id: endpoint.id },
      data: { previousSecretExpiresAt: new Date(Date.now() - 1000) },
    });
    // Before any maintenance tick: only the current secret signs and the API
    // no longer reports the past expiry, although the columns are still stored.
    expect(await claim()).toHaveLength(1);
    expect(
      (await service.getWebhookEndpoint(principal, { id: endpoint.id })).previousSecretExpiresAt,
    ).toBeNull();
    const listed = await service.listWebhookEndpoints(principal, {});
    expect(
      listed.items.find((item) => item.id === endpoint.id)?.previousSecretExpiresAt,
    ).toBeNull();
    expect(
      listed.items.find((item) => item.id === live.id)?.previousSecretExpiresAt,
    ).not.toBeNull();
    expect(
      (await db.inspect.webhookEndpoint.findUniqueOrThrow({ where: { id: endpoint.id } }))
        .previousSecretCiphertext,
    ).not.toBeNull();

    const result = await ledger.runMaintenance({ client: db.prisma });
    expect(result.clearedOverlaps).toBeGreaterThanOrEqual(1);
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({
        where: { id: endpoint.id },
        select: {
          secretVersion: true,
          previousSecretCiphertext: true,
          previousSecretNonce: true,
          previousSecretKeyId: true,
          previousSecretVersion: true,
          previousSecretExpiresAt: true,
        },
      }),
    ).toEqual({
      secretVersion: 2,
      previousSecretCiphertext: null,
      previousSecretNonce: null,
      previousSecretKeyId: null,
      previousSecretVersion: null,
      previousSecretExpiresAt: null,
    });
    // A live overlap on another endpoint is untouched.
    expect(
      await db.inspect.webhookEndpoint.findUniqueOrThrow({
        where: { id: live.id },
        select: { previousSecretVersion: true },
      }),
    ).toEqual({ previousSecretVersion: 1 });
    // Signing is unchanged after the clear: the current secret only.
    expect(await claim()).toHaveLength(1);
  });

  it("account deletion removes endpoints, deliveries, attempts and events", async () => {
    configure();
    const owner = await seedOwner(db.inspect);
    const endpoint = await endpointFor(owner);
    const delivery = await pending(owner, endpoint.id);
    await db.inspect.webhookDeliveryAttempt.create({
      data: { deliveryId: delivery.id, attempt: 1, startedAt: new Date(), durationMs: 1 },
    });
    expect(await requestAccountDeletion(owner)).toBe(true);
    expect(await db.inspect.webhookEndpoint.count({ where: { userId: owner } })).toBe(0);
    expect(await db.inspect.webhookEvent.count({ where: { userId: owner } })).toBe(0);
    expect(await db.inspect.webhookDelivery.count({ where: { userId: owner } })).toBe(0);
    expect(
      await db.inspect.webhookDeliveryAttempt.count({ where: { deliveryId: delivery.id } }),
    ).toBe(0);
  });
});
