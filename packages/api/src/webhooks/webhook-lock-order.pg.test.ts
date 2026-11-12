import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));

const db = await pgTestDatabase();
const { seedEndpoint, seedOwner, seedSandbox } = await import("./testing/fixtures");
const { claimDelivery, fanOutEvents, newFanOutCursor, reapWebhookLog } = await import("./ledger");
const { requestAccountDeletion } = await import("@wssp/db/account-deletion");

async function seedClaimable() {
  const owner = await seedOwner(db.inspect);
  const endpoint = await seedEndpoint(db.inspect, owner, { url: "https://hooks.example.com/x" });
  const eventId = `evt_${"c".repeat(24)}${Math.random().toString(16).slice(2, 10).padEnd(8, "0")}`;
  await db.inspect.webhookEvent.create({
    data: {
      id: eventId,
      userId: owner,
      type: "webhook.test",
      facts: {},
      body: "{}",
      fannedOutAt: new Date(),
    },
  });
  const delivery = await db.inspect.webhookDelivery.create({
    data: {
      eventId,
      endpointId: endpoint.id,
      userId: owner,
      kind: "event",
      maxAttempts: 11,
      nextAttemptAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    },
  });
  return { owner, endpoint, delivery };
}
const claimOptions = { configured: true, privateScope: "all" as const, client: db.prisma };
const ENDPOINT_LOCK = /^sql:SELECT id, "userId", url, "disabledAt".*FOR NO KEY UPDATE$/;
afterAll(() => db.close());

/** Open a transaction as `actor`, take `lock`, and hold it until released. */
function holdLock(actor: string, lock: (tx: typeof db.prisma) => Promise<unknown>) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let ready!: () => void;
  const locked = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const done = db.run(actor, () =>
    db.prisma.$transaction(async (tx) => {
      await lock(tx as unknown as typeof db.prisma);
      ready();
      await released;
    }),
  );
  return { locked, release, done };
}

describe("webhook emission adds no lock-order edge (real PostgreSQL)", () => {
  it("an emitting transition commits while another transaction holds the owner row FOR UPDATE", async () => {
    const owner = await seedOwner(db.inspect);
    await seedEndpoint(db.inspect, owner);
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    // Account finalization holds exactly this lock for its whole transaction.
    const holder = holdLock(
      "finalizer",
      (tx) => tx.$queryRaw`SELECT id FROM "user" WHERE id = ${owner} FOR UPDATE`,
    );
    await holder.locked;
    // The trigger's event insert has no FK, so it takes no key-share lock on
    // "user": the transition completes instead of queueing behind the holder.
    await db.run("emitter", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
      }),
    );
    expect(
      await db.inspect.webhookEvent.count({
        where: { sandboxId: sandbox.id, type: "sandbox.ready" },
      }),
    ).toBe(1);
    holder.release();
    await holder.done;
  });

  it("an emitting transition never waits on an endpoint row being edited", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await seedEndpoint(db.inspect, owner);
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    const holder = holdLock(
      "editor",
      (tx) => tx.$queryRaw`SELECT id FROM webhook_endpoint WHERE id = ${endpoint.id} FOR UPDATE`,
    );
    await holder.locked;
    await db.run("emitter2", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
      }),
    );
    expect(await db.inspect.webhookEvent.count({ where: { sandboxId: sandbox.id } })).toBe(1);
    holder.release();
    await holder.done;
  });

  it("a credential event emits while its endpoint row is being edited (no new lock edge)", async () => {
    const owner = await seedOwner(db.inspect);
    const endpoint = await seedEndpoint(db.inspect, owner);
    const holder = holdLock(
      "credential-editor",
      (tx) => tx.$queryRaw`SELECT id FROM webhook_endpoint WHERE id = ${endpoint.id} FOR UPDATE`,
    );
    await holder.locked;
    await db.run("credential-emitter", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.credentialEvent.create({
          data: { userId: owner, credentialId: "cred-1", type: "recovery_required", reason: "x" },
        });
      }),
    );
    expect(
      await db.inspect.webhookEvent.count({
        where: { userId: owner, type: "credential.recovery_required" },
      }),
    ).toBe(1);
    holder.release();
    await holder.done;
  });

  it("claim then account finalization: finalization waits on the claim's endpoint lock, no deadlock", async () => {
    const { owner, delivery } = await seedClaimable();
    const gate = db.pauseAt("claimer", { after: ENDPOINT_LOCK });
    const claim = db.run("claimer", () =>
      claimDelivery({ deliveryId: delivery.id, attempt: 1, seq: 0 }, claimOptions),
    );
    await gate.waitReached();
    const deletion = db.run("finalizer", () => requestAccountDeletion(owner));
    await db.waitUntilBlocked("finalizer", { by: "claimer" });
    gate.release();
    expect((await claim).kind).toBe("claimed");
    expect(await deletion).toBe(true);
    expect(await db.inspect.webhookDelivery.count({ where: { id: delivery.id } })).toBe(0);
  });

  it("account finalization then claim: the claim waits, then finds nothing (same lock order)", async () => {
    const { owner, delivery } = await seedClaimable();
    const gate = db.pauseAt("finalizer2", { after: "webhookEndpoint.deleteMany" });
    const deletion = db.run("finalizer2", () => requestAccountDeletion(owner));
    await gate.waitReached();
    const claim = db.run("claimer2", () =>
      claimDelivery({ deliveryId: delivery.id, attempt: 1, seq: 0 }, claimOptions),
    );
    await db.waitUntilBlocked("claimer2", { by: "finalizer2" });
    gate.release();
    expect(await deletion).toBe(true);
    expect(await claim).toEqual({ kind: "skipped", reason: "missing" });
  });
});

/** Fan out everything earlier tests left, so each case sees only its own events. */
async function drain() {
  while ((await fanOutEvents(db.inspect)) > 0);
}

/** An owner whose only state is an endpoint and `count` unfanned events (DELETED sandboxes). */
async function seedFanOutCase(count = 1) {
  const owner = await seedOwner(db.inspect);
  const endpoint = await seedEndpoint(db.inspect, owner, {
    createdAt: new Date(Date.now() - 60_000),
  });
  for (let i = 0; i < count; i++) {
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "DELETED" } });
  }
  const events = await db.inspect.webhookEvent.findMany({
    where: { userId: owner },
    orderBy: { seq: "asc" },
  });
  expect(events).toHaveLength(count);
  return { owner, endpoint, eventId: events[0]!.id, eventIds: events.map((e) => e.id) };
}
const ENDPOINT_KEY_SHARE =
  /^sql:SELECT id, "operationKinds", events, "createdAt" FROM webhook_endpoint/;
const EVENT_LOCK = /^sql:SELECT id, seq, "userId", type, .* FOR UPDATE SKIP LOCKED$/;

describe("fan-out locks endpoints before events, like deletion (review rounds 1-4)", () => {
  it("fan-out first (holding endpoint and event): account finalization waits, then deletes everything", async () => {
    await drain();
    const { owner, eventId } = await seedFanOutCase();
    const gate = db.pauseAt("fanout-a", { after: EVENT_LOCK });
    const fan = db.run("fanout-a", () => fanOutEvents(db.prisma));
    await gate.waitReached();
    const deletion = db.run("finalizer-a", () => requestAccountDeletion(owner));
    await db.waitUntilBlocked("finalizer-a", { by: "fanout-a" });
    gate.release();
    expect(await fan).toBe(1); // no 40P01: the deleter waited, fan-out never waited back
    expect(await deletion).toBe(true);
    expect(await db.inspect.webhookEvent.count({ where: { id: eventId } })).toBe(0);
    expect(await db.inspect.webhookDelivery.count({ where: { userId: owner } })).toBe(0);
  });

  it("account finalization first: fan-out waits on the endpoint, then finds nothing (no FK error)", async () => {
    await drain();
    const { owner } = await seedFanOutCase();
    const gate = db.pauseAt("finalizer-b", { after: "webhookEndpoint.deleteMany" });
    const deletion = db.run("finalizer-b", () => requestAccountDeletion(owner));
    await gate.waitReached();
    const fan = db.run("fanout-b", () => fanOutEvents(db.prisma));
    await db.waitUntilBlocked("fanout-b", { by: "finalizer-b" });
    gate.release();
    expect(await deletion).toBe(true);
    expect(await fan).toBe(0);
    expect(await db.inspect.webhookEvent.count({ where: { userId: owner } })).toBe(0);
  });

  it("an endpoint delete in flight past lock_timeout: the event is retried next poll, never lost", async () => {
    await drain();
    const { endpoint, eventId } = await seedFanOutCase();
    const holder = holdLock("endpoint-delete-c", (tx) =>
      tx.webhookEndpoint.delete({ where: { id: endpoint.id } }),
    );
    await holder.locked;
    const started = Date.now();
    expect(await db.run("fanout-c", () => fanOutEvents(db.prisma))).toBe(0);
    // Bounded by the 2 s lock_timeout, not by the holder.
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(
      (await db.inspect.webhookEvent.findUniqueOrThrow({ where: { id: eventId } })).fannedOutAt,
    ).toBeNull();
    holder.release();
    await holder.done;
    expect(await db.run("fanout-c2", () => fanOutEvents(db.prisma))).toBe(1);
    expect(await db.inspect.webhookDelivery.count({ where: { eventId } })).toBe(0);
  });

  it("fan-out holding the endpoint lock: an endpoint delete waits, then cascades the new deliveries", async () => {
    await drain();
    const { endpoint, eventId } = await seedFanOutCase();
    const gate = db.pauseAt("fanout-d", { after: ENDPOINT_KEY_SHARE });
    const fan = db.run("fanout-d", () => fanOutEvents(db.prisma));
    await gate.waitReached();
    const deleting = db.run("endpoint-delete-d", () =>
      db.prisma.$transaction((tx) => tx.webhookEndpoint.deleteMany({ where: { id: endpoint.id } })),
    );
    await db.waitUntilBlocked("endpoint-delete-d", { by: "fanout-d" });
    gate.release();
    expect(await fan).toBe(1);
    expect((await deleting).count).toBe(1);
    expect(await db.inspect.webhookDelivery.count({ where: { eventId } })).toBe(0);
  });

  it("480 contended events of one owner: another owner's event fans out in the FIRST pass", async () => {
    await drain();
    const a = await seedFanOutCase(480);
    const b = await seedFanOutCase(1);
    const holder = holdLock("endpoint-delete-e", (tx) =>
      tx.webhookEndpoint.delete({ where: { id: a.endpoint.id } }),
    );
    await holder.locked;
    const started = Date.now();
    // One pass: A costs a single lock_timeout, then B (behind 480 of A's) fans out.
    expect(await db.run("fanout-e", () => fanOutEvents(db.prisma))).toBe(1);
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(
      (await db.inspect.webhookEvent.findUniqueOrThrow({ where: { id: b.eventId } })).fannedOutAt,
    ).not.toBeNull();
    expect(await db.inspect.webhookDelivery.count({ where: { eventId: b.eventId } })).toBe(1);
    expect(
      await db.inspect.webhookEvent.count({ where: { userId: a.owner, fannedOutAt: null } }),
    ).toBe(480);
    holder.release();
    await holder.done;
    // Nothing was persisted for A: the next polls fan its events out.
    let fanned = 0;
    for (let pass = 0; pass < 10 && fanned < 480; pass++)
      fanned += await db.run(`fanout-e${pass}`, () => fanOutEvents(db.prisma));
    expect(fanned).toBe(480);
  }, 180_000);

  it("uses the database clock: a skewed worker clock does not move ledger times", async () => {
    await drain();
    const { eventId } = await seedFanOutCase();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3_600_000); // worker clock one hour ahead
    try {
      expect(await db.run("fanout-skew", () => fanOutEvents(db.prisma))).toBe(1);
    } finally {
      vi.useRealTimers();
    }
    const [dbNowRow] = await db.inspect.$queryRaw<{ now: Date }[]>`
      SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    const event = await db.inspect.webhookEvent.findUniqueOrThrow({ where: { id: eventId } });
    const delivery = await db.inspect.webhookDelivery.findFirstOrThrow({ where: { eventId } });
    for (const at of [event.fannedOutAt!, delivery.nextAttemptAt!])
      expect(Math.abs(at.getTime() - dbNowRow!.now.getTime())).toBeLessThan(60_000);
    expect(delivery.expiresAt.getTime() - dbNowRow!.now.getTime()).toBeLessThan(
      24 * 3_600_000 + 60_000,
    );
  });
});

describe("review round 5: ordered multi-endpoint deletion, bounded contention, rotating cursor", () => {
  /** Owner with `endpoints` endpoints (all subscribed) and one unfanned event. */
  async function ownerWithEndpoints(endpoints: number) {
    const owner = await seedOwner(db.inspect);
    const ids: string[] = [];
    for (let i = 0; i < endpoints; i++)
      ids.push(
        (await seedEndpoint(db.inspect, owner, { createdAt: new Date(Date.now() - 60_000) })).id,
      );
    const sandbox = await seedSandbox(db.inspect, owner, "PROVISIONING");
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "DELETED" } });
    const [event] = await db.inspect.webhookEvent.findMany({ where: { userId: owner } });
    return { owner, endpointIds: ids.sort(), eventId: event!.id };
  }

  it("fan-out first with 3 endpoints locked, then account deletion: no 40P01", async () => {
    await drain();
    const { owner } = await ownerWithEndpoints(3);
    const gate = db.pauseAt("fanout-m1", { after: ENDPOINT_KEY_SHARE });
    const fan = db.run("fanout-m1", () => fanOutEvents(db.prisma));
    await gate.waitReached();
    const deletion = db.run("finalizer-m1", () => requestAccountDeletion(owner));
    await db.waitUntilBlocked("finalizer-m1", { by: "fanout-m1" });
    gate.release();
    expect(await fan).toBe(1);
    expect(await deletion).toBe(true);
    expect(await db.inspect.webhookEndpoint.count({ where: { userId: owner } })).toBe(0);
  });

  it("account deletion first with 3 endpoints locked in id order, then fan-out: no 40P01, no FK error", async () => {
    await drain();
    const { owner } = await ownerWithEndpoints(3);
    const gate = db.pauseAt("finalizer-m2", {
      after: /^sql:SELECT id FROM webhook_endpoint WHERE "userId" = \? ORDER BY id FOR UPDATE$/,
    });
    const deletion = db.run("finalizer-m2", () => requestAccountDeletion(owner));
    await gate.waitReached();
    const fan = db.run("fanout-m2", () => fanOutEvents(db.prisma));
    await db.waitUntilBlocked("fanout-m2", { by: "finalizer-m2" });
    gate.release();
    expect(await deletion).toBe(true);
    expect(await fan).toBe(0);
    expect(await db.inspect.webhookEvent.count({ where: { userId: owner } })).toBe(0);
  });

  /** Hold every listed endpoint's delete lock in ONE transaction (one connection). */
  function holdEndpointDeletes(ids: string[]) {
    return holdLock("endpoint-deletes", (tx) =>
      tx.webhookEndpoint.deleteMany({ where: { id: { in: ids } } }),
    );
  }

  it("9 contended owners ahead of a healthy owner: the healthy one delivers in the first pass, quickly", async () => {
    await drain();
    const contended = [];
    for (let i = 0; i < 9; i++) contended.push(await ownerWithEndpoints(1));
    const healthy = await ownerWithEndpoints(1);
    const holder = holdEndpointDeletes(contended.flatMap((c) => c.endpointIds));
    await holder.locked;
    const started = Date.now();
    expect(await db.run("fanout-n1", () => fanOutEvents(db.prisma))).toBe(1);
    const elapsed = Date.now() - started;
    // 9 lock timeouts of 200 ms, well inside the 2 s per-pass contention budget.
    expect(elapsed).toBeLessThan(5_000);
    expect(await db.inspect.webhookDelivery.count({ where: { eventId: healthy.eventId } })).toBe(1);
    holder.release();
    await holder.done;
  });

  it("more contended owners than one pass's budget: the cursor reaches the healthy owner on the next poll", async () => {
    await drain();
    const contended = [];
    for (let i = 0; i < 16; i++) contended.push(await ownerWithEndpoints(1));
    const healthy = await ownerWithEndpoints(1);
    const holder = holdEndpointDeletes(contended.flatMap((c) => c.endpointIds));
    await holder.locked;
    const cursor = newFanOutCursor();
    const delivered = async () =>
      db.inspect.webhookDelivery.count({ where: { eventId: healthy.eventId } });
    const started = Date.now();
    await db.run("fanout-p1", () => fanOutEvents(db.prisma, undefined, cursor));
    const firstPass = Date.now() - started;
    // The pass yields once it has spent its 2 s contention budget.
    expect(firstPass).toBeLessThan(4_000);
    // 16 timeouts of >= 200 ms exceed the budget before the healthy owner (17th).
    expect(await delivered()).toBe(0);
    expect(cursor.contendedMs).toBeGreaterThanOrEqual(2_000);
    // Next poll resumes after the last attempted event instead of the front.
    await db.run("fanout-p2", () => fanOutEvents(db.prisma, undefined, cursor));
    expect(await delivered()).toBe(1);
    holder.release();
    await holder.done;
    // Contended owners' events are picked up once released (the cursor wraps).
    let fanned = 0;
    for (let pass = 0; pass < 5 && fanned < 16; pass++)
      fanned += await db.run(`fanout-p${pass + 3}`, () =>
        fanOutEvents(db.prisma, undefined, cursor),
      );
    expect(fanned).toBe(16);
  }, 60_000);
});

describe("review round 6: retention reaper takes endpoints before events", () => {
  /** An owner whose only state is an endpoint, an 8-day-old event and its delivery. */
  async function oldDeliveryCase() {
    const owner = await seedOwner(db.inspect);
    const endpoint = await seedEndpoint(db.inspect, owner);
    const eventId = `evt_${Math.random().toString(16).slice(2).padEnd(32, "0").slice(0, 32)}`;
    const old = new Date(Date.now() - 8 * 86_400_000);
    await db.inspect.webhookEvent.create({
      data: {
        id: eventId,
        userId: owner,
        type: "webhook.test",
        occurredAt: old,
        facts: {},
        body: "{}",
        fannedOutAt: old,
      },
    });
    await db.inspect.webhookDelivery.create({
      data: {
        eventId,
        endpointId: endpoint.id,
        userId: owner,
        kind: "event",
        maxAttempts: 11,
        state: "FAILED",
        expiresAt: new Date(old.getTime() + 86_400_000),
      },
    });
    return { owner, eventId };
  }

  it("reaper first (holding endpoints, events and deliveries): finalization waits; both complete", async () => {
    const { owner, eventId } = await oldDeliveryCase();
    const gate = db.pauseAt("reaper-a", { after: "webhookEvent.deleteMany" });
    const reaping = db.run("reaper-a", () => reapWebhookLog({ client: db.prisma }));
    await gate.waitReached();
    const deletion = db.run("finalizer-r1", () => requestAccountDeletion(owner));
    await db.waitUntilBlocked("finalizer-r1", { by: "reaper-a" });
    gate.release();
    expect(await reaping).toBeGreaterThanOrEqual(1);
    expect(await deletion).toBe(true);
    expect(await db.inspect.webhookEvent.count({ where: { id: eventId } })).toBe(0);
    expect(await db.inspect.webhookDelivery.count({ where: { userId: owner } })).toBe(0);
  });

  it("finalization first (holding endpoints and cascaded deliveries): the reaper waits on endpoints, then completes", async () => {
    const { owner, eventId } = await oldDeliveryCase();
    const gate = db.pauseAt("finalizer-r2", { after: "webhookEndpoint.deleteMany" });
    const deletion = db.run("finalizer-r2", () => requestAccountDeletion(owner));
    await gate.waitReached();
    const reaping = db.run("reaper-b", () => reapWebhookLog({ client: db.prisma }));
    // The reaper blocks on its endpoint lock, BEFORE holding any event.
    const blocked = await db.waitUntilBlocked("reaper-b", { by: "finalizer-r2" });
    expect(blocked.query).toMatch(/FROM webhook_endpoint/);
    gate.release();
    expect(await deletion).toBe(true);
    expect(await reaping).toBeGreaterThanOrEqual(0); // completed, no 40P01
    expect(await db.inspect.webhookEvent.count({ where: { id: eventId } })).toBe(0);
  });

  it("the reaper keeps recent events and deletes only past retention", async () => {
    const { eventId } = await oldDeliveryCase();
    const recent = await seedOwner(db.inspect);
    await db.inspect.webhookEvent.create({
      data: {
        id: `evt_${"e".repeat(32)}`,
        userId: recent,
        type: "webhook.test",
        facts: {},
        body: "{}",
      },
    });
    expect(await reapWebhookLog({ client: db.prisma })).toBeGreaterThanOrEqual(1);
    expect(await db.inspect.webhookEvent.count({ where: { id: eventId } })).toBe(0);
    expect(await db.inspect.webhookEvent.count({ where: { id: `evt_${"e".repeat(32)}` } })).toBe(1);
  });
});
