import type { SandboxState } from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../sandbox/digest-context";
import { requestDigestMetadata } from "../sandbox/idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64) },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { SANDBOX_TRANSITIONS } = await import("../sandbox/state-transitions");
const { seedEndpoint, seedOwner, seedSandbox } = await import("./testing/fixtures");
const { offloadSandboxForTest } = await import("../sandbox/testing/offload-fixtures");
afterAll(() => db.close());

/**
 * The trigger contract (`wssp_webhook_*_event` in committed migration SQL), proven
 * against the production schema the migration runner installs. The TS oracle
 * below is the predicate table documented in docs/design/webhooks-contract.md.
 */
const PRE_READY = new Set(["REQUESTED", "SCHEDULED", "PROVISIONING", "WAITING_FOR_CAPACITY"]);
function expectedTypes(from: string, to: string, readyAt: Date | null, errorCode: string | null) {
  const out: string[] = [];
  if (to === "READY") out.push("sandbox.ready");
  if (to === "STOPPED") out.push("sandbox.stopped");
  if (
    readyAt === null &&
    PRE_READY.has(from) &&
    (to === "ERROR" || (to === "DELETED" && errorCode !== null))
  )
    out.push("sandbox.create_failed");
  if (to === "DELETED") out.push("sandbox.destroyed");
  return out.sort();
}

async function eventsFor(sandboxId: string) {
  const rows = await db.inspect.webhookEvent.findMany({
    where: { sandboxId },
    orderBy: { seq: "asc" },
    select: { type: true, facts: true, userId: true, id: true, occurredAt: true },
  });
  return rows;
}

/** Seed in a state, dropping what the INSERT itself emitted (an insert into READY is a transition too). */
async function seeded(
  owner: string,
  state: SandboxState,
  extra: Parameters<typeof seedSandbox>[3] = {},
) {
  // OFFLOADED is hostless with a stored disk (schema CHECK): built through the real key path.
  const sandbox = await seedSandbox(
    db.inspect,
    owner,
    state === "OFFLOADED" ? "STOPPED" : state,
    extra,
  );
  if (state === "OFFLOADED")
    await db.inspect.$transaction((tx) =>
      offloadSandboxForTest(tx, { userId: owner, sandboxId: sandbox.id, hostId: "host-none" }),
    );
  await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: sandbox.id } });
  return sandbox;
}

let owner: string;
beforeEach(async () => {
  owner = await seedOwner(db.inspect);
  await seedEndpoint(db.inspect, owner);
});

describe("webhook emission triggers (real PostgreSQL)", () => {
  const edges = (Object.entries(SANDBOX_TRANSITIONS) as [SandboxState, readonly SandboxState[]][])
    .flatMap(([from, targets]) => targets.map((to) => [from, to] as const))
    .filter(([, to]) => ["READY", "STOPPED", "DELETED", "ERROR"].includes(to));

  it.each(edges)("transition %s -> %s matches the predicate table", async (from, to) => {
    const preReady = PRE_READY.has(from);
    for (const errorCode of [null, "host_capacity"]) {
      const readyAt = preReady ? null : new Date();
      const sandbox = await seeded(owner, from, { readyAt });
      await db.inspect.sandbox.update({
        where: { id: sandbox.id },
        // An offloaded sandbox leaves its stored disk only when destroyed.
        data: {
          state: to,
          lastErrorCode: errorCode,
          ...(from === "OFFLOADED" ? { diskOffloadId: null } : {}),
        },
      });
      const events = await eventsFor(sandbox.id);
      expect(events.map((event) => event.type).sort(), `${from}->${to} err=${errorCode}`).toEqual(
        expectedTypes(from, to, readyAt, errorCode),
      );
      for (const event of events) {
        expect(event.id).toMatch(/^evt_[0-9a-f]{32}$/);
        expect(event.userId).toBe(owner);
        expect(event.facts).toEqual({ from, to, generation: 1, errorCode });
      }
    }
  });

  it("sandbox.offloaded fires for STOPPED → OFFLOADED only (R6, T15)", async () => {
    for (const from of ["STOPPED", "ERROR", "STOPPING"] as const) {
      const sandbox = await seedSandbox(db.inspect, owner, from);
      await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: sandbox.id } });
      await db.inspect.$transaction((tx) =>
        offloadSandboxForTest(tx, { userId: owner, sandboxId: sandbox.id, hostId: "host-none" }),
      );
      const events = await eventsFor(sandbox.id);
      expect(
        events.map((event) => event.type),
        from,
      ).toEqual(from === "STOPPED" ? ["sandbox.offloaded"] : []);
      for (const event of events)
        expect(event.facts).toEqual({ from, to: "OFFLOADED", generation: 1, errorCode: null });
    }
    // Not for an endpoint that did not subscribe to it.
    const other = await seedOwner(db.inspect);
    await seedEndpoint(db.inspect, other, { events: ["sandbox.stopped"] });
    const quiet = await seedSandbox(db.inspect, other, "STOPPED");
    await db.inspect.webhookEvent.deleteMany({ where: { sandboxId: quiet.id } });
    await db.inspect.$transaction((tx) =>
      offloadSandboxForTest(tx, { userId: other, sandboxId: quiet.id, hostId: "host-none" }),
    );
    expect(await eventsFor(quiet.id)).toEqual([]);
  });

  it("ERROR from READY is not create_failed; a kill before READY is only destroyed", async () => {
    const ready = await seeded(owner, "READY", { readyAt: new Date() });
    await db.inspect.sandbox.update({ where: { id: ready.id }, data: { state: "ERROR" } });
    expect((await eventsFor(ready.id)).map((e) => e.type)).toEqual([]);
    const killed = await seeded(owner, "PROVISIONING");
    await db.inspect.sandbox.update({ where: { id: killed.id }, data: { state: "DELETED" } });
    expect((await eventsFor(killed.id)).map((e) => e.type)).toEqual(["sandbox.destroyed"]);
  });

  it("keeps the pre-READY list in one function, as text, including WAITING_FOR_CAPACITY", async () => {
    // The trigger compares OLD.state::text against this one list. The real
    // WAITING_FOR_CAPACITY -> DELETED edges are in the table above and, through
    // the real capacity queue, in sandbox/capacity-queue.pg.test.ts.
    const [row] = await db.inspect.$queryRaw<{ states: string[] }[]>`
      SELECT public.wssp_webhook_pre_ready_states() AS states`;
    expect(row?.states).toEqual(["REQUESTED", "SCHEDULED", "PROVISIONING", "WAITING_FOR_CAPACITY"]);
    expect(edges).toContainEqual(["WAITING_FOR_CAPACITY", "DELETED"]);
  });

  it("emits nothing for a rolled-back transition", async () => {
    const sandbox = await seeded(owner, "PROVISIONING");
    await expect(
      db.prisma.$transaction(async (tx) => {
        await tx.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(await eventsFor(sandbox.id)).toEqual([]);
  });

  it("a concurrent READ COMMITTED reader sees the event only after commit", async () => {
    const sandbox = await seeded(owner, "PROVISIONING");
    const gate = db.pauseAt("writer", { after: "sandbox.update" });
    const writer = db.run("writer", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
        await tx.$queryRaw`SELECT 1`;
      }),
    );
    await gate.waitReached();
    expect(await eventsFor(sandbox.id)).toEqual([]);
    gate.release();
    await writer;
    expect((await eventsFor(sandbox.id)).map((e) => e.type)).toEqual(["sandbox.ready"]);
  });

  it("emits nothing without a subscribed, enabled endpoint", async () => {
    const lonely = await seedOwner(db.inspect);
    const a = await seeded(lonely, "PROVISIONING");
    await db.inspect.sandbox.update({ where: { id: a.id }, data: { state: "READY" } });
    expect(await eventsFor(a.id)).toEqual([]);
    await seedEndpoint(db.inspect, lonely, { disabledAt: new Date() });
    await seedEndpoint(db.inspect, lonely, { events: ["sandbox.stopped"] });
    const b = await seeded(lonely, "PROVISIONING");
    await db.inspect.sandbox.update({ where: { id: b.id }, data: { state: "READY" } });
    expect(await eventsFor(b.id)).toEqual([]);
  });

  it("an INSERT directly into READY is itself a ready transition", async () => {
    const sandbox = await seedSandbox(db.inspect, owner, "READY", { readyAt: new Date() });
    expect((await eventsFor(sandbox.id)).map((e) => e.type)).toEqual(["sandbox.ready"]);
  });

  it("does not fire on updates that leave state unchanged", async () => {
    const sandbox = await seeded(owner, "READY", { readyAt: new Date() });
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { metadata: { a: "b" } } });
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
    expect(await eventsFor(sandbox.id)).toEqual([]);
  });

  it("operation.completed: INSERT of a terminal row, double emit after UNKNOWN_OUTCOME, kind filter", async () => {
    const sandbox = await seeded(owner, "READY", { readyAt: new Date() });
    const base = {
      userId: owner,
      sandboxId: sandbox.id,
      generation: 1,
      requestBodyHash: "h",
    };
    const inserted = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),
        ...base,
        kind: "RECONNECT_SANDBOX",
        state: "SUCCEEDED",
        idempotencyKey: "k1",
      },
    });
    const running = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),
        ...base,
        kind: "RUN_COMMAND",
        state: "RUNNING",
        idempotencyKey: "k2",
      },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: running.id },
      data: { state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: running.id },
      data: { state: "SUCCEEDED", errorCode: null },
    });
    const ops = await db.inspect.webhookEvent.findMany({
      where: { operationId: { in: [inserted.id, running.id] } },
      orderBy: { seq: "asc" },
      select: { operationId: true, facts: true, type: true, sandboxId: true },
    });
    expect(ops).toEqual([
      {
        operationId: inserted.id,
        type: "operation.completed",
        sandboxId: sandbox.id,
        facts: {
          from: null,
          to: "SUCCEEDED",
          kind: "RECONNECT_SANDBOX",
          generation: 1,
          errorCode: null,
        },
      },
      {
        operationId: running.id,
        type: "operation.completed",
        sandboxId: sandbox.id,
        facts: {
          from: "RUNNING",
          to: "UNKNOWN_OUTCOME",
          kind: "RUN_COMMAND",
          generation: 1,
          errorCode: "unknown_outcome",
        },
      },
      {
        operationId: running.id,
        type: "operation.completed",
        sandboxId: sandbox.id,
        facts: {
          from: "UNKNOWN_OUTCOME",
          to: "SUCCEEDED",
          kind: "RUN_COMMAND",
          generation: 1,
          errorCode: null,
        },
      },
    ]);
    // Kind filter: an endpoint limited to CREATE_SANDBOX ignores a STAT_PATH result.
    const filtered = await seedOwner(db.inspect);
    await seedEndpoint(db.inspect, filtered, { operationKinds: ["CREATE_SANDBOX"] });
    const other = await seeded(filtered, "READY", { readyAt: new Date() });
    const stat = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        ...base,
        userId: filtered,
        sandboxId: other.id,
        kind: "STAT_PATH",
        state: "SUCCEEDED",
        idempotencyKey: "k3",
      },
    });
    const create = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        ...base,
        userId: filtered,
        sandboxId: other.id,
        kind: "CREATE_SANDBOX",
        state: "FAILED",
        idempotencyKey: "k4",
      },
    });
    const filteredEvents = await db.inspect.webhookEvent.findMany({
      where: { userId: filtered, type: "operation.completed" },
      select: { operationId: true },
    });
    expect(filteredEvents.map((event) => event.operationId)).toEqual([create.id]);
    expect(filteredEvents.map((event) => event.operationId)).not.toContain(stat.id);
  });

  it("credential.*: one event per subscribed lease outcome, facts name only the event row, rendered from it", async () => {
    const { renderWebhookEvent } = await import("./render");
    const sandbox = await seeded(owner, "READY", { readyAt: new Date() });
    const types = [
      "capture_failed",
      "capture_lost",
      "recovery_required",
      "needs_login",
      // Not webhook events: the trigger ignores them.
      "value_written",
      "capture_rejected",
      "force_released",
    ];
    const rows = [];
    for (const type of types)
      rows.push(
        await db.inspect.credentialEvent.create({
          data: {
            userId: owner,
            credentialId: "cred-1",
            accountId: "acct-1",
            instanceId: "inst-1",
            leaseId: "lease-1",
            sandboxId: sandbox.id,
            hostId: "host-1",
            storageSeq: 4,
            sizeBytes: 512,
            type,
            reason: type === "needs_login" ? "capture_lost" : "census_settlement",
          },
          select: { id: true, type: true },
        }),
      );
    const events = await db.inspect.webhookEvent.findMany({
      where: { userId: owner, type: { startsWith: "credential." } },
      orderBy: { seq: "asc" },
      select: {
        id: true,
        type: true,
        sandboxId: true,
        facts: true,
        userId: true,
        occurredAt: true,
      },
    });
    expect(events.map((e) => [e.type, e.facts])).toEqual(
      rows.slice(0, 4).map((row) => [`credential.${row.type}`, { credentialEventId: row.id }]),
    );
    for (const event of events) {
      expect(event.sandboxId).toBe(sandbox.id);
      const body = await renderWebhookEvent(db.inspect, { ...event, operationId: null });
      const parsed = JSON.parse(body ?? "null");
      expect(parsed.type).toBe(event.type);
      expect(parsed.data).toEqual({
        credential: { id: "cred-1", accountId: "acct-1", instanceId: "inst-1" },
        leaseId: "lease-1",
        sandboxId: sandbox.id,
        reason: event.type === "credential.needs_login" ? "capture_lost" : "census_settlement",
      });
      // The envelope's random id and timestamp can contain any digits; only
      // the rendered data must not leak the host or the lease's sizing.
      const data = JSON.stringify(parsed.data);
      expect(data).not.toContain("host-1");
      expect(data).not.toContain("512");
    }
    // Another owner cannot render this owner's row through a forged event.
    const stranger = await seedOwner(db.inspect);
    const first = events[0];
    if (!first) throw new Error("no credential event");
    expect(
      await renderWebhookEvent(db.inspect, { ...first, userId: stranger, operationId: null }),
    ).toBeNull();
    // Only subscribed types are emitted.
    const picky = await seedOwner(db.inspect);
    await seedEndpoint(db.inspect, picky, { events: ["credential.capture_lost"] });
    for (const type of ["capture_lost", "recovery_required"])
      await db.inspect.credentialEvent.create({
        data: { userId: picky, credentialId: "cred-2", type, reason: type },
      });
    expect(
      (
        await db.inspect.webhookEvent.findMany({ where: { userId: picky }, select: { type: true } })
      ).map((e) => e.type),
    ).toEqual(["credential.capture_lost"]);
  });

  it("never breaks sandbox writes when the webhook tables are absent (removal safety)", async () => {
    // Disposable per-file clone only: rename, write, rename back.
    const sandbox = await seeded(owner, "PROVISIONING");
    await db.inspect.$executeRawUnsafe(`ALTER TABLE webhook_event RENAME TO webhook_event_hidden`);
    try {
      await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
    } finally {
      await db.inspect.$executeRawUnsafe(
        `ALTER TABLE webhook_event_hidden RENAME TO webhook_event`,
      );
    }
    expect(await eventsFor(sandbox.id)).toEqual([]);
    // The credential trigger returns early too.
    await db.inspect.$executeRawUnsafe(`ALTER TABLE webhook_event RENAME TO webhook_event_hidden`);
    try {
      await db.inspect.credentialEvent.create({
        data: { userId: owner, credentialId: "cred-1", type: "capture_lost", reason: "x" },
      });
    } finally {
      await db.inspect.$executeRawUnsafe(
        `ALTER TABLE webhook_event_hidden RENAME TO webhook_event`,
      );
    }
  });
});
