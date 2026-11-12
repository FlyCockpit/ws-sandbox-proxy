import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
// No sockets: relay "sends" succeed; every durable transition is real SQL.
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
  },
}));

const db = await pgTestDatabase();
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { commitHostHello } = await import("./host-hello.js");
const { applyOperationResult } = await import("./operation-handlers.js");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");

afterAll(() => db.close());
beforeEach(() => vi.clearAllMocks());

const FP = `sha256:${"d".repeat(64)}`;
const clock = () => new Date();

/** The dispatch transaction's host-row lock: a no-op UPDATE at the epoch it read. */
const DISPATCH_HOST_LOCK = /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/;
/** The hello transaction's connection-row write (epoch increment + capabilities). */
const HELLO_HOST_WRITE = "sandboxHost.update";

async function seed() {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  // An egress-policy create leaves exactly one pending launch intent.
  const sandbox = await createSandbox(
    { kind: "session", ownerId },
    createSandboxInput.parse({
      template: "revision/" + template.id,
      sandboxHostId: host.id,
      idempotencyKey: `create-${randomUUID()}`,
      egress: { domains: ["example.com"] },
    }),
  );
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  expect(operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id, payload: { path: ["operationId"], equals: operation.id } },
  });
  return {
    ownerId,
    hostId: host.id,
    sandboxId: sandbox.id,
    operationId: operation.id,
    eventId: event.id,
  };
}

/** The downgrading replacement hello, driven through the production commit. */
async function downgradingHello(hostId: string, userId: string) {
  const epoch = await commitHostHello({
    identity: { hostId, userId },
    now: new Date(),
    message: (() => {
      const message = helloFixture(hostId, false);
      message.daemon.capabilities.egressPolicy = false;
      return message;
    })(),
  });
  const { acknowledgeJournalKey } = await import("./journal-key-ack.js");
  const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
  await acknowledgeJournalKey(
    { hostId, userId, connectionEpoch: epoch },
    {
      type: "journal.key.ack",
      connectionEpoch: epoch,
      keyVersion: 1,
      keyId: requestDigestMetadata().requestDigestKeyId,
    },
  );
  return epoch;
}

describe("C34-RACE (real PostgreSQL): launch dispatch vs capability-dropping replacement hello", () => {
  it("dispatch commits first: the epoch-1 send is legitimate, and the fenced retry terminalizes with zero sends", async () => {
    const fixture = await seed();

    // Park the dispatch transaction just after it write-locked the host row
    // at epoch 1; it holds the row lock while parked.
    const parked = db.pauseAt("dispatch", { after: DISPATCH_HOST_LOCK });
    const batch = db.run("dispatch", () => processSandboxOutboxBatch(clock));
    await parked.waitReached();

    // The replacement hello's connection-row write waits on that row lock:
    // observed in PostgreSQL itself, not presumed.
    const hello = db.run("hello", () => downgradingHello(fixture.hostId, fixture.ownerId));
    const blocked = await db.waitUntilBlocked("hello", { by: "dispatch" });
    expect(blocked.waitEventType).toBe("Lock");
    expect(blocked.blockers).toContain(db.backendPid("dispatch"));

    // The dispatch transaction commits first. Its gate read observed the
    // still-committed epoch-1 capability (egressEnforcement=true), so the
    // send to the epoch-1 session is legitimate.
    parked.release();
    expect(await batch).toBe(1);
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);

    // The hello commits afterwards: epoch 2, capability dropped, and the
    // epoch-1 intent reopened.
    expect(await hello).toBe(2);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: fixture.hostId } }),
    ).toMatchObject({ connectionEpoch: 2, egressEnforcement: false });
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: fixture.eventId } }),
    ).toMatchObject({ sentAt: null, claimToken: null, sentConnectionEpoch: 1 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: fixture.operationId } }),
    ).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1, dispatchedConnectionEpoch: 1 });

    // The replaced epoch cannot complete the operation it dispatched: the
    // stale result is fenced by the epoch CAS.
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: fixture.operationId },
    });
    const event = await db.inspect.outboxEvent.findUniqueOrThrow({
      where: { id: fixture.eventId },
    });
    const payload = event.payload as Record<string, unknown>;
    expect(
      await applyOperationResult({
        sender: { userId: fixture.ownerId, hostId: fixture.hostId, connectionEpoch: 1 },
        operationId: operation.id,
        sandboxId: fixture.sandboxId,
        generation: operation.generation,
        attempt: 1,
        state: "succeeded",
        result: { state: "ready", lease: payload.lease },
      }),
    ).toEqual({ written: false });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: fixture.operationId } }))
        .state,
    ).toBe("DISPATCHED");

    // The reopened retry re-enters the gate at epoch 2: the durable payload
    // still carries dispatchAttempt 0 while the operation row advanced, so
    // the DISPATCHED-arm check reads the operation and terminalizes with
    // retained uncertainty. No send ever reaches the downgraded session, and
    // the sandbox state is NOT authored — the epoch-1 dispatch may have
    // launched the VM.
    const beforeRetry = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: fixture.sandboxId },
    });
    expect(await db.run("retry", () => processSandboxOutboxBatch(clock))).toBe(0);
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: fixture.operationId } }),
    ).toMatchObject({ state: "UNKNOWN_OUTCOME", errorCode: "unsupported_capability" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: fixture.sandboxId } }),
    ).toMatchObject({ state: beforeRetry.state, lastErrorCode: beforeRetry.lastErrorCode });
    expect(
      (await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: fixture.eventId } }))
        .processedAt,
    ).not.toBeNull();
  });

  it("hello commits first: the dispatch's epoch CAS rejects the stale prepare with zero sends, and the retry terminalizes FAILED", async () => {
    const fixture = await seed();

    // Park the hello just after its connection-row write: epoch 2 and the
    // dropped capability are written in its transaction, and it holds the
    // host row lock while parked.
    const parked = db.pauseAt("hello", { after: HELLO_HOST_WRITE });
    const hello = db.run("hello", () => downgradingHello(fixture.hostId, fixture.ownerId));
    await parked.waitReached();

    // The dispatch transaction's no-op epoch lock waits on the hello's row
    // lock, observed in PostgreSQL itself.
    const batch = db.run("dispatch", () => processSandboxOutboxBatch(clock));
    const blocked = await db.waitUntilBlocked("dispatch", { by: "hello" });
    expect(blocked.waitEventType).toBe("Lock");
    expect(blocked.blockers).toContain(db.backendPid("hello"));

    // The hello commits first. The waiting epoch CAS re-evaluates its WHERE
    // against the new row version (connectionEpoch=2), matches zero rows and
    // rejects the prepare: no claim, no send, nothing durable changed.
    parked.release();
    expect(await hello).toBe(2);
    expect(await batch).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: fixture.operationId } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: fixture.eventId } }),
    ).toMatchObject({ processedAt: null, sentAt: null });

    // The next scan prepares at epoch 2: the gate read (after the host-row
    // lock) observes the committed egressEnforcement=false and terminalizes
    // the never-dispatched launch as FAILED, still with zero sends. Because
    // no dispatch ever happened, the failure is knowable: the sandbox leaves
    // the transitional states atomically and the reserved capacity is
    // released in the same transaction.
    expect(await db.run("retry", () => processSandboxOutboxBatch(clock))).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: fixture.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "unsupported_capability" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: fixture.sandboxId } }),
    ).toMatchObject({
      state: "ERROR",
      lastErrorCode: "unsupported_capability",
      liveResourcesHeld: false,
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: fixture.hostId } }),
    ).toMatchObject({ liveCount: 0 });
    expect(
      (await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: fixture.eventId } }))
        .processedAt,
    ).not.toBeNull();
  });
});
