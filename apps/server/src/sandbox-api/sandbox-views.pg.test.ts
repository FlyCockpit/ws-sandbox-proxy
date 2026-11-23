import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * C47: the sandboxes page's owner projection against real PostgreSQL — the
 * host summary, the template revision (archived ones included) and the latest
 * lifecycle receipt ride on list/get; the status filter; a create retried
 * with the same idempotency key is one sandbox; another owner's sandbox is
 * NOT_FOUND on detail and absent from the list; and a renewal becomes the
 * latest lifecycle receipt while the host has not acknowledged it.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c47-pg-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
const { sandboxTemplatesRouter } = await import(
  "../../../../packages/api/src/routers/sandbox-templates"
);
afterAll(() => db.close());

const FP = `sha256:${"c".repeat(64)}`;

async function owner() {
  const id = `view-${randomUUID()}`;
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
      lastHeartbeatAt: new Date(),
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "ubuntu",
      label: "Ubuntu",
      imageRef: "local:ubuntu",
      incusFingerprint: FP,
    },
  });
  // protectedProcedure requires the durable session row behind the session.
  await db.inspect.session.create({
    data: {
      id: `session-${id}`,
      userId: id,
      token: `fixture-${id}`,
      expiresAt: new Date(Date.now() + 60000),
    },
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
        createdAt: new Date(),
        updatedAt: new Date(),
        ipAddress: null,
        userAgent: null,
      },
    },
  } as Context;
  return {
    id,
    host,
    template,
    sandboxes: createRouterClient(sandboxesRouter, { context }),
    templates: createRouterClient(sandboxTemplatesRouter, { context }),
  };
}

it("create is one sandbox per key; list/get carry host, template and the queued receipt; foreign detail is NOT_FOUND", async () => {
  const a = await owner();
  const b = await owner();
  const input = {
    template: "revision/" + a.template.id,
    sandboxHostId: a.host.id,
    idempotencyKey: `web-create-${randomUUID()}`,
    metadata: { team: "infra" },
    lifecycle: { onTimeout: "kill" as const },
  };
  const created = await a.sandboxes.createSandbox(input);
  // A double submit (same stable key, same body) replays the same sandbox.
  const replay = await a.sandboxes.createSandbox(input);
  expect(replay.id).toBe(created.id);
  expect(await db.inspect.sandbox.count({ where: { userId: a.id } })).toBe(1);

  const view = await a.sandboxes.getSandbox({ id: created.id });
  expect(view).toMatchObject({
    state: "REQUESTED",
    metadata: { team: "infra" },
    leaseExpireActionRequested: "DESTROY",
    leaseExpiresAtEffective: null,
    host: { id: a.host.id, slug: "lab", label: "Lab", status: "CONNECTED", draining: false },
    template: { id: a.template.templateId, slug: "ubuntu", label: "Ubuntu", retiredAt: null },
    lastLifecycleOperation: { kind: "CREATE_SANDBOX", state: "QUEUED", completedAt: null },
  });

  await expect(b.sandboxes.getSandbox({ id: created.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect((await b.sandboxes.list({ limit: 50 })).items).toEqual([]);
  expect((await a.sandboxes.list({ limit: 50, status: "all" })).items.map((row) => row.id)).toEqual(
    [created.id],
  );
});

it("status filter: active hides DELETED, deleted shows only it; an archived template stays readable", async () => {
  const a = await owner();
  const live = await a.sandboxes.createSandbox({
    template: "revision/" + a.template.id,
    sandboxHostId: a.host.id,
    idempotencyKey: `web-live-${randomUUID()}`,
  });
  const gone = await a.sandboxes.createSandbox({
    template: "revision/" + a.template.id,
    sandboxHostId: a.host.id,
    idempotencyKey: `web-gone-${randomUUID()}`,
  });
  // Settle `gone` as a destroyed sandbox, then archive the template it used.
  await db.inspect.sandbox.update({
    where: { id: gone.id },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
    },
  });
  await db.inspect.sandbox.update({
    where: { id: live.id },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
    },
  });
  await db.inspect.sandboxHost.update({
    where: { id: a.host.id },
    data: { liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 },
  });
  await a.templates.retireTemplate({ id: a.template.templateId });
  await db.inspect.sandbox.update({ where: { id: live.id }, data: { state: "STOPPED" } });

  const ids = async (status: "active" | "deleted" | "all") =>
    (await a.sandboxes.list({ limit: 50, status })).items.map((row) => row.id).sort();
  expect(await ids("active")).toEqual([live.id]);
  expect(await ids("deleted")).toEqual([gone.id]);
  expect(await ids("all")).toEqual([live.id, gone.id].sort());

  const view = await a.sandboxes.getSandbox({ id: gone.id });
  expect(view).toMatchObject({ state: "DELETED", host: null });
  expect(view.template.archivedAt).not.toBeNull();
  // The detail page reads the archived revision through the session-only getTemplate.
  expect(await a.templates.getTemplateRevision({ id: a.template.id })).toMatchObject({
    id: a.template.id,
    incusFingerprint: FP,
    retiredAt: null,
  });
});

it("a renewal is the latest lifecycle receipt; requested moves while effective stays unacknowledged", async () => {
  const a = await owner();
  const created = await a.sandboxes.createSandbox({
    template: "revision/" + a.template.id,
    sandboxHostId: a.host.id,
    idempotencyKey: `web-renew-${randomUUID()}`,
  });
  await db.inspect.sandbox.update({ where: { id: created.id }, data: { state: "READY" } });
  const beforeRenewal = Date.now();
  await a.sandboxes.setSandboxTimeout({
    id: created.id,
    idempotencyKey: `web-renew-1-${randomUUID()}`,
    timeoutMs: 2 * 3_600_000,
  });
  const view = await a.sandboxes.getSandbox({ id: created.id });
  expect(view.leaseExpiresAtRequested?.getTime()).toBeGreaterThanOrEqual(
    beforeRenewal + 2 * 3_600_000,
  );
  expect(view.leaseExpiresAtRequested?.getTime()).toBeLessThanOrEqual(Date.now() + 2 * 3_600_000);
  expect(view).toMatchObject({
    leaseRevision: 2,
    leaseExpireActionRequested: "DESTROY",
    leaseExpiresAtEffective: null,
    lastLifecycleOperation: { kind: "RENEW_SANDBOX_LEASE" },
  });
});

const { createSandbox, setSandboxTimeout } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { getSandboxView } = await import(
  "../../../../packages/api/src/sandbox/services/sandbox-views"
);
const { leaseWireSchema } = await import("@wssp/api/sandbox/lease-wire");
const { applyOperationResult } = await import("../sandbox-relay/operation-handlers.js");

async function fixture() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "Lease", email: `${id}@example.test` } });
  const owner = { kind: "session" as const, ownerId: id };
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lease",
      label: "Lease",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "lease",
      label: "Lease",
      imageRef: "local:fixture",
      incusFingerprint: `sha256:${"c".repeat(64)}`,
    },
  });
  const sandbox = await createSandbox(owner, {
    template: "revision/" + template.id,
    sandboxHostId: host.id,
    idempotencyKey: randomUUID(),
  });
  const sender = { userId: id, hostId: host.id, connectionEpoch: 1 };
  async function dispatch(key?: string) {
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: {
        sandboxId: sandbox.id,
        ...(key ? { idempotencyKey: key } : { kind: "CREATE_SANDBOX" }),
      },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: operation.id },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: host.id,
        dispatchedConnectionEpoch: 1,
      },
    });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandbox.id, payload: { path: ["operationId"], equals: operation.id } },
    });
    const payload = event.payload as Record<string, unknown>;
    const lease = leaseWireSchema.parse(payload.lease);
    return {
      sender,
      operationId: operation.id,
      sandboxId: sandbox.id,
      generation: operation.generation,
      attempt: 1,
      state: "succeeded",
      result: { state: "ready", lease },
    };
  }
  return { owner, sandbox, dispatch };
}

it("create requires the exact lease ACK and the detail view exposes the durable effective lifetime", async () => {
  const f = await fixture();
  const ack = await f.dispatch();
  expect(await applyOperationResult({ ...ack, result: { state: "ready" } })).toEqual({
    written: false,
  });
  expect(
    await applyOperationResult({
      ...ack,
      result: { state: "ready", lease: { ...ack.result.lease, revision: 99 } },
    }),
  ).toEqual({ written: false });
  expect((await getSandboxView(f.owner, { id: f.sandbox.id })).leaseExpiresAtEffective).toBeNull();
  expect(await applyOperationResult(ack)).toEqual({ written: true });
  expect(await getSandboxView(f.owner, { id: f.sandbox.id })).toMatchObject({
    state: "READY",
    leaseRevisionEffective: 1,
    leaseExpiresAtEffective: new Date(ack.result.lease.deadlineUnixMs),
    leaseExpireActionEffective: "DESTROY",
  });
});

it("offline renewal stays queued and reversed concurrent ACKs retain the newest effective revision", async () => {
  const f = await fixture();
  expect(await applyOperationResult(await f.dispatch())).toEqual({ written: true });
  const keys = [randomUUID(), randomUUID()];
  for (const [i, key] of keys.entries())
    await setSandboxTimeout(f.owner, {
      id: f.sandbox.id,
      idempotencyKey: key,
      timeoutMs: (i + 2) * 3_600_000,
    });
  const view = await getSandboxView(f.owner, { id: f.sandbox.id });
  expect(view).toMatchObject({
    leaseRevision: 3,
    leaseRevisionEffective: 1,
    lastLifecycleOperation: { state: "QUEUED" },
  });
  const [older, newer] = await Promise.all(keys.map((key) => f.dispatch(key)));
  const gate = db.pauseAt("newer", { after: "sandbox.updateMany" });
  const pendingNewer = db.run("newer", () => applyOperationResult(newer!));
  await gate.waitReached();
  const pendingOlder = db.run("older", () => applyOperationResult(older!));
  try {
    expect((await db.waitUntilBlocked("older", { by: "newer" })).waitEventType).toBe("Lock");
  } finally {
    gate.release();
  }
  const acks = await Promise.all([pendingNewer, pendingOlder]);
  expect(acks).toEqual([{ written: true }, { written: true }]);
  expect(await getSandboxView(f.owner, { id: f.sandbox.id })).toMatchObject({
    leaseRevisionEffective: 3,
    leaseExpiresAtEffective: new Date(newer!.result.lease.deadlineUnixMs),
    leaseExpireActionEffective: "DESTROY",
  });
  expect(await applyOperationResult(older!)).toEqual({ written: false });
});

it("S0 protected sandbox list/detail conceal historical expiry and lifecycle diagnostics", async () => {
  const a = await owner();
  const created = await a.sandboxes.createSandbox({
    template: "revision/" + a.template.id,
    sandboxHostId: a.host.id,
    idempotencyKey: randomUUID(),
  });
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { lastErrorCode: "expiry_failed", lastErrorDetail: "PRIVATE-EXPIRY-ARGV-PATH" },
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: created.id, userId: a.id },
    data: {
      state: "FAILED",
      errorCode: "PRIVATE-LIFECYCLE-CODE",
      errorDetail: "PRIVATE-LIFECYCLE-DETAIL",
    },
  });
  const detail = await a.sandboxes.getSandbox({ id: created.id });
  const list = await a.sandboxes.list({ limit: 10 });
  expect(detail.expiryFailureReason).toBe("Host could not enforce sandbox expiry.");
  expect(detail.lastLifecycleOperation?.errorCode).toBe("internal");
  expect(JSON.stringify({ detail, list })).not.toContain("PRIVATE-");
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { lastErrorCode: "PRIVATE-SANDBOX-CODE" },
  });
  const unknown = await a.sandboxes.getSandbox({ id: created.id });
  expect(unknown.lastErrorCode).toBe("internal");
  expect(JSON.stringify(unknown)).not.toContain("PRIVATE-");
});
