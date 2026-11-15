import {
  acknowledgeFixtureExecutionConfigs,
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, beforeEach, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn(() => true),
    dispatchOperation: vi.fn(async () => "sent"),
    sendStdin: vi.fn(async () => true),
    cancelOperation: vi.fn(async () => true),
    captureHostDispatchCredential: vi.fn(),
    reserveFileStreamSlot: vi.fn(() => ({ release() {} })),
  },
}));
const db = await pgTestDatabase();
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

const access = await import("@wssp/api/lib/sdk-key-access");
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const services = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { revokeSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { withAuthorityChange, withGlobalAuthorityChange } = await import("@wssp/db/authority");
const { applyOperationResult } = await import("./operation-handlers.js");
const { bindSandboxDispatchWake } = await import("@wssp/api/sandbox/outbox");
const owners: string[] = [];
afterAll(() => db.close());
afterEach(async () => {
  bindSandboxDispatchWake(null);
  vi.restoreAllMocks();
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
});
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(manager.dispatchOperation).mockResolvedValue("sent");
  vi.mocked(manager.captureHostDispatchCredential).mockReturnValue(undefined);
});
const clock = () => new Date();
/** The host re-registers at epoch 2; its guard lease renews at the new epoch. */
async function reconnectHost(hostId: string) {
  await db.inspect.sandboxHost.update({
    where: { id: hostId },
    data: { connectionEpoch: 2, daemonEgressGuardEpoch: 2 },
  });
}
async function seed() {
  const ownerId = `s3b-relay-${randomUUID()}`;
  owners.push(ownerId);
  await db.inspect.user.create({
    data: { id: ownerId, email: `${ownerId}@example.test`, name: "Owner", twoFactorEnabled: true },
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
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: ownerId,
      name: "accepted",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALLOWLIST",
      scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
      HostAllowlist: { create: { sandboxHostId: host.id } },
      RevisionAllowlist: { create: { templateRevisionId: revision.id } },
    },
  });
  const principal = await access.revalidateSdkKey(key.id, ownerId);
  if (!principal) throw new Error("Fixture key refused.");
  const sandbox = await services.createSandbox(
    principal,
    createSandboxInput.parse({
      sandboxHostId: host.id,
      template: "revision/" + revision.id,
      idempotencyKey: randomUUID(),
    }),
  );
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id },
  });
  return { ownerId, host, revision, key, principal, sandbox, operation, event };
}
type Fixture = Awaited<ReturnType<typeof seed>>;
async function preserveCreation(f: Fixture) {
  await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.ownerId,
      sandboxId: f.sandbox.id,
      kind: "CREATE_SANDBOX",
      generation: 1,
      state: "SUCCEEDED",
      authorizingKeyId: f.key.id,
      idempotencyKey: randomUUID(),
      requestBodyHash: "fixture",
      createdAt: new Date(0),
    },
  });
}
async function refuse(f: Fixture, reason: "key" | "host-grant" | "revision-grant") {
  await withAuthorityChange({ ownerId: f.ownerId, credentialId: f.key.id }, async () => {
    if (reason === "key")
      await db.inspect.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    if (reason === "host-grant")
      await db.inspect.sdkKeyHostAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
    if (reason === "revision-grant")
      await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
  });
}
async function state(f: Fixture) {
  return {
    operation: await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    }),
    sandbox: await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } }),
    host: await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    event: await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: f.event.id } }),
  };
}

it.each(["key", "host-grant", "revision-grant"] as const)(
  "3B directly seeded accepted dispatch refuses removed %s and releases a proven first claim once",
  async (reason) => {
    const f = await seed();
    await refuse(f, reason);
    if (reason !== "key") {
      expect(await processSandboxOutboxBatch(clock)).toBe(1);
      expect((await state(f)).operation.state).toBe("DISPATCHED");
      expect((await state(f)).sandbox.liveResourcesHeld).toBe(true);
      return;
    }
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    expect(row.operation).toMatchObject({
      state: "FAILED",
      dispatchAttempt: 1,
      errorCode: "credential_inactive",
      errorDetail: "Accepted dispatch authority is inactive.",
    });
    expect(row.sandbox).toMatchObject({
      state: "ERROR",
      lastErrorCode: "credential_inactive",
      lastErrorDetail: "Accepted dispatch authority is inactive.",
      liveResourcesHeld: false,
    });
    expect(row.host.liveCount).toBe(0);
    expect(row.event.processedAt).not.toBeNull();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    await processSandboxOutboxBatch(clock);
    const repeated = await state(f);
    expect(repeated.host.liveCount).toBe(0);
    expect(repeated.sandbox).toEqual(row.sandbox);
    expect(repeated.operation).toEqual(row.operation);
  },
);

it.each(["key", "revision-grant"] as const)(
  "revoked_key_redispatch_keeps_slot %s through receipt ingestion",
  async (reason) => {
    const f = await seed();
    await db.inspect.sandboxOperation.update({
      where: { id: f.operation.id },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 1,
      },
    });
    await reconnectHost(f.host.id);
    await refuse(f, reason);
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    if (reason === "revision-grant") {
      expect(row.operation).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
      expect(row.sandbox.liveResourcesHeld).toBe(true);
      expect(row.host.liveCount).toBe(1);
      return;
    }
    expect(row.operation).toMatchObject({ state: "UNKNOWN_OUTCOME", dispatchAttempt: 2 });
    expect(row.sandbox.liveResourcesHeld).toBe(true);
    expect(row.host.liveCount).toBe(1);
    await applyOperationResult({
      sender: { hostId: f.host.id, userId: f.ownerId, connectionEpoch: 2 },
      operationId: f.operation.id,
      sandboxId: f.sandbox.id,
      generation: 1,
      attempt: 2,
      state: "unknown_outcome",
      error: { code: "access_denied", message: "refused" },
    });
    expect((await state(f)).sandbox.liveResourcesHeld).toBe(true);
  },
);

it("creating key dispatch retains accepted work across future revision-grant loss", async () => {
  const f = await seed();
  await refuse(f, "revision-grant");
  const context = {
    sandboxId: f.sandbox.id,
    sandboxHostId: f.host.id,
    templateRevisionId: f.revision.id,
    originPoolId: null,
  };
  expect(
    await db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id=${f.key.id} FOR SHARE`;
      return access.checkAcceptedDispatchAuthority(
        { ownerId: f.ownerId, principal: { kind: "sdkKey", keyId: f.key.id }, context },
        tx,
      );
    }),
  ).toBe("active");
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: { userId: f.ownerId, sdkKeyId: f.key.id, templateRevisionId: f.revision.id },
  });
  expect(await processSandboxOutboxBatch(clock)).toBe(1);
  expect(manager.dispatchOperation).toHaveBeenCalledOnce();
});

it.each(["key", "host-grant", "revision-grant"] as const)(
  "3B revoke %s between prepare and send prevents frame and releases first claim",
  async (reason) => {
    const f = await seed();
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      await refuse(f, reason);
      return "refused_before_frame";
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    if (reason !== "key") {
      expect(row.operation.state).toBe("QUEUED");
      expect(row.sandbox.liveResourcesHeld).toBe(true);
      expect(await processSandboxOutboxBatch(clock)).toBe(1);
      return;
    }
    expect(row.operation.state).toBe("FAILED");
    expect(row.sandbox).toMatchObject({
      state: "ERROR",
      lastErrorCode: "credential_inactive",
      lastErrorDetail: "Accepted dispatch authority is inactive.",
      liveResourcesHeld: false,
    });
    expect(row.host.liveCount).toBe(0);
    await processSandboxOutboxBatch(clock);
    const repeated = await state(f);
    expect(repeated.host.liveCount).toBe(0);
    expect(repeated.sandbox).toEqual(row.sandbox);
  },
);

it.each(["owner", "global"] as const)(
  "3B unrelated %s authority-bump retries first claim on the same connection",
  async (bump) => {
    const f = await seed();
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      if (bump === "owner")
        await withAuthorityChange({ ownerId: f.ownerId }, async () => undefined);
      else await withGlobalAuthorityChange(async () => undefined);
      return "refused_before_frame";
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    expect(row.operation).toMatchObject({
      state: "QUEUED",
      dispatchAttempt: 0,
      acceptedAttempt: null,
      dispatchedAt: null,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    });
    expect(row.event).toMatchObject({ claimToken: null, processedAt: null });
    expect(row.host.liveCount).toBe(1);
    expect(await processSandboxOutboxBatch(clock)).toBe(1);
    expect((await state(f)).operation).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
  },
);

it("revoking_key_a_does_not_fail_key_b_operation", async () => {
  const f = await seed();
  const keyA = await db.inspect.sdkKey.create({
    data: {
      userId: f.ownerId,
      name: "sibling",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
    },
  });
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
    await revokeSdkKey({ kind: "session", ownerId: f.ownerId }, { id: keyA.id });
    return "refused_before_frame";
  });
  const wake = vi.fn();
  bindSandboxDispatchWake(wake);
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  expect(wake).not.toHaveBeenCalled();
  expect((await state(f)).operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  expect(await processSandboxOutboxBatch(clock)).toBe(1);
  expect((await state(f)).host.liveCount).toBe(1);
});

it("post_frame_authority_loss_keeps_dispatched", async () => {
  const f = await seed();
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async (_host, input) => {
    input.onPossibleDispatchFrame?.();
    await refuse(f, "key");
    return "sent_then_lost_authority";
  });
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  const row = await state(f);
  expect(row.operation.state).toBe("DISPATCHED");
  expect(row.sandbox.liveResourcesHeld).toBe(true);
  expect(row.host.liveCount).toBe(1);
});

it("stale_claim_token_cannot_reset", async () => {
  const f = await seed();
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
    await db.inspect.outboxEvent.update({
      where: { id: f.event.id },
      data: { claimToken: "new-claim-token" },
    });
    return "refused_before_frame";
  });
  await processSandboxOutboxBatch(clock);
  const row = await state(f);
  expect(row.operation).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
  expect(row.event.claimToken).toBe("new-claim-token");
  expect(row.host.liveCount).toBe(1);
});

it("3B K-before-H revoke barrier observes inactive row without owner lock acquisition", async () => {
  const f = await seed();
  const held = db.pauseAt("revoke", { before: "$transaction.commit" });
  const revoking = db.run("revoke", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    }),
  );
  await held.waitReached();
  const dispatch = db.run("dispatch", () => processSandboxOutboxBatch(clock));
  expect((await db.waitUntilBlocked("dispatch", { by: "revoke" })).query).toMatch(
    /sdk_key.*FOR SHARE/,
  );
  await db.inspect.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id=${f.host.id} FOR UPDATE NOWAIT`;
  });
  held.release();
  await revoking;
  await dispatch;
  expect((await state(f)).operation.state).toBe("FAILED");
});

it.each(["owner", "global"] as const)(
  "3B moved %s fence during row read is indeterminate and leaves pending",
  async (bump) => {
    const f = await seed();
    const gate = db.pauseAt("dispatch", { after: "sdkKey.findUnique" });
    const pending = db.run("dispatch", () => processSandboxOutboxBatch(clock));
    await gate.waitReached();
    if (bump === "owner") await withAuthorityChange({ ownerId: f.ownerId }, async () => undefined);
    else await withGlobalAuthorityChange(async () => undefined);
    gate.release();
    await pending;
    expect((await state(f)).operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(await processSandboxOutboxBatch(clock)).toBe(1);
  },
);

it("cancel_during_pre_frame_refusal_is_not_reverted", async () => {
  const f = await seed();
  await preserveCreation(f);
  // Convert the accepted fixture to a cancellable command with its own held sandbox slot.
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "READY" } });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { kind: "RUN_COMMAND" },
  });
  await db.inspect.outboxEvent.update({
    where: { id: f.event.id },
    data: {
      payload: {
        ...(f.event.payload as Record<string, string>),
        kind: "command.run",
        argv: ["true"],
      },
    },
  });
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
    await services.cancelOperation(
      { kind: "session", ownerId: f.ownerId },
      { operationId: f.operation.id },
    );
    return "refused_before_frame";
  });
  await processSandboxOutboxBatch(clock);
  const row = await state(f);
  expect(row.operation.state).toBe("CANCELLED");
  expect(row.host.liveCount).toBe(1);
  await processSandboxOutboxBatch(clock);
  expect(
    await db.inspect.outboxEvent.count({ where: { aggregateId: f.sandbox.id, processedAt: null } }),
  ).toBe(0);
});

it.each([
  "sandbox.kill",
  "sandbox.stop",
  "command.run",
  "file.put",
  "sandbox.lease.renew",
  "operation.cancel",
  "process.stdin",
])("system_dispatch_kind_allowlist real dispatch %s", async (kind) => {
  const f = await seed();
  const cleanup = kind === "sandbox.kill" || kind === "sandbox.stop";
  const control = kind === "operation.cancel" || kind === "process.stdin";
  await preserveCreation(f);
  const opKind =
    kind === "sandbox.kill"
      ? "KILL_SANDBOX"
      : kind === "sandbox.stop"
        ? "STOP_SANDBOX"
        : kind === "file.put"
          ? "PUT_FILE"
          : kind === "sandbox.lease.renew"
            ? "RENEW_SANDBOX_LEASE"
            : "RUN_COMMAND";
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { state: cleanup ? "STOPPING" : "READY" },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: {
      kind: opKind,
      authorizingKeyId: null,
      ...(control
        ? {
            state: kind === "operation.cancel" ? "CANCEL_REQUESTED" : "RUNNING",
            dispatchAttempt: 1,
            acceptedAttempt: 1,
            dispatchedHostId: f.host.id,
            dispatchedConnectionEpoch: 1,
          }
        : {}),
    },
  });
  await db.inspect.outboxEvent.update({
    where: { id: f.event.id },
    data: {
      payload: {
        kind,
        sandboxId: f.sandbox.id,
        sandboxHostId: f.host.id,
        operationId: f.operation.id,
        idempotencyKey: f.operation.idempotencyKey,
        generation: 1,
        dispatchAttempt: control ? 1 : 0,
        incusName: `wssp-sbx-${f.sandbox.id}`,
        authorizingPrincipal: { kind: "system" },
      },
    },
  });
  expect(await processSandboxOutboxBatch(clock)).toBe(cleanup ? 1 : 0);
  expect(manager.dispatchOperation).toHaveBeenCalledTimes(cleanup ? 1 : 0);
  if (control)
    expect((await state(f)).operation.state).toBe(
      kind === "operation.cancel" ? "CANCEL_REQUESTED" : "RUNNING",
    );
});

it.each(["env", "envs", "privateConfig", "configId", "bindingMac", "stdinBase64", "nested"])(
  "system_dispatch_kind_allowlist rejects secret-bearing cleanup %s",
  async (field) => {
    const f = await seed();
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "STOPPING" } });
    await db.inspect.sandboxOperation.update({
      where: { id: f.operation.id },
      data: { kind: "KILL_SANDBOX", authorizingKeyId: null },
    });
    await db.inspect.outboxEvent.update({
      where: { id: f.event.id },
      data: {
        payload: {
          kind: "sandbox.kill",
          sandboxId: f.sandbox.id,
          sandboxHostId: f.host.id,
          operationId: f.operation.id,
          idempotencyKey: f.operation.idempotencyKey,
          generation: 1,
          dispatchAttempt: 0,
          authorizingPrincipal: { kind: "system" },
          [field]: { env: { TOKEN: "synthetic-system-secret" } },
        },
      },
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect((await state(f)).operation.state).toBe("FAILED");
  },
);

it("3B deterministic error after a possible frame keeps DISPATCHED and held", async () => {
  const f = await seed();
  const { SandboxRelayDispatchValidationError } = await import("./protocol.js");
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async (_host, input) => {
    input.onPossibleDispatchFrame?.();
    throw new SandboxRelayDispatchValidationError("synthetic-after-frame");
  });
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  const row = await state(f);
  expect(row.operation.state).toBe("DISPATCHED");
  expect(row.host.liveCount).toBe(1);
  expect(row.sandbox.liveResourcesHeld).toBe(true);
});

it("3B row read errors are indeterminate and preserve pending work", async () => {
  const f = await seed();
  const gate = db.pauseAt("dispatch", { before: "sdkKey.findUnique" });
  const pending = db.run("dispatch", () => processSandboxOutboxBatch(clock));
  await gate.waitReached();
  gate.fail(new Error("synthetic SDK read failure"));
  expect(await pending).toBe(0);
  const row = await state(f);
  expect(row.operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  expect(row.event.processedAt).toBeNull();
  expect(row.host.liveCount).toBe(1);
  expect(await processSandboxOutboxBatch(clock)).toBe(1);
});

it.each([
  ["missing-kind", 0],
  ["binding-mismatch", 0],
  ["wrong-key", 0],
  ["missing-kind", 1],
  ["binding-mismatch", 1],
  ["wrong-key", 1],
] as const)(
  "3B malformed non-control attribution %s with prior attempt %i follows C-26",
  async (malformed, priorAttempt) => {
    const f = await seed();
    if (priorAttempt > 0) {
      await db.inspect.sandboxOperation.update({
        where: { id: f.operation.id },
        data: {
          state: "DISPATCHED",
          dispatchAttempt: priorAttempt,
          dispatchedHostId: f.host.id,
          dispatchedConnectionEpoch: 1,
        },
      });
      await reconnectHost(f.host.id);
    }
    await db.inspect.outboxEvent.update({
      where: { id: f.event.id },
      data: {
        payload: {
          ...(f.event.payload as Record<string, string>),
          authorizingPrincipal:
            malformed === "missing-kind"
              ? { keyId: f.key.id }
              : malformed === "wrong-key"
                ? { kind: "sdkKey", keyId: `${f.key.id}-other` }
                : { kind: "session" },
        },
      },
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    const row = await state(f);
    expect(row.operation).toMatchObject({
      state: priorAttempt === 0 ? "FAILED" : "UNKNOWN_OUTCOME",
      dispatchAttempt: priorAttempt + 1,
      completedAt: expect.any(Date),
      errorCode: "credential_inactive",
      errorDetail: "Accepted dispatch authority is inactive.",
    });
    expect(row.event).toMatchObject({ processedAt: expect.any(Date), claimToken: null });
    expect(row.sandbox.liveResourcesHeld).toBe(priorAttempt > 0);
    expect(row.host.liveCount).toBe(priorAttempt);
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const repeated = await state(f);
    expect(repeated.operation).toEqual(row.operation);
    expect(repeated.sandbox).toEqual(row.sandbox);
    expect(repeated.host.liveCount).toBe(row.host.liveCount);
  },
);

it.each([
  ["extra key", { kind: "session", keyId: "shadow" }],
  ["unknown kind", { kind: "owner" }],
  ["malformed build", { kind: "build", buildId: "b-1" }],
] as const)(
  "R6: undecodable attribution (%s) settles inactive with no session, key or system authority check",
  async (_name, authorizingPrincipal) => {
    const f = await seed();
    await db.inspect.outboxEvent.update({
      where: { id: f.event.id },
      data: {
        payload: { ...(f.event.payload as Record<string, string>), authorizingPrincipal },
      },
    });
    const check = vi.spyOn(access, "checkAcceptedDispatchAuthority");
    try {
      expect(await processSandboxOutboxBatch(clock)).toBe(0);
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      // Never judged as the owner's session (the deleted `?? session` fallback).
      expect(check).not.toHaveBeenCalled();
    } finally {
      check.mockRestore();
    }
    const row = await state(f);
    expect(row.operation).toMatchObject({
      state: "FAILED",
      errorCode: "credential_inactive",
      completedAt: expect.any(Date),
    });
    expect(row.event).toMatchObject({ processedAt: expect.any(Date), claimToken: null });
  },
);

it.each(["inactive", "indeterminate"] as const)(
  "3B refusal terminalizer %s commits while the owner row is exclusively held",
  async (status) => {
    const f = await seed();
    const ownerGate = db.pauseAt("owner-holder", { before: "$transaction.commit" });
    let root: Promise<unknown> | undefined;
    let terminalGate: ReturnType<typeof db.pauseAt> | undefined;
    let ready!: () => void;
    const prepared = new Promise<void>((resolve) => {
      ready = resolve;
    });
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      if (status === "inactive") await refuse(f, "key");
      root = db.run("owner-holder", () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id=${f.ownerId} FOR UPDATE`;
        }),
      );
      await ownerGate.waitReached();
      terminalGate = db.pauseAt("dispatch", { before: "$transaction.commit" });
      ready();
      return "refused_before_frame";
    });
    const pending = db.run("dispatch", () => processSandboxOutboxBatch(clock));
    await prepared;
    try {
      await terminalGate!.waitReached();
      terminalGate!.release();
      expect(await pending).toBe(0);
    } finally {
      ownerGate.release();
      terminalGate?.release();
    }
    await root;
    const row = await state(f);
    expect(row.operation.state).toBe(status === "inactive" ? "FAILED" : "QUEUED");
    expect(row.host.liveCount).toBe(status === "inactive" ? 0 : 1);
  },
);

it.each(["banned", "enrollment", "deleting"] as const)(
  "3B durable owner-policy %s is inactive from rows without a scope rerun",
  async (policy) => {
    const f = await seed();
    await db.inspect.user.update({
      where: { id: f.ownerId },
      data:
        policy === "banned"
          ? { banned: true }
          : policy === "enrollment"
            ? { twoFactorEnabled: false, createdAt: new Date("2020-01-01"), role: "admin" }
            : { deletionRequestedAt: new Date() },
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    expect(row.operation).toMatchObject({ state: "FAILED", dispatchAttempt: 1 });
    expect(row.host.liveCount).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  },
);

it.each(["expired", "missing"] as const)(
  "3B %s accepting SDK key is inactive from its locked row",
  async (keyState) => {
    const f = await seed();
    if (keyState === "expired")
      await db.inspect.sdkKey.update({
        where: { id: f.key.id },
        data: { expiresAt: new Date(Date.now() - 1) },
      });
    else await db.inspect.sdkKey.delete({ where: { id: f.key.id } });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await state(f);
    expect(row.operation).toMatchObject({ state: "FAILED", dispatchAttempt: 1 });
    expect(row.host.liveCount).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  },
);
