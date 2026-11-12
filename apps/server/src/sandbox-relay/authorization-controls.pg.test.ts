import {
  seedAcceptedOperation,
  seedDispatchEvent,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "s3b-wire-host-test",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
// The socket starts at the already-authenticated host boundary. SDK authority,
// accept, dispatch, row locks, frame normalization and encoding are production.
vi.mock("@wssp/api/lib/host-token-access", async (original) => ({
  ...(await original<typeof import("@wssp/api/lib/host-token-access")>()),
  revalidateSandboxHostIdentity: vi.fn(async () => ({
    status: "active",
    hostDeletionRequested: false,
  })),
}));
const db = await pgTestDatabase();
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { parseBinaryFrame } = await import("./protocol.js");
const { bindSandboxDispatchWake } = await import("@wssp/api/sandbox/outbox");
const services = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { revokeSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const owners: string[] = [];
afterAll(async () => {
  await manager.dispose();
  await db.close();
});
afterEach(async () => {
  vi.restoreAllMocks();
  bindSandboxDispatchWake(null);
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
});
class Socket {
  readyState = 1;
  messages: Record<string, unknown>[] = [];
  binary: Uint8Array[] = [];
  onDispatch?: () => void;
  send(data: string | ArrayBuffer | Uint8Array) {
    if (typeof data === "string") {
      const message = JSON.parse(data) as Record<string, unknown>;
      this.messages.push(message);
      if (message.type === "operation.dispatch") this.onDispatch?.();
    } else this.binary.push(data instanceof Uint8Array ? data : new Uint8Array(data));
  }
  close() {
    this.readyState = 3;
  }
}
async function seed(admission = true, pooled = false) {
  const ownerId = `s3b-controls-${randomUUID()}`;
  owners.push(ownerId);
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test`, twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: ownerId, slug: "lab", label: "Lab", connectionEpoch: 0 },
  });
  const socket = new Socket();
  expect(
    manager.acceptAuthenticatedSocket({
      socket,
      identity: {
        hostId: host.id,
        userId: ownerId,
        tokenId: randomUUID(),
        credentialKind: "hostToken",
        expiresAt: null,
      },
    }),
  ).toBe(true);
  manager.handleTextFrame(
    socket,
    JSON.stringify({
      ...helloFixture(host.id),
    }),
  );
  await manager.drain(socket);
  manager.handleTextFrame(
    socket,
    JSON.stringify({
      type: "host.admission",
      ...capacityFixture(host.id),
      journalId: "1234567890abcdef1234567890abcdef",
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: true,
      terminal: false,
    }),
  );
  await manager.drain(socket);
  manager.handleTextFrame(
    socket,
    JSON.stringify({ type: "sandbox.inventory", page: 0, complete: true, entries: [] }),
  );
  await manager.drain(socket);
  manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
  await manager.drain(socket);
  if (admission) {
    const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "journal.key.ack",
        connectionEpoch: 1,
        keyVersion: 1,
        keyId: requestDigestMetadata().requestDigestKeyId,
      }),
    );
    await manager.drain(socket);
  }
  expect(manager.isHostConnected(host.id, 1)).toBe(true);
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
  const pool = pooled
    ? await db.inspect.sandboxPool.create({
        data: { userId: ownerId, slug: "pool", label: "Pool" },
      })
    : null;
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: revision.id,
      originPoolId: pool?.id ?? null,
      state: "READY",
      liveResourcesHeld: true,
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  await db.inspect.sandboxHost.update({ where: { id: host.id }, data: { liveCount: 1 } });
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: ownerId,
      name: "creator-without-cancel",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALLOWLIST",
      scopes: ["commands:execute"],
      PoolAllowlist: pool ? { create: { poolId: pool.id, poolOwnerId: ownerId } } : undefined,
      HostAllowlist: { create: { sandboxHostId: host.id } },
      RevisionAllowlist: { create: { templateRevisionId: revision.id } },
    },
  });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: ownerId,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      authorizingKeyId: key.id,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      ...requestDigestMetadata(),
    },
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    data: { authorizingKeyId: key.id },
  });
  return { ownerId, host, revision, sandbox, key, operation, socket, pool };
}
type Fixture = Awaited<ReturnType<typeof seed>>;
async function queueCommand(f: Fixture) {
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: {
      state: "QUEUED",
      dispatchAttempt: 0,
      acceptedAttempt: null,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    },
  });
  return seedDispatchEvent(db.inspect, {
    data: {
      userId: f.ownerId,
      aggregateType: "sandbox",
      aggregateId: f.sandbox.id,
      eventType: "sandbox.command_requested",
      payload: {
        sandboxOwnerId: f.ownerId,
        sandboxId: f.sandbox.id,
        sandboxHostId: f.host.id,
        operationId: f.operation.id,
        generation: 1,
        dispatchAttempt: 0,
        kind: "command.run",
        idempotencyKey: f.operation.idempotencyKey,
        argv: ["true"],
        authorizingPrincipal: { kind: "sdkKey", keyId: f.key.id },
      },
    },
  });
}

it("3B R1-1 unacked keyed work stays unclaimed across drains and dispatches on journal ACK", async () => {
  const f = await seed(true);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { journalKeyAcknowledgedEpoch: null },
  });
  const event = await queueCommand(f);
  const dispatch = vi.spyOn(manager, "dispatchOperation");
  const transactions = vi.spyOn(
    await import("@wssp/api/sandbox/outbox"),
    "sandboxOutboxTransaction",
  );
  const wake = vi.fn();
  bindSandboxDispatchWake(wake);
  for (let drain = 1; drain <= 4; drain++) {
    expect(await processSandboxOutboxBatch()).toBe(0);
    // One prepare transaction per external scan, no send or refusal transaction.
    expect(transactions).toHaveBeenCalledTimes(drain);
    expect(dispatch).not.toHaveBeenCalled();
    expect(wake).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } }),
    ).toMatchObject({
      claimToken: null,
      processedAt: null,
      sentAt: null,
    });
  }
  manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: 1,
      keyVersion: 1,
      keyId: requestDigestMetadata().requestDigestKeyId,
    }),
  );
  await manager.drain(f.socket);
  expect(wake).toHaveBeenCalledOnce();
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(dispatch).toHaveBeenCalledOnce();
  expect(f.socket.messages.at(-1)).toMatchObject({
    sandboxOwnerId: f.ownerId,
    type: "operation.dispatch",
    operationId: f.operation.id,
    attempt: 1,
  });
});

it("3B R1-1 an ACK for the current key cannot claim work recorded under an old key", async () => {
  const f = await seed(true);
  const event = await queueCommand(f);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { journalKeyAcknowledgedEpoch: 1 },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { requestDigestKeyId: "0".repeat(32) },
  });
  const dispatch = vi.spyOn(manager, "dispatchOperation");
  for (let drain = 0; drain < 3; drain++) expect(await processSandboxOutboxBatch()).toBe(0);
  expect(dispatch).not.toHaveBeenCalled();
  expect(await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } })).toMatchObject(
    {
      claimToken: null,
      processedAt: null,
    },
  );
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
  ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
});

it("3B R1-1 SDK dispatch waits for the sandbox to be bound to its session host", async () => {
  const f = await seed();
  const event = await queueCommand(f);
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { sandboxHostId: null, diskReservationHeld: false },
  });
  const dispatch = vi.spyOn(manager, "dispatchOperation");
  for (let drain = 0; drain < 3; drain++) expect(await processSandboxOutboxBatch()).toBe(0);
  expect(dispatch).not.toHaveBeenCalled();
  expect(await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } })).toMatchObject(
    {
      claimToken: null,
      processedAt: null,
    },
  );
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { sandboxHostId: f.host.id, diskReservationHeld: true },
  });
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(dispatch).toHaveBeenCalledOnce();
});

async function seedControl(f: Fixture, kind: "process.stdin" | "operation.cancel", keyId?: string) {
  if (kind === "operation.cancel")
    await db.inspect.sandboxOperation.update({
      where: { id: f.operation.id },
      data: { state: "CANCEL_REQUESTED" },
    });
  return seedDispatchEvent(db.inspect, {
    data: {
      userId: f.ownerId,
      aggregateType: "sandbox",
      aggregateId: f.sandbox.id,
      eventType: "sandbox.control_requested",
      payload: {
        sandboxId: f.sandbox.id,
        sandboxHostId: f.host.id,
        operationId: f.operation.id,
        generation: 1,
        dispatchAttempt: 1,
        kind,
        ...(kind === "process.stdin"
          ? {
              stdinBase64: Buffer.from("control bytes \u0000😀").toString("base64"),
              stdinSequence: 7,
              eof: true,
            }
          : {}),
        authorizingPrincipal: keyId ? { kind: "sdkKey", keyId } : { kind: "session" },
      },
    },
  });
}
function assertStdin(f: Fixture, sequence: number, bytes: Uint8Array) {
  const frame = parseBinaryFrame(new Uint8Array(f.socket.binary.at(-1)!).buffer);
  expect(frame).toMatchObject({
    metadata: {
      operationId: f.operation.id,
      generation: 1,
      attempt: 1,
      sequence,
      flags: { stdin: true },
    },
    body: new Uint8Array(bytes),
  });
}

it.each(["session", "sdk"] as const)(
  "%s control delivers actual cancel and exact stdin bytes/sequence",
  async (kind) => {
    const f = await seed();
    const keyId = kind === "sdk" ? f.key.id : undefined;
    if (kind === "session")
      await db.inspect.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    await seedControl(f, "process.stdin", keyId);
    expect(await processSandboxOutboxBatch()).toBe(1);
    assertStdin(f, 7, Buffer.from("control bytes \u0000😀"));
    await seedControl(f, "operation.cancel", keyId);
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(f.socket.messages.at(-1)).toMatchObject({
      type: "operation.cancel",
      operationId: f.operation.id,
      generation: 1,
      attempt: 1,
    });
  },
);

it.each(
  [false, true].flatMap((pooled) =>
    (["revoked", "missing-grants", "missing-pool"] as const).map(
      (reason) => [pooled, reason] as const,
    ),
  ),
)(
  "browser cancel and stdin ignore creating SDK key (pooled: %s, %s) and absent cancel scope",
  async (pooled, reason) => {
    const f = await seed(true, pooled);
    if (reason === "revoked")
      await db.inspect.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    else if (reason === "missing-pool")
      await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
    else await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
    const owner = { kind: "session" as const, ownerId: f.ownerId };
    await services.writeStdin(owner, {
      operationId: f.operation.id,
      contentBase64: Buffer.from("browser bytes").toString("base64"),
      eof: true,
    });
    const stdin = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: f.sandbox.id, eventType: "sandbox.stdin_requested" },
    });
    expect(stdin.payload).toMatchObject({ authorizingPrincipal: { kind: "session" } });
    expect(await processSandboxOutboxBatch()).toBe(1);
    assertStdin(f, 0, Buffer.from("browser bytes"));
    await services.cancelOperation(owner, { operationId: f.operation.id });
    const cancel = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: f.sandbox.id, eventType: "sandbox.operation_cancel_requested" },
    });
    expect(cancel.payload).toMatchObject({ authorizingPrincipal: { kind: "session" } });
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(f.socket.messages.at(-1)).toMatchObject({
      type: "operation.cancel",
      operationId: f.operation.id,
    });
  },
);

it.each(["malformed", "inactive", "system"] as const)(
  "3B %s control records constant refusal without changing its target",
  async (reason) => {
    const f = await seed();
    const event = await seedControl(
      f,
      "process.stdin",
      reason === "inactive" ? f.key.id : undefined,
    );
    if (reason === "inactive")
      await db.inspect.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    else
      await db.inspect.outboxEvent.update({
        where: { id: event.id },
        data: {
          payload: {
            ...(event.payload as Record<string, string>),
            authorizingPrincipal: reason === "system" ? { kind: "system" } : { kind: "sdkKey" },
          },
        },
      });
    const before = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    });
    expect(await processSandboxOutboxBatch()).toBe(0);
    expect(f.socket.binary).toHaveLength(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toEqual(before);
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } }),
    ).toMatchObject({
      processedAt: expect.any(Date),
      payload: {
        dispatchRefusal: reason === "inactive" ? "credential_inactive" : "protocol_error",
      },
    });
  },
);

it("3B socket authorization locks K before H and holds no owner admission", async () => {
  const f = await seed();
  const held = db.pauseAt("holder", { before: "$transaction.commit" });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id=${f.key.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const sending = db.run("sender", () =>
    manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, {
      kind: "sdkKey",
      keyId: f.key.id,
    }),
  );
  expect((await db.waitUntilBlocked("sender", { by: "holder" })).query).toMatch(
    /sdk_key.*FOR SHARE/,
  );
  await db.inspect.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id=${f.host.id} FOR UPDATE NOWAIT`;
    await tx.$queryRaw`SELECT id FROM "user" WHERE id=${f.ownerId} FOR UPDATE NOWAIT`;
  });
  held.release();
  await holder;
  expect(await sending).toBe(true);
});

it("post_frame_authority_loss_keeps_dispatched on the actual socket during initial stdin", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: {
      state: "QUEUED",
      dispatchAttempt: 0,
      acceptedAttempt: null,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    },
  });
  await seedDispatchEvent(db.inspect, {
    data: {
      userId: f.ownerId,
      aggregateType: "sandbox",
      aggregateId: f.sandbox.id,
      eventType: "sandbox.command_requested",
      payload: {
        sandboxOwnerId: f.ownerId,
        sandboxId: f.sandbox.id,
        sandboxHostId: f.host.id,
        operationId: f.operation.id,
        generation: 1,
        dispatchAttempt: 0,
        kind: "command.run",
        idempotencyKey: f.operation.idempotencyKey,
        argv: ["true"],
        stdinBase64: "aGk=",
        hasStdin: true,
        authorizingPrincipal: { kind: "sdkKey", keyId: f.key.id },
      },
    },
  });
  let revoking: Promise<unknown> | undefined;
  f.socket.onDispatch = () => {
    revoking = revokeSdkKey({ kind: "session", ownerId: f.ownerId }, { id: f.key.id });
  };
  expect(await processSandboxOutboxBatch()).toBe(0);
  await revoking;
  expect(f.socket.messages.some((message) => message.type === "operation.dispatch")).toBe(true);
  expect(f.socket.binary).toHaveLength(0);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
  ).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 1 });
});

it("creating key socket send retains accepted work after revision-grant loss", async () => {
  const f = await seed();
  const principal = { kind: "sdkKey" as const, keyId: f.key.id };
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
  await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
  const before = f.socket.messages.length;
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
  expect(f.socket.messages).toHaveLength(before + 1);
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: { userId: f.ownerId, sdkKeyId: f.key.id, templateRevisionId: f.revision.id },
  });
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
});

it("creating key socket send survives future origin-pool grant removal", async () => {
  const f = await seed(true, true);
  const principal = { kind: "sdkKey" as const, keyId: f.key.id };
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
  await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: f.key.id } });
  const before = f.socket.messages.length;
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
  expect(f.socket.messages).toHaveLength(before + 1);
  await db.inspect.sdkKeyPoolAllowlist.create({
    data: {
      poolOwnerId: f.ownerId,
      userId: f.ownerId,
      sdkKeyId: f.key.id,
      poolId: f.pool!.id,
    },
  });
  expect(await manager.cancelOperation(f.host.id, f.operation.id, 1, 1, 1, principal)).toBe(true);
});

async function controller(f: Fixture) {
  const row = await db.inspect.sdkKey.create({
    data: {
      userId: f.ownerId,
      name: "independent-controller",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALL_OWNED",
      scopes: ["commands:execute", "operations:cancel", "operations:read"],
      HostAllowlist: { create: { sandboxHostId: f.host.id } },
      RevisionAllowlist: { create: { templateRevisionId: f.revision.id } },
      PoolAllowlist: f.pool ? { create: { poolId: f.pool.id, poolOwnerId: f.ownerId } } : undefined,
    },
  });
  const { revalidateSdkKey } = await import("@wssp/api/lib/sdk-key-access");
  const principal = await revalidateSdkKey(row.id, f.ownerId);
  if (!principal) throw new Error("Controller fixture was refused");
  return principal;
}

it.each(["stdin", "cancel"] as const)(
  "B5 %s dispatch uses control principal/grants, independently of creator revocation",
  async (kind) => {
    const f = await seed(true, true);
    const principal = await controller(f);
    const { writeStdinReceipt, cancelOperationReceipt } = await import(
      "@wssp/api/sandbox/sdk-mutations"
    );
    await db.inspect.sdkKey.update({ where: { id: f.key.id }, data: { revokedAt: new Date() } });
    const input = {
      operationId: f.operation.id,
      idempotencyKey: randomUUID(),
      contentBase64: Buffer.from("own principal").toString("base64"),
    };
    const receipt = await (kind === "stdin"
      ? writeStdinReceipt(principal, input)
      : cancelOperationReceipt(principal, input));
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: {
        userId: f.ownerId,
        eventType:
          kind === "stdin" ? "sandbox.stdin_requested" : "sandbox.operation_cancel_requested",
      },
    });
    expect(event.payload).toMatchObject({
      authorizingPrincipal: { kind: "sdkKey", keyId: principal.keyId },
    });
    expect(await processSandboxOutboxBatch()).toBe(1);
    if (kind === "stdin") {
      assertStdin(f, 0, Buffer.from("own principal"));
      expect(
        await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
          where: { id: receipt.operationId },
        }),
      ).toMatchObject({ state: "SUCCEEDED", authorizingKeyId: principal.keyId });
    } else
      expect(f.socket.messages.at(-1)).toMatchObject({
        type: "operation.cancel",
        operationId: f.operation.id,
      });
  },
);

it("B5 control-key revoke AFTER prepare but BEFORE send emits no stdin frame and never rewrites accepted receipt/target", async () => {
  const f = await seed();
  const principal = await controller(f);
  const { writeStdinReceipt } = await import("@wssp/api/sandbox/sdk-mutations");
  const receipt = await writeStdinReceipt(principal, {
    operationId: f.operation.id,
    idempotencyKey: randomUUID(),
    contentBase64: Buffer.from("held input").toString("base64"),
  });
  const held = db.pauseAt("send", { before: /sdk_key.*FOR SHARE/ });
  const actual = manager.sendStdin.bind(manager);
  vi.spyOn(manager, "sendStdin").mockImplementation((...args) =>
    db.run("send", () => actual(...args)),
  );
  const draining = processSandboxOutboxBatch();
  await held.waitReached();
  await revokeSdkKey({ kind: "session", ownerId: f.ownerId }, { id: principal.keyId });
  held.release();
  await draining;
  expect(f.socket.binary).toHaveLength(0);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
  ).toMatchObject({ state: "RUNNING", authorizingKeyId: f.key.id });
  expect(
    await db.inspect.sandboxActionReceipt.findUniqueOrThrow({ where: { id: receipt.operationId } }),
  ).toMatchObject({ state: "SUCCEEDED", authorizingKeyId: principal.keyId });
});

it("B5 last control send locks H/S/O without owner admission; committed withdrawal refuses remaining stdin", async () => {
  const f = await seed();
  const held = db.pauseAt("send", { before: /sandbox_mutation_operation.*FOR SHARE/ });
  const sending = db.run("send", () =>
    manager.sendStdin(f.host.id, f.operation.id, 1, 1, Buffer.from("input"), false, 1, 0, {
      kind: "session",
    }),
  );
  await held.waitReached();
  await db.inspect.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id=${f.ownerId} FOR UPDATE NOWAIT`;
  });
  const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
  const finalizing = db.run("finalizer", () =>
    deleteHost({ kind: "session", ownerId: f.ownerId }, { id: f.host.id }),
  );
  expect((await db.waitUntilBlocked("finalizer", { by: "send" })).query).toMatch(/sandbox_host/);
  held.release();
  // T2 marks pending host deletion stale before it waits for H. The last
  // authority check now refuses before the frame-count diagnostic can run.
  expect(await sending).toBe(false);
  await finalizing;
  expect(f.socket.binary).toHaveLength(0);
});

it.each(
  ["replacement", "payload"].flatMap((mismatch) =>
    ["stdin", "cancel"].map((kind) => ({ mismatch, kind })),
  ),
)(
  "B5 $mismatch epoch refuses old $kind without touching target, slot or stream receipts",
  async ({ mismatch, kind }) => {
    const f = await seed();
    const { writeStdinReceipt, cancelOperationReceipt } = await import(
      "@wssp/api/sandbox/sdk-mutations"
    );
    const owner = { kind: "session" as const, ownerId: f.ownerId };
    const receipt =
      kind === "stdin"
        ? await writeStdinReceipt(owner, {
            operationId: f.operation.id,
            idempotencyKey: randomUUID(),
            contentBase64: Buffer.from("old pipe").toString("base64"),
          })
        : await cancelOperationReceipt(owner, {
            operationId: f.operation.id,
            idempotencyKey: randomUUID(),
          });
    const before = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    });
    let receiver = f.socket;
    if (mismatch === "replacement") {
      receiver = new Socket();
      expect(
        manager.acceptAuthenticatedSocket({
          socket: receiver,
          identity: {
            hostId: f.host.id,
            userId: f.ownerId,
            tokenId: randomUUID(),
            credentialKind: "hostToken",
            expiresAt: null,
          },
        }),
      ).toBe(true);
      manager.handleTextFrame(
        receiver,
        JSON.stringify({
          ...helloFixture(f.host.id),
        }),
      );
      await manager.drain(receiver);
      manager.handleTextFrame(
        receiver,
        JSON.stringify({
          type: "sandbox.inventory",
          page: 0,
          complete: true,
          entries: [
            { sandboxOwnerId: f.ownerId, root: null, sandboxId: f.sandbox.id, state: "ready" },
          ],
        }),
      );
      await manager.drain(receiver);
      manager.handleTextFrame(receiver, JSON.stringify({ type: "reconcile.complete" }));
      await manager.drain(receiver);
      expect(manager.isHostConnected(f.host.id, 2)).toBe(true);
      // Reconciliation has its own old-operation sweep. Reconstitute the
      // accepted target/event fixtures to isolate the send-side refusal below;
      // its dispatch identity remains bound to epoch 1 throughout.
      await db.inspect.sandboxOperation.update({
        where: { id: f.operation.id },
        data: {
          state: before.state,
          completedAt: before.completedAt,
          errorCode: before.errorCode,
        },
      });
      await db.inspect.outboxEvent.updateMany({
        where: {
          userId: f.ownerId,
          eventType: { in: ["sandbox.stdin_requested", "sandbox.operation_cancel_requested"] },
        },
        data: { processedAt: null },
      });
    } else {
      const events = await db.inspect.outboxEvent.findMany({
        where: { userId: f.ownerId, processedAt: null },
        take: 10,
      });
      for (const event of events) {
        const payload = event.payload;
        if (!payload || typeof payload !== "object" || Array.isArray(payload))
          throw new Error("Expected control payload");
        await db.inspect.outboxEvent.update({
          where: { id: event.id },
          data: { payload: { ...payload, connectionEpoch: 2 } },
        });
      }
      expect(manager.isHostConnected(f.host.id, 1)).toBe(true);
    }
    const targetBefore = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    });
    const slotBefore = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
    receiver.messages.length = 0;
    expect(await processSandboxOutboxBatch()).toBe(0);
    const events = await db.inspect.outboxEvent.findMany({
      where: {
        userId: f.ownerId,
        eventType: { in: ["sandbox.stdin_requested", "sandbox.operation_cancel_requested"] },
      },
      take: 10,
    });
    expect(events).toHaveLength(1);
    for (const event of events) {
      expect(event.processedAt).not.toBeNull();
      expect(event.payload).toMatchObject({ dispatchRefusal: "unknown_outcome" });
    }
    expect(receiver.binary).toHaveLength(0);
    expect(receiver.messages).toHaveLength(0);
    expect(f.socket.binary).toHaveLength(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toEqual(targetBefore);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).toEqual(
      slotBefore,
    );
    expect(slotBefore.liveResourcesHeld).toBe(true);
    expect(
      await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
        where: { id: receipt.operationId },
      }),
    ).toMatchObject({ state: kind === "stdin" ? "SUCCEEDED" : "CANCEL_REQUESTED" });
  },
);

it("B5 the last socket gate refuses stdin from an unbound prior operation epoch", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { dispatchedConnectionEpoch: 0 },
  });
  expect(
    await manager.sendStdin(
      f.host.id,
      f.operation.id,
      1,
      1,
      Buffer.from("old input"),
      false,
      1,
      0,
      { kind: "session" },
    ),
  ).toBe(false);
  expect(f.socket.binary).toHaveLength(0);
});
