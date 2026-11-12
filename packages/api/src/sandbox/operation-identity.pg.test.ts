import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";

/**
 * Operation identity independent of later movement and the accepted launch mode stamp (§8.4), on real
 * PostgreSQL. A "move" is simulated the way a restore rebinds a lineage: a new
 * current placement at a higher generation on another host and host owner.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "operation-identity-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import type { Principal } from "./contracts";
import { RESTORE_INTENT_DIGEST_DOMAIN } from "./digest-context";
import { bindHostSandboxProbe } from "./host-image-verifier";
import { operationTransaction } from "./operation-transaction";
import { probeSandboxReceipt } from "./sdk-mutations";
import { createSandbox, killSandbox, reconnectSandbox } from "./services/sandboxes";
import { offloadSandboxForTest } from "./testing/offload-fixtures";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

const conflict = { data: { code: "sandbox.idempotency_conflict" } };

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  return id;
}

async function fixture() {
  const id = await user();
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "lab", label: "Lab", status: "CONNECTED", egressEnforcement: true },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  // The destination of a simulated move: another owner's host.
  const otherOwner = await user();
  const otherHost = await seedLaunchHost(db.inspect, {
    data: {
      userId: otherOwner,
      slug: "far",
      label: "Far",
      status: "CONNECTED",
      egressEnforcement: true,
    },
  });
  const owner: Principal = { kind: "session", ownerId: id };
  const input = { template: "base", sandboxHostId: host.id, idempotencyKey: randomUUID() };
  return { id, owner, host, revision, otherOwner, otherHost, input };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

/** Settle the create and park the sandbox STOPPED on its disk (3E pattern). */
async function stopped(f: Fixture, sandboxId: string) {
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { userId: f.id },
    data: { processedAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: sandboxId },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { liveCount: 0 } });
}

/** Rebind the lineage: a new current placement at generation + 1 on the
 * other owner's host (what a restore's placement step writes). */
async function simulateMove(f: Fixture, sandboxId: string) {
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: sandboxId },
    include: { CurrentPlacement: true },
  });
  const previous = sandbox.CurrentPlacement;
  if (!previous) throw new Error("fixture sandbox has no placement");
  const generation = sandbox.generation + 1;
  const operation = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: f.id,
      sandboxId,
      kind: "RECONNECT_SANDBOX",
      launchMode: "WARM",
      state: "SUCCEEDED",
      generation,
      idempotencyKey: `move-${randomUUID()}`,
      requestBodyHash: "0".repeat(64),
    },
  });
  const { id: _id, operationId: _op, ...copied } = previous;
  const placement = await db.inspect.sandboxPlacement.create({
    data: {
      ...copied,
      generation,
      operationId: operation.id,
      originHostId: f.otherHost.id,
      hostOwnerId: f.otherOwner,
      acceptedAt: new Date(),
    },
  });
  await db.inspect.sandbox.update({
    where: { id: sandboxId },
    data: { generation, currentPlacementId: placement.id },
  });
}

it("I22 a same-key replay of a pre-move CREATE returns the same sandbox; a changed body conflicts", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  const op = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: created.id, kind: "CREATE_SANDBOX" },
  });
  expect(op.launchMode).toBe("NEW_ROOT");
  expect(op.digestContext).toMatchObject({
    version: 1,
    domain: "wssp-request-v2",
    hostId: f.host.id,
    hostOwnerId: f.id,
    generation: op.generation,
  });
  await simulateMove(f, created.id);
  await expect(createSandbox(f.owner, f.input)).resolves.toMatchObject({ id: created.id });
  await expect(createSandbox(f.owner, { ...f.input, timeoutMs: 1_234_000 })).rejects.toMatchObject(
    conflict,
  );
});

it("I22 a pre-move cold reconnect replays the same operation; launch mode COLD; changed body conflicts", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  await stopped(f, created.id);
  const request = { id: created.id, mode: "cold" as const, idempotencyKey: randomUUID() };
  const first = await reconnectSandbox(f.owner, request);
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: first.operationId },
  });
  expect(op).toMatchObject({ kind: "RECONNECT_SANDBOX", launchMode: "COLD" });
  expect(op.digestContext).toMatchObject({ hostId: f.host.id, hostOwnerId: f.id });
  await simulateMove(f, created.id);
  await expect(reconnectSandbox(f.owner, request)).resolves.toMatchObject({
    operationId: first.operationId,
  });
  await expect(
    reconnectSandbox(f.owner, { ...request, timeoutMs: 1_234_000 }),
  ).rejects.toMatchObject(conflict);
});

it("§8.4 a warm reconnect of a READY sandbox is accepted WARM", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: created.id },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.sandbox.update({ where: { id: created.id }, data: { state: "READY" } });
  const warm = await reconnectSandbox(f.owner, {
    id: created.id,
    mode: "warm",
    idempotencyKey: randomUUID(),
  });
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: warm.operationId } }),
  ).toMatchObject({ kind: "RECONNECT_SANDBOX", launchMode: "WARM" });
});

it("I22 an action receipt after the sandbox moved replays the same receipt", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  bindHostSandboxProbe(async () => "guest_ready");
  const input = { id: created.id, idempotencyKey: randomUUID() };
  const first = await probeSandboxReceipt(f.owner, input);
  expect(
    (await db.inspect.sandboxActionReceipt.findUniqueOrThrow({ where: { id: first.operationId } }))
      .digestContext,
  ).toMatchObject({ domain: "wssp-action-v2", hostId: f.host.id, hostOwnerId: f.id });
  await simulateMove(f, created.id);
  await expect(probeSandboxReceipt(f.owner, input)).resolves.toEqual(first);
});

it("CN3 an OFFLOADED sandbox: env-free kill and a hostless restore intent never throw in operationTransaction", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  await stopped(f, created.id);
  await db.inspect.$transaction((tx) =>
    offloadSandboxForTest(tx, { userId: f.id, sandboxId: created.id, hostId: f.host.id }),
  );
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect(sandbox).toMatchObject({
    state: "OFFLOADED",
    hostOwnerId: null,
    currentPlacementId: null,
  });

  const accept = (
    kind: "KILL_SANDBOX" | "RECONNECT_SANDBOX",
    action: "sandboxes.kill" | "sandboxes.reconnect",
    key: string,
    intent: unknown,
  ) =>
    operationTransaction(
      f.owner,
      { key, intent, kind, action, target: { sandboxId: created.id } },
      async (tx, digest) =>
        (
          await tx.sandboxOperation.create({
            data: {
              digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),

              userId: f.id,
              sandboxId: created.id,
              kind,
              state: "QUEUED",
              generation: sandbox.generation,
              idempotencyKey: key,
              requestBodyHash: digest(),
              ...(kind === "KILL_SANDBOX"
                ? { requestDigestScheme: "sha256-env-free-v1", requestDigestKeyId: null }
                : (await import("./idempotency")).requestDigestMetadata()),
            },
            select: { id: true },
          })
        ).id,
      async (_tx, prior) => prior.id,
    );

  const killKey = randomUUID();
  const killIntent = { sandboxId: created.id };
  const kill = await accept("KILL_SANDBOX", "sandboxes.kill", killKey, killIntent);
  expect(await accept("KILL_SANDBOX", "sandboxes.kill", killKey, killIntent)).toBe(kill);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: kill } })).digestContext,
  ).toMatchObject({ domain: "env-free", hostId: "", hostOwnerId: "" });

  const restoreKey = randomUUID();
  const restoreIntent = { sandboxId: created.id, generation: sandbox.generation, timeoutMs: 1 };
  const restore = await accept(
    "RECONNECT_SANDBOX",
    "sandboxes.reconnect",
    restoreKey,
    restoreIntent,
  );
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: restore } })).digestContext,
  ).toMatchObject({ domain: RESTORE_INTENT_DIGEST_DOMAIN, hostId: "", hostOwnerId: "" });
  expect(await accept("RECONNECT_SANDBOX", "sandboxes.reconnect", restoreKey, restoreIntent)).toBe(
    restore,
  );
  await expect(
    accept("RECONNECT_SANDBOX", "sandboxes.reconnect", restoreKey, {
      ...restoreIntent,
      timeoutMs: 2,
    }),
  ).rejects.toMatchObject(conflict);

  // The service kill reaches its own state rule, never a transport throw.
  const refused = await killSandbox(f.owner, { id: created.id, idempotencyKey: randomUUID() }).then(
    () => null,
    (error: unknown) => error,
  );
  expect(refused).not.toMatchObject({ data: { code: "digest_key_unavailable" } });
});
