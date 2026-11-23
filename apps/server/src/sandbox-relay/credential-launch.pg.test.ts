import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../../../../packages/api/src/lib/procedure-budget", () => ({
  createProcedureBudget: () => async () => {},
}));

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { parseCredentialSpec } from "@wssp/sandbox-contracts";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_MAX_TIMEOUT_MS: 86_400_000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
const relay = vi.hoisted(() => ({ dispatchOperation: vi.fn() }));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: relay.dispatchOperation,
    captureHostDispatchCredential: vi.fn(),
  },
}));

/**
 * C8a launch path against real PostgreSQL: a create naming a login writes the attachment, claims a RESERVED
 * lease naming the create operation, stores the spec and dispatches its
 * reference; READY is published only once every lease is ACTIVE; a launch
 * that ends without READY settles its leases.
 */
const db = await pgTestDatabase();
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const service = await import("@wssp/api/credentials/service");
const { applyInstalledReceipt, grantInstallBundle, recordInstalled } = await import(
  "@wssp/api/credentials/relay"
);
const { leaseWireSchema } = await import("@wssp/api/sandbox/lease-wire");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { applyOperationResult } = await import("./operation-handlers.js");
afterAll(() => db.close());

const savedKey = process.env.DATA_ENCRYPTION_KEY;
const savedEnabled = process.env.CREDENTIALS_ENABLED;
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
  if (savedEnabled === undefined) delete process.env.CREDENTIALS_ENABLED;
  else process.env.CREDENTIALS_ENABLED = savedEnabled;
});

const FP = `sha256:${"c".repeat(64)}`;
const CREDENTIAL_CAPABILITY = {
  files: true,
  env: true,
  proxy: false,
  sealedReturn: true,
  checkpoint: true,
  specTransfer: true,
  maxBundleBytes: 4_823_129,
  returnKeyEpoch: 0,
};

async function fixture(options: { capable?: boolean } = {}) {
  const ownerId = `cred-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
      daemonFeatures: {
        egressPolicy: true,
        terminal: true,
        ...(options.capable === false ? {} : { credentials: CREDENTIAL_CAPABILITY }),
      },
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
  const actor = { kind: "session" as const, ownerId };
  const slug = `tool-${randomUUID().slice(0, 8)}`;
  const definition = await service.createDefinition(actor, {
    document: {
      schemaVersion: 1,
      id: slug,
      displayName: "Tool",
      login: { command: "tool login", method: "device-code" },
      credentials: {
        files: { required: [".config/tool"], optional: [], exclude: [] },
        sharing: "exclusive",
      },
    },
  });
  const login = await service.createLogin(actor, { name: slug, definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  await service.writeValue(actor, {
    credentialId: login.id,
    instanceId: instance.id,
    files: [
      { path: ".config/tool", kind: "dir" },
      { path: ".config/tool/token", contentBase64: Buffer.from("token-v1").toString("base64") },
    ],
  });
  return { ownerId, actor, host, template, login, instance };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

async function create(f: Fixture) {
  const sandbox = await createSandbox(f.actor, {
    template: `revision/${f.template.id}`,
    sandboxHostId: f.host.id,
    idempotencyKey: `create-${randomUUID()}`,
    credentials: [{ credentialId: f.login.id, instanceId: f.instance.id }],
  });
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  return { sandbox, operation };
}

async function dispatch(f: Fixture, sandboxId: string) {
  relay.dispatchOperation.mockReset();
  relay.dispatchOperation.mockResolvedValue("sent");
  await db.inspect.sandboxExecutionConfig.updateMany({
    where: { sandboxId, userId: f.ownerId },
    data: { acknowledgedEpoch: 1, acknowledgedAt: new Date() },
  });
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  await processSandboxOutboxBatch();
}

async function readyResult(f: Fixture, sandboxId: string, operationId: string) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.ownerId, payload: { path: ["operationId"], equals: operationId } },
  });
  const payload = event.payload as Record<string, unknown>;
  const lease = leaseWireSchema.safeParse(payload.lease);
  return {
    sender: { userId: f.ownerId, hostId: f.host.id, connectionEpoch: 1 },
    operationId,
    sandboxId,
    generation: op.generation,
    attempt: op.dispatchAttempt,
    state: "succeeded",
    receipt: {
      bodyHash: op.requestBodyHash,
      idempotencyKey: op.idempotencyKey,
      kind: String(payload.kind),
    },
    result: { state: "ready", ...(lease.success ? { lease: lease.data } : {}) },
  };
}

const leaseOf = (sandboxId: string) =>
  db.inspect.credentialLease.findFirstOrThrow({ where: { sandboxId } });

/** create → dispatch → grant: the lease is INSTALLING, no frame applied yet. */
async function installing(f: Fixture) {
  const { sandbox, operation } = await create(f);
  await dispatch(f, sandbox.id);
  const lease = await leaseOf(sandbox.id);
  const granted = await grantInstallBundle({
    hostId: f.host.id,
    connectionEpoch: 1,
    requestId: `req-${randomUUID()}`,
    sandboxId: sandbox.id,
    leaseId: lease.id,
    operationId: operation.id,
  });
  if (granted.kind !== "granted") throw new Error(`grant refused: ${JSON.stringify(granted)}`);
  granted.bytes.fill(0);
  expect((await leaseOf(sandbox.id)).state).toBe("INSTALLING");
  return { sandbox, operation, lease, bindingId: granted.bindingId };
}

describe("C8a credential launch (pg)", () => {
  it("a direct create with a login writes the attachment, a RESERVED lease naming the create, the spec, and dispatches its reference", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    expect(
      await db.inspect.sandboxCredential.findFirstOrThrow({
        where: { sandboxId: sandbox.id },
        select: { credentialId: true, instanceId: true, requestedInstanceId: true },
      }),
    ).toEqual({ credentialId: f.login.id, instanceId: f.instance.id, requestedInstanceId: null });
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RESERVED",
      operationId: operation.id,
      instanceId: f.instance.id,
      hostId: f.host.id,
    });
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId: operation.id },
    });
    const digest = createHash("sha256").update(stored.bytes).digest("hex");
    expect(Buffer.from(stored.digest).toString("hex")).toBe(digest);
    const spec = parseCredentialSpec(stored.bytes);
    expect(spec.leases).toMatchObject([{ credentialId: f.login.id, action: "inject" }]);
    expect(spec.residue).toEqual([]);
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { userId: f.ownerId, payload: { path: ["operationId"], equals: operation.id } },
    });
    expect((event.payload as Record<string, unknown>).credentialSpec).toEqual({
      digest,
      bytes: stored.bytes.byteLength,
    });
    await dispatch(f, sandbox.id);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({
        kind: "sandbox.create",
        credentialSpec: { digest, bytes: stored.bytes.byteLength },
      }),
    );
  });

  it("a host without the credential capability is refused host_forbidden before any lease", async () => {
    const f = await fixture({ capable: false });
    await expect(create(f)).rejects.toSatisfy(
      (e) => (e as { data?: { code?: string } }).data?.code === "credential.host_forbidden",
    );
    expect(await db.inspect.credentialLease.count({ where: { userId: f.ownerId } })).toBe(0);
    expect(await db.inspect.sandbox.count({ where: { userId: f.ownerId } })).toBe(0);
  });

  it("an SDK key naming a login is refused before anything is written", async () => {
    const f = await fixture();
    await expect(
      createSandbox(
        {
          kind: "sdkKey",
          ownerId: f.ownerId,
          keyId: "k",
          resourceMode: "ALL_OWNED",
        } as never,
        {
          template: `revision/${f.template.id}`,
          sandboxHostId: f.host.id,
          idempotencyKey: `create-${randomUUID()}`,
          credentials: [{ credentialId: f.login.id }],
        },
      ),
    ).rejects.toBeTruthy();
    expect(await db.inspect.sandbox.count({ where: { userId: f.ownerId } })).toBe(0);
  });

  it("install before READY: grant → installed → ACTIVE → the create result publishes READY and drops the spec", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    await dispatch(f, sandbox.id);
    const lease = await leaseOf(sandbox.id);
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: 1,
      requestId: "req-1",
      sandboxId: sandbox.id,
      leaseId: lease.id,
      operationId: operation.id,
    });
    expect(granted).toMatchObject({ kind: "granted", storageSeq: 1, fileCount: 2 });
    if (granted.kind !== "granted") throw new Error("unreachable");
    granted.bytes.fill(0);
    expect(
      await recordInstalled({
        hostId: f.host.id,
        connectionEpoch: 1,
        leaseId: lease.id,
        bindingId: granted.bindingId,
        storageSeq: 1,
      }),
    ).toBe(true);
    expect(
      await applyOperationResult(await readyResult(f, sandbox.id, operation.id)),
    ).toMatchObject({ written: true });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: sandbox.id },
        select: { state: true },
      }),
    ).toEqual({ state: "READY" });
    expect((await leaseOf(sandbox.id)).state).toBe("ACTIVE");
    expect(
      await db.inspect.credentialOperationSpec.count({ where: { operationId: operation.id } }),
    ).toBe(0);
  });

  it("a ready result with a lease still INSTALLING is a credential install failure, never READY; the lease is RELEASED and its residue non-recoverable", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    await dispatch(f, sandbox.id);
    const lease = await leaseOf(sandbox.id);
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: 1,
      requestId: "req-1",
      sandboxId: sandbox.id,
      leaseId: lease.id,
      operationId: operation.id,
    });
    if (granted.kind === "granted") granted.bytes.fill(0);
    await applyOperationResult(await readyResult(f, sandbox.id, operation.id));
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: operation.id },
      select: { state: true, errorCode: true },
    });
    expect(op).toEqual({ state: "FAILED", errorCode: "credential_install_failed" });
    expect(
      (
        await db.inspect.sandbox.findUniqueOrThrow({
          where: { id: sandbox.id },
          select: { state: true },
        })
      ).state,
    ).not.toBe("READY");
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
    expect(
      await db.inspect.credentialResidue.findFirstOrThrow({
        where: { leaseId: lease.id },
        select: { recoverable: true },
      }),
    ).toEqual({ recoverable: false });
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: f.instance.id },
        select: { activeLeases: true },
      }),
    ).toEqual({ activeLeases: 0 });
  });

  it("a replayed READY receipt repeating a lost credential.installed activates the lease and publishes READY; the receipt is not stored", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    await dispatch(f, sandbox.id);
    const lease = await leaseOf(sandbox.id);
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: 1,
      requestId: "req-1",
      sandboxId: sandbox.id,
      leaseId: lease.id,
      operationId: operation.id,
    });
    if (granted.kind !== "granted") throw new Error("unreachable");
    granted.bytes.fill(0);
    // The host installed the login, but its `credential.installed` frame was
    // lost with the socket; the journaled receipt replays on a new connection.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { connectionEpoch: 2 },
    });
    const ready = await readyResult(f, sandbox.id, operation.id);
    const report = {
      leaseId: lease.id,
      bindingId: granted.bindingId,
      storageSeq: 1,
      fileCount: 2,
      envCount: 0,
    };
    expect(
      await applyOperationResult({
        ...ready,
        sender: { ...ready.sender, connectionEpoch: 2 },
        result: { ...ready.result, credentialInstalled: [report] },
      }),
    ).toMatchObject({ written: true });
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: operation.id },
      select: { state: true, errorCode: true, result: true },
    });
    expect(op).toMatchObject({ state: "SUCCEEDED", errorCode: null });
    expect(JSON.stringify(op.result)).not.toContain("credentialInstalled");
    expect(
      (
        await db.inspect.sandbox.findUniqueOrThrow({
          where: { id: sandbox.id },
          select: { state: true },
        })
      ).state,
    ).toBe("READY");
    expect((await leaseOf(sandbox.id)).state).toBe("ACTIVE");
  });

  it("a READY receipt whose install report does not match the lease's binding and granted sequence is still an install failure", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    await dispatch(f, sandbox.id);
    const lease = await leaseOf(sandbox.id);
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: 1,
      requestId: "req-1",
      sandboxId: sandbox.id,
      leaseId: lease.id,
      operationId: operation.id,
    });
    if (granted.kind !== "granted") throw new Error("unreachable");
    granted.bytes.fill(0);
    const ready = await readyResult(f, sandbox.id, operation.id);
    await applyOperationResult({
      ...ready,
      result: {
        ...ready.result,
        credentialInstalled: [
          {
            leaseId: lease.id,
            bindingId: granted.bindingId,
            storageSeq: 7,
            fileCount: 2,
            envCount: 0,
          },
        ],
      },
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { state: true, errorCode: true },
      }),
    ).toEqual({ state: "FAILED", errorCode: "credential_install_failed" });
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
  });

  it("an install receipt applied directly activates only a matching INSTALLING lease of its own sandbox and host", async () => {
    const f = await fixture();
    const b = await installing(f);
    // Sandbox A: another sandbox on the same host (no login of its own).
    const a = await createSandbox(f.actor, {
      template: `revision/${f.template.id}`,
      sandboxHostId: f.host.id,
      idempotencyKey: `create-${randomUUID()}`,
    });
    const other = await fixture();
    const report = {
      leaseId: b.lease.id,
      bindingId: b.bindingId,
      storageSeq: 1,
      fileCount: 2,
      envCount: 0,
    };
    const apply = (hostId: string, sandboxId: string, result: Record<string, unknown>) =>
      db.inspect.$transaction((tx) => applyInstalledReceipt(tx, { hostId, sandboxId, result }));
    // Sandbox A's receipt naming sandbox B's lease, a foreign host, a stale
    // binding and a stale sequence apply nothing.
    expect(await apply(f.host.id, a.id, { credentialInstalled: [report] })).toBe(0);
    expect(await apply(other.host.id, b.sandbox.id, { credentialInstalled: [report] })).toBe(0);
    expect(
      await apply(f.host.id, b.sandbox.id, {
        credentialInstalled: [{ ...report, bindingId: `binding-${randomUUID()}` }],
      }),
    ).toBe(0);
    expect(
      await apply(f.host.id, b.sandbox.id, {
        credentialInstalled: [{ ...report, storageSeq: 2 }],
      }),
    ).toBe(0);
    // Malformed receipts (extra field, wrong shape, duplicate lease) apply nothing.
    for (const malformed of [
      [{ ...report, value: "x" }],
      { ...report },
      [report, report],
      [{ ...report, storageSeq: -1 }],
    ])
      expect(await apply(f.host.id, b.sandbox.id, { credentialInstalled: malformed })).toBe(0);
    expect((await leaseOf(b.sandbox.id)).state).toBe("INSTALLING");
    // The matching receipt applies once; a repeat is a no-op.
    expect(await apply(f.host.id, b.sandbox.id, { credentialInstalled: [report] })).toBe(1);
    const active = await leaseOf(b.sandbox.id);
    expect(active.state).toBe("ACTIVE");
    expect(await apply(f.host.id, b.sandbox.id, { credentialInstalled: [report] })).toBe(0);
    expect((await leaseOf(b.sandbox.id)).updatedAt).toEqual(active.updatedAt);
  });

  it("an install receipt never reactivates a closed binding nor a lease awaiting recovery", async () => {
    const apply = (f: Fixture, sandboxId: string, report: Record<string, unknown>) =>
      db.inspect.$transaction((tx) =>
        applyInstalledReceipt(tx, {
          hostId: f.host.id,
          sandboxId,
          result: { credentialInstalled: [report] },
        }),
      );
    // A matching report against the lease's current binding once it is closed.
    const f = await fixture();
    const closed = await installing(f);
    const closedAt = new Date();
    await db.inspect.credentialBinding.update({
      where: { id: closed.bindingId },
      data: { closedAt },
    });
    const report = (lease: { id: string }, bindingId: string) => ({
      leaseId: lease.id,
      bindingId,
      storageSeq: 1,
      fileCount: 2,
      envCount: 0,
    });
    expect(await apply(f, closed.sandbox.id, report(closed.lease, closed.bindingId))).toBe(0);
    expect((await leaseOf(closed.sandbox.id)).state).toBe("INSTALLING");
    // A matching report against a lease awaiting recovery (its binding open).
    const g = await fixture();
    const recovering = await installing(g);
    await db.inspect.credentialLease.update({
      where: { id: recovering.lease.id },
      data: { state: "RECOVERY_REQUIRED", endReason: "capture_failed" },
    });
    expect(
      await apply(g, recovering.sandbox.id, report(recovering.lease, recovering.bindingId)),
    ).toBe(0);
    expect(await leaseOf(recovering.sandbox.id)).toMatchObject({
      state: "RECOVERY_REQUIRED",
      endReason: "capture_failed",
      releasedAt: null,
    });
    expect(
      (
        await db.inspect.credentialBinding.findUniqueOrThrow({
          where: { id: recovering.bindingId },
          select: { closedAt: true },
        })
      ).closedAt,
    ).toBeNull();
  });

  it.each(["frame first", "receipt first"] as const)(
    "the installed frame and a READY receipt racing (%s) serialize on the sandbox lock: both finish, one ACTIVE transition",
    async (order) => {
      const f = await fixture();
      const { sandbox, operation, lease, bindingId } = await installing(f);
      const ready = await readyResult(f, sandbox.id, operation.id);
      const report = { leaseId: lease.id, bindingId, storageSeq: 1, fileCount: 2, envCount: 0 };
      let release!: () => void;
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      let locked!: () => void;
      const isLocked = new Promise<void>((resolve) => {
        locked = resolve;
      });
      // Another transaction holds the sandbox row both paths lock.
      let holderPid = 0;
      const holder = db.inspect.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
          const [me] = await tx.$queryRaw<{ pid: number }[]>`SELECT pg_backend_pid() AS pid`;
          holderPid = me?.pid ?? 0;
          locked();
          await released;
        },
        { timeout: 20_000 },
      );
      holder.catch(() => {});
      // Backends blocked by the holder, directly or behind another waiter (the
      // second path queues on a lock the first took), not any lock wait.
      const waiting = async (n: number) => {
        for (let i = 0; i < 200; i++) {
          const [row] = await db.inspect.$queryRaw<{ n: bigint }[]>`WITH RECURSIVE blocked(pid) AS (
            SELECT pid FROM pg_stat_activity WHERE ${holderPid}::int = ANY(pg_blocking_pids(pid))
            UNION
            SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid = ANY(pg_blocking_pids(a.pid))
          ) SELECT count(*) AS n FROM blocked`;
          if (Number(row?.n ?? 0) >= n) return;
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        throw new Error(`fewer than ${n} backends blocked by the holder`);
      };
      const settled: string[] = [];
      const frame = () =>
        recordInstalled({
          hostId: f.host.id,
          connectionEpoch: 1,
          leaseId: lease.id,
          bindingId,
          storageSeq: 1,
        }).then((applied) => {
          settled.push("frame");
          return applied;
        });
      const result = () =>
        applyOperationResult({
          ...ready,
          result: { ...ready.result, credentialInstalled: [report] },
        }).then((outcome) => {
          settled.push("result");
          return outcome;
        });
      let framePromise: Promise<boolean> | undefined;
      let resultPromise: Promise<unknown> | undefined;
      const startFrame = () => {
        framePromise = frame();
        framePromise.catch(() => {});
      };
      const startResult = () => {
        resultPromise = result();
        resultPromise.catch(() => {});
      };
      let handshake: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          isLocked,
          new Promise((_, reject) => {
            handshake = setTimeout(() => reject(new Error("no row lock")), 5_000);
          }),
        ]);
        if (order === "frame first") {
          startFrame();
          await waiting(1);
          startResult();
        } else {
          startResult();
          await waiting(1);
          startFrame();
        }
        await waiting(2);
        // Both wait on the held lock; neither has finished.
        expect(settled).toEqual([]);
      } finally {
        // Even on a failed handshake or assertion: end the holder and every
        // started path, so nothing outlives this test.
        clearTimeout(handshake);
        release();
        await Promise.allSettled([holder, framePromise, resultPromise]);
      }
      const [applied, outcome] = await Promise.all([framePromise, resultPromise]);
      expect(outcome).toMatchObject({ written: true });
      // Whoever queued first activated the lease; the other found it ACTIVE.
      expect(applied).toBe(order === "frame first");
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({
          where: { id: operation.id },
          select: { state: true, errorCode: true },
        }),
      ).toEqual({ state: "SUCCEEDED", errorCode: null });
      expect((await leaseOf(sandbox.id)).state).toBe("ACTIVE");
    },
  );

  it("a malformed READY receipt is ignored: the result is still applied and ends as an install failure", async () => {
    const f = await fixture();
    const { sandbox, operation, lease, bindingId } = await installing(f);
    const ready = await readyResult(f, sandbox.id, operation.id);
    expect(
      await applyOperationResult({
        ...ready,
        result: {
          ...ready.result,
          credentialInstalled: [
            { leaseId: lease.id, bindingId, storageSeq: 1, fileCount: 2, envCount: 0, extra: 1 },
          ],
        },
      }),
    ).toMatchObject({ written: true });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { state: true, errorCode: true },
      }),
    ).toEqual({ state: "FAILED", errorCode: "credential_install_failed" });
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
  });

  it("a receipt replayed after the install failure was settled changes nothing: the lease stays RELEASED install_failed", async () => {
    const f = await fixture();
    const { sandbox, operation, lease, bindingId } = await installing(f);
    const ready = await readyResult(f, sandbox.id, operation.id);
    await applyOperationResult(ready);
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
    const report = { leaseId: lease.id, bindingId, storageSeq: 1, fileCount: 2, envCount: 0 };
    await applyOperationResult({
      ...ready,
      result: { ...ready.result, credentialInstalled: [report] },
    }).catch(() => undefined);
    expect(
      await db.inspect.$transaction((tx) =>
        applyInstalledReceipt(tx, {
          hostId: f.host.id,
          sandboxId: sandbox.id,
          result: { credentialInstalled: [report] },
        }),
      ),
    ).toBe(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { state: true, errorCode: true },
      }),
    ).toEqual({ state: "FAILED", errorCode: "credential_install_failed" });
    expect(await leaseOf(sandbox.id)).toMatchObject({
      state: "RELEASED",
      endReason: "install_failed",
    });
  });

  it("the frame applied first and the same receipt in the READY result: one ACTIVE transition, READY published", async () => {
    const f = await fixture();
    const { sandbox, operation, lease, bindingId } = await installing(f);
    const report = { leaseId: lease.id, bindingId, storageSeq: 1, fileCount: 2, envCount: 0 };
    expect(
      await recordInstalled({
        hostId: f.host.id,
        connectionEpoch: 1,
        leaseId: lease.id,
        bindingId,
        storageSeq: 1,
      }),
    ).toBe(true);
    const active = await leaseOf(sandbox.id);
    const ready = await readyResult(f, sandbox.id, operation.id);
    expect(
      await applyOperationResult({
        ...ready,
        result: { ...ready.result, credentialInstalled: [report] },
      }),
    ).toMatchObject({ written: true });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { state: true },
      }),
    ).toEqual({ state: "SUCCEEDED" });
    const after = await leaseOf(sandbox.id);
    expect(after.state).toBe("ACTIVE");
    expect(after.updatedAt).toEqual(active.updatedAt);
  });

  it("a create the dispatch refuses server-side (never sent) abandons its RESERVED lease in that transaction", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    expect(await leaseOf(sandbox.id)).toMatchObject({ state: "RESERVED" });
    // The host stopped advertising egress enforcement: the launch is refused at dispatch.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { egressEnforcement: false },
    });
    await dispatch(f, sandbox.id);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { state: true },
      }),
    ).toEqual({ state: "FAILED" });
    expect(await leaseOf(sandbox.id)).toMatchObject({ state: "ABANDONED" });
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: f.instance.id },
        select: { activeLeases: true },
      }),
    ).toEqual({ activeLeases: 0 });
    expect(
      await db.inspect.credentialOperationSpec.count({ where: { operationId: operation.id } }),
    ).toBe(0);
  });

  it("a FAILED create (spec invalid, nothing installed) abandons its RESERVED lease", async () => {
    const f = await fixture();
    const { sandbox, operation } = await create(f);
    await dispatch(f, sandbox.id);
    const base = await readyResult(f, sandbox.id, operation.id);
    await applyOperationResult({
      ...base,
      state: "failed",
      result: undefined,
      error: { code: "credential_spec_invalid", message: "spec" },
    });
    expect(await leaseOf(sandbox.id)).toMatchObject({ state: "ABANDONED" });
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: f.instance.id },
        select: { activeLeases: true },
      }),
    ).toEqual({ activeLeases: 0 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operation.id },
        select: { errorCode: true },
      }),
    ).toEqual({ errorCode: "credential_spec_invalid" });
  });
});
