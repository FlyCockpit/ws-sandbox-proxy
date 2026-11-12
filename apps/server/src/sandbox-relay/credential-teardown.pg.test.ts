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
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
// Test-only: the server package does not depend on the definition package.
import {
  encodeBundle,
  fromHex,
  parseLoginDefinition,
} from "../../../../packages/login-definition/src/index";

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
 * C8b-server teardown settlement against real PostgreSQL. Each sandbox runs
 * the real create → grant → installed → READY path first.
 */
const db = await pgTestDatabase();
const { createSandbox, killSandbox, readFile, reconnectSandbox, stopSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const service = await import("@wssp/api/credentials/service");
const {
  applyCompleteCensus,
  accumulateCensusPage,
  commitCapture,
  grantInstallBundle,
  issueCurrentReturnKey,
  newCensusAccumulator,
  recordInstalled,
  settleTerminalTeardown,
} = await import("@wssp/api/credentials/relay");
const { sealToReturnKey } = await import(
  "../../../../packages/api/src/credentials/vault/sealed-box"
);
const { buildEnvelope } = await import("../../../../packages/api/src/credentials/vault/envelope");
const { leaseWireSchema } = await import("@wssp/api/sandbox/lease-wire");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { applyOperationResult } = await import("./operation-handlers.js");
const { InventoryCensus } = await import("./inventory-reconcile.js");
const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
const { settleCredentialsOnHostLost, settleCredentialTeardown } = await import(
  "../../../../packages/api/src/credentials/teardown"
);
const { captureSandbox } = await import(
  "../../../../packages/api/src/sandbox/image-store/captures"
);
const { parseCredentialSpec } = await import("@wssp/sandbox-contracts");
const { attachSandboxCredential, freeSandboxCredential } = await import(
  "@wssp/api/credentials/live"
);
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

const ORIGIN = "https://wssp.example.test";
const FP = `sha256:${"c".repeat(64)}`;
const clock = () => new Date();
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
type Rotates = "yes" | "no" | "unknown";
const document = (
  slug: string,
  dir = ".config/tool",
  rotates?: Rotates,
  sharing: "exclusive" | "shareable" = "exclusive",
) => ({
  schemaVersion: 1,
  id: slug,
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: {
    files: { required: [dir], optional: [], exclude: [] },
    sharing,
    ...(rotates ? { rotates } : {}),
  },
});

async function loginFor(
  actor: { kind: "session"; ownerId: string },
  instances = 1,
  dir = ".config/tool",
  rotates?: Rotates,
  /** > 1: a shareable login whose instances take this many leases. */
  capacity = 1,
) {
  const slug = `tool-${randomUUID().slice(0, 8)}`;
  const sharing = capacity > 1 ? "shareable" : "exclusive";
  const definition = await service.createDefinition(actor, {
    document: document(slug, dir, rotates, sharing),
  });
  const login = await service.createLogin(actor, { name: slug, definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id });
  const ids: string[] = [];
  for (let n = 0; n < instances; n += 1) {
    const instance = await service.createInstance(actor, {
      credentialId: login.id,
      accountId: account.id,
      ...(capacity > 1 ? { maxConcurrent: capacity } : {}),
    });
    await service.writeValue(actor, {
      credentialId: login.id,
      instanceId: instance.id,
      files: [
        { path: dir, kind: "dir" },
        { path: `${dir}/token`, contentBase64: Buffer.from("token-v1").toString("base64") },
      ],
    });
    ids.push(instance.id);
  }
  const { definitionDigest } = await db.inspect.credential.findUniqueOrThrow({
    where: { id: login.id },
    select: { definitionDigest: true },
  });
  const parsed = parseLoginDefinition(document(slug, dir, rotates, sharing));
  if (!parsed.success) throw new Error("bad fixture definition");
  return {
    dir,
    id: login.id,
    accountId: account.id,
    instances: ids,
    digest: definitionDigest,
    definition: parsed.definition,
  };
}
type Login = Awaited<ReturnType<typeof loginFor>>;

async function fixture(
  options: { logins?: number; instances?: number; proxy?: boolean; rotates?: Rotates } = {},
) {
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
        credentials: { ...CREDENTIAL_CAPABILITY, proxy: options.proxy ?? false },
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
  const logins: Login[] = [];
  // The logins of one sandbox are path-disjoint (the claim gate refuses an
  // overlapping set): the first keeps `.config/tool`, the others get their own.
  for (let n = 0; n < (options.logins ?? 1); n += 1)
    logins.push(
      await loginFor(
        actor,
        options.instances ?? 1,
        n === 0 ? ".config/tool" : `.config/tool-${n}`,
        options.rotates,
      ),
    );
  const frame = await issueCurrentReturnKey({
    hostId: host.id,
    hostSlotEpoch: 0,
    serverOrigin: ORIGIN,
  });
  if (!frame) throw new Error("no return key");
  const key = { kidR: frame.kidR, publicKey: Buffer.from(frame.publicKey, "base64url") };
  return { ownerId, actor, host, template, logins, key, epoch: 1 };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

async function dispatch(f: Fixture) {
  relay.dispatchOperation.mockReset();
  relay.dispatchOperation.mockResolvedValue("sent");
  await db.inspect.sandboxExecutionConfig.updateMany({
    where: { userId: f.ownerId },
    data: { acknowledgedEpoch: f.epoch, acknowledgedAt: new Date() },
  });
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  await processSandboxOutboxBatch(clock);
}

async function report(
  f: Fixture,
  operationId: string,
  state: "succeeded" | "failed" | "unknown_outcome",
  result?: Record<string, unknown>,
  errorCode?: string,
) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.ownerId, payload: { path: ["operationId"], equals: operationId } },
  });
  const lease = leaseWireSchema.safeParse((event.payload as Record<string, unknown>).lease);
  return applyOperationResult(
    {
      sender: { userId: f.ownerId, hostId: f.host.id, connectionEpoch: f.epoch },
      operationId,
      sandboxId: op.sandboxId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state,
      ...(result ? { result: { ...result, ...(lease.success ? { lease: lease.data } : {}) } } : {}),
      ...(errorCode ? { error: { code: errorCode as never, message: errorCode } } : {}),
    },
    clock,
  );
}

type Held = { leaseId: string; bindingId: string; login: Login; instanceId: string };

/** create → grant → installed → READY for every login (first instance of each). */
async function readySandbox(f: Fixture) {
  const sandbox = await createSandbox(f.actor, {
    template: `revision/${f.template.id}`,
    sandboxHostId: f.host.id,
    idempotencyKey: `create-${randomUUID()}`,
    credentials: f.logins.map((l) => ({ credentialId: l.id, instanceId: l.instances[0]! })),
  });
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  await dispatch(f);
  const held: Held[] = [];
  for (const login of f.logins) {
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId: sandbox.id, credentialId: login.id },
    });
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId: sandbox.id,
      leaseId: lease.id,
      operationId: create.id,
    });
    if (granted.kind !== "granted") throw new Error(`grant refused: ${JSON.stringify(granted)}`);
    granted.bytes.fill(0);
    await recordInstalled({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      leaseId: lease.id,
      bindingId: granted.bindingId,
      storageSeq: granted.storageSeq,
    });
    held.push({
      leaseId: lease.id,
      bindingId: granted.bindingId,
      login,
      instanceId: lease.instanceId,
    });
  }
  expect(await report(f, create.id, "succeeded", { state: "ready" })).toMatchObject({
    written: true,
  });
  expect((await sandboxRow(sandbox.id)).state).toBe("READY");
  return { sandboxId: sandbox.id, held };
}

async function capture(
  f: Fixture,
  sandboxId: string,
  h: Held,
  o: { captureSeq: number; token: string; kind?: "stop" | "kill" | "free"; tamper?: boolean },
) {
  const captureId = `cap-${randomUUID().slice(0, 12)}`;
  const kind = o.kind ?? "stop";
  const aad = {
    serverOrigin: ORIGIN,
    hostOwnerId: f.ownerId,
    hostId: f.host.id,
    sandboxOwnerId: f.ownerId,
    sandboxId,
    leaseId: h.leaseId,
    bindingId: h.bindingId,
    instanceId: h.instanceId,
    credentialId: h.login.id,
    captureSeq: String(o.captureSeq),
    captureId,
    kind,
    residueId: "",
  } as Parameters<typeof sealToReturnKey>[2];
  const plaintext = encodeBundle(
    {
      definitionDigest: fromHex(h.login.digest),
      files: [
        { kind: "dir", path: h.login.dir, mode: 0o700 },
        { kind: "file", path: `${h.login.dir}/token`, mode: 0o600, data: Buffer.from(o.token) },
      ],
      env: [],
    },
    h.login.definition,
  );
  const seal = sealToReturnKey(plaintext, f.key.publicKey, aad);
  if (o.tamper) seal[seal.length - 1] = (seal[seal.length - 1] ?? 0) ^ 1;
  const envelope = buildEnvelope(
    {
      kidR: f.key.kidR,
      recipientPubSha256: createHash("sha256").update(f.key.publicKey).digest("hex"),
      aad,
      sealedLen: seal.byteLength,
      sealedSha256: createHash("sha256").update(seal).digest("hex"),
      createdAt: 1,
    },
    seal,
  );
  const ack = await commitCapture({
    hostId: f.host.id,
    connectionEpoch: f.epoch,
    serverOrigin: ORIGIN,
    captureId,
    leaseId: h.leaseId,
    bindingId: h.bindingId,
    kidR: f.key.kidR,
    kind,
    envelopeDigest: createHash("sha256").update(envelope).digest("hex"),
    envelope,
  });
  return { captureId, ack };
}

const sandboxRow = (id: string) =>
  db.inspect.sandbox.findUniqueOrThrow({
    where: { id },
    select: { state: true, generation: true, liveResourcesHeld: true },
  });
const leaseRow = (id: string) =>
  db.inspect.credentialLease.findUniqueOrThrow({
    where: { id },
    select: { state: true, endReason: true, teardownOperationId: true, baseSeq: true },
  });
const instanceRow = (id: string) =>
  db.inspect.credentialInstance.findUniqueOrThrow({
    where: { id },
    select: { activeLeases: true, currentSeq: true, state: true, needsLoginReason: true },
  });
const residueOf = (bindingId: string) =>
  db.inspect.credentialResidue.findUniqueOrThrow({
    where: { bindingId },
    select: { clearedAt: true, clearReason: true, recoverable: true },
  });
const latestOp = (sandboxId: string, kind: "STOP_SANDBOX" | "KILL_SANDBOX") =>
  db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId, kind },
    orderBy: { generation: "desc" },
  });
const acked = (h: Held, captureId: string, outcome: string, scrub = "verified") => ({
  leaseId: h.leaseId,
  bindingId: h.bindingId,
  capture: { status: "acked", captureId, outcome },
  scrub,
});

async function credentialCensus(f: Fixture, pending: { h: Held; captureId: string }[] = []) {
  const acc = newCensusAccumulator();
  accumulateCensusPage(acc, {
    type: "credential.census",
    page: 0,
    complete: true,
    keyEpoch: 1,
    quarantined: [],
    entries: [],
  });
  for (const p of pending)
    acc.pending.set(p.captureId, {
      leaseId: p.h.leaseId,
      bindingId: p.h.bindingId,
      kidR: f.key.kidR,
      kind: "stop",
    });
  return applyCompleteCensus({ hostId: f.host.id, connectionEpoch: f.epoch, census: acc });
}

/** A host outage: the host reconnects under a new epoch. */
async function reconnectHost(f: Fixture) {
  const host = await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: { increment: 1 }, journalKeyAcknowledgedEpoch: { increment: 1 } },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.host.id },
    data: { connectionEpoch: host.connectionEpoch, reportedAt: new Date() },
  });
  f.epoch = host.connectionEpoch;
}

async function inventory(f: Fixture, sandboxId: string, state: "stopped" | "absent") {
  const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  const accepted = await new InventoryCensus(
    { userId: f.ownerId, hostId: f.host.id, connectionEpoch: f.epoch },
    clock,
  ).acceptPage({
    type: "sandbox.inventory",
    page: 0,
    complete: true,
    entries: [
      {
        sandboxId,
        sandboxOwnerId: f.ownerId,
        state,
        root:
          s.storagePoolName && s.storageMarker
            ? {
                storagePoolName: s.storagePoolName,
                storageMarker: s.storageMarker,
                diskGiB: s.diskGiB,
                state: state === "absent" ? "absent" : "present",
                networkCleanupComplete: state === "absent",
                observationSequence: 100,
              }
            : undefined,
      },
    ] as never,
  });
  expect(accepted).toEqual({ ok: true });
}

describe("C8b-server teardown settlement (pg)", () => {
  it("11: a stop at N+1 commits the capture of the binding granted at N; STOPPED releases the lease", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    expect(stop).toMatchObject({ generation: 2, teardownPriorState: "READY" });
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "RELEASING",
      teardownOperationId: stop.id,
    });
    const binding = await db.inspect.credentialBinding.findUniqueOrThrow({
      where: { id: a.bindingId },
    });
    expect(binding).toMatchObject({ grantGeneration: 1, closedAt: null });
    await dispatch(f);
    // A user stop: no system origin on the dispatch.
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.not.objectContaining({ credentialTeardown: expect.anything() }),
    );
    const { captureId, ack } = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    expect(ack).toEqual({ outcome: "committed" });
    // Still RELEASING: the sandbox has not stopped yet.
    expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, captureId, "committed")],
    });
    expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
    expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RELEASED", endReason: "captured" });
    expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 0, currentSeq: 2 });
    expect(await residueOf(a.bindingId)).toMatchObject({ clearReason: "scrubbed" });
    // The receipt is never stored on the public operation.
    const stored = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: stop.id } });
    expect(JSON.stringify(stored.result)).not.toContain("credentialOutcomes");
  });

  it("11b: a durable envelope keeps the lease RELEASING across STOPPED until its commit releases it", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [
        {
          leaseId: a.leaseId,
          bindingId: a.bindingId,
          capture: { status: "durable", captureId: "cap-offline" },
          scrub: "verified",
        },
      ],
    });
    expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
    expect(await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })).toMatchObject({
      ack: { outcome: "committed" },
    });
    expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RELEASED", endReason: "captured" });
    expect((await instanceRow(a.instanceId)).activeLeases).toBe(0);
  });

  it("13: a kill supersedes a stop; the in-flight stop capture commits and the kill result releases the lease", async () => {
    for (const order of ["commit-first", "result-first"] as const) {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      await dispatch(f);
      const stop = await latestOp(sandboxId, "STOP_SANDBOX");
      await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
      const kill = await latestOp(sandboxId, "KILL_SANDBOX");
      expect(kill).toMatchObject({ generation: 3, teardownPriorState: "READY" });
      expect(await leaseRow(a.leaseId)).toMatchObject({
        state: "RELEASING",
        teardownOperationId: kill.id,
      });
      expect(
        (await db.inspect.credentialBinding.findUniqueOrThrow({ where: { id: a.bindingId } }))
          .closedAt,
      ).toBeNull();
      expect(
        (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: stop.id } })).state,
      ).toBe("CANCEL_REQUESTED");
      await dispatch(f);
      if (order === "commit-first") {
        const { captureId, ack } = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
        expect(ack).toEqual({ outcome: "committed" });
        await report(f, kill.id, "succeeded", {
          state: "deleted",
          credentialOutcomes: [acked(a, captureId, "committed", "not_run")],
        });
      } else {
        await report(f, kill.id, "succeeded", {
          state: "deleted",
          credentialOutcomes: [
            {
              leaseId: a.leaseId,
              bindingId: a.bindingId,
              capture: { status: "durable", captureId: "cap-joined" },
              scrub: "not_run",
            },
          ],
        });
        expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
        expect((await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })).ack).toEqual({
          outcome: "committed",
        });
      }
      expect((await sandboxRow(sandboxId)).state).toBe("DELETED");
      expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RELEASED", endReason: "captured" });
      expect(await instanceRow(a.instanceId)).toMatchObject({
        activeLeases: 0,
        currentSeq: 2,
        state: "READY",
      });
      expect(await residueOf(a.bindingId)).toMatchObject({ clearReason: "deleted" });
    }
  });

  it("27: a failed kill from ERROR / UNREACHABLE stays ERROR, from RECOVERED returns READY, leases ACTIVE; no owned lease never takes the READY branch", async () => {
    for (const [origin, expected] of [
      ["ERROR", "ERROR"],
      ["UNREACHABLE", "ERROR"],
      ["RECOVERED", "READY"],
      ["READY", "READY"],
    ] as const) {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await db.inspect.sandbox.update({ where: { id: sandboxId }, data: { state: origin } });
      await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
      const kill = await latestOp(sandboxId, "KILL_SANDBOX");
      expect(kill.teardownPriorState).toBe(origin);
      await dispatch(f);
      await report(f, kill.id, "failed", undefined, "credential_capture_failed");
      expect(await sandboxRow(sandboxId)).toMatchObject({
        state: expected,
        generation: 2,
        liveResourcesHeld: true,
      });
      expect(await leaseRow(a.leaseId)).toMatchObject({
        state: "ACTIVE",
        teardownOperationId: null,
      });
    }
    // A kill that skipped capture owns no RELEASING lease: ordinary FAILED → ERROR.
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    await killSandbox(f.actor, {
      id: sandboxId,
      idempotencyKey: `kill-${randomUUID()}`,
      credentialCapture: "skip",
    });
    expect(await leaseRow(held[0]!.leaseId)).toMatchObject({
      state: "RELEASED",
      endReason: "skipped",
    });
    await dispatch(f);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({ kind: "sandbox.kill", credentialCapture: "skip" }),
    );
    const kill = await latestOp(sandboxId, "KILL_SANDBOX");
    await report(f, kill.id, "failed", undefined, "credential_capture_failed");
    expect((await sandboxRow(sandboxId)).state).toBe("ERROR");
  });

  it("29: failed-stop re-arm — A commits, B REJECTED → READY at N+1 with both ACTIVE; the next stop commits A's rotation; A's older envelope is DISCARDED", async () => {
    const f = await fixture({ logins: 2 });
    const { sandboxId, held } = await readySandbox(f);
    const [a, b] = held as [Held, Held];
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const a1 = await capture(f, sandboxId, a, { captureSeq: 1, token: "a-v2" });
    expect(a1.ack).toEqual({ outcome: "committed" });
    // A second, older-in-seq envelope of A sealed in the same failed attempt.
    const b1 = await capture(f, sandboxId, b, { captureSeq: 1, token: "b-v2", tamper: true });
    expect(b1.ack).toMatchObject({ outcome: "rejected" });
    // The user stop keeps the VM running: B stays RELEASING, no recovery.
    expect((await leaseRow(b.leaseId)).state).toBe("RELEASING");
    await report(
      f,
      stop.id,
      "failed",
      {
        credentialOutcomes: [
          acked(a, a1.captureId, "committed", "not_run"),
          acked(b, b1.captureId, "rejected", "not_run"),
        ],
      },
      "credential_capture_failed",
    );
    expect(await sandboxRow(sandboxId)).toMatchObject({ state: "READY", generation: 2 });
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "ACTIVE",
      baseSeq: 2,
      teardownOperationId: null,
    });
    expect((await leaseRow(b.leaseId)).state).toBe("ACTIVE");
    expect((await residueOf(a.bindingId)).clearedAt).toBeNull();
    // Each re-armed lease records `capture_failed` (credential.capture_failed webhook).
    for (const lease of [a, b])
      expect(
        await db.inspect.credentialEvent.count({
          where: { leaseId: lease.leaseId, type: "capture_failed" },
        }),
      ).toBe(1);

    // Guest work resumes at N+1.
    await readFile(f.actor, {
      id: sandboxId,
      idempotencyKey: `read-${randomUUID()}`,
      path: "/home/user/notes.txt",
    });
    const work = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "GET_FILE" },
    });
    expect(work.generation).toBe(2);
    await dispatch(f);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({ operationId: work.id, generation: 2 }),
    );

    // A rotates again; the second stop opens a new attempt and commits it.
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop2 = await latestOp(sandboxId, "STOP_SANDBOX");
    expect(stop2.generation).toBe(3);
    await dispatch(f);
    const a2 = await capture(f, sandboxId, a, { captureSeq: 2, token: "a-v3" });
    expect(a2.ack).toEqual({ outcome: "committed" });
    expect(await instanceRow(a.instanceId)).toMatchObject({ currentSeq: 3 });
    // An older envelope of A from the failed attempt arriving last.
    const late = await capture(f, sandboxId, a, { captureSeq: 1, token: "a-stale" });
    expect(late.ack).toEqual({ outcome: "discarded", reason: "superseded" });
    expect(await instanceRow(a.instanceId)).toMatchObject({ currentSeq: 3 });
    const b2 = await capture(f, sandboxId, b, { captureSeq: 2, token: "b-v3" });
    expect(b2.ack).toEqual({ outcome: "committed" });
    await report(f, stop2.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [
        acked(a, a2.captureId, "committed"),
        acked(b, b2.captureId, "committed"),
      ],
    });
    expect((await leaseRow(a.leaseId)).state).toBe("RELEASED");
    expect((await leaseRow(b.leaseId)).state).toBe("RELEASED");
  });

  it("29b: without a receipt, a commit made during the failed attempt never resolves the next teardown", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    expect((await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })).ack).toEqual({
      outcome: "committed",
    });
    await report(f, stop.id, "failed", undefined, "credential_capture_failed");
    expect((await leaseRow(a.leaseId)).state).toBe("ACTIVE");
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop2 = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    // STOPPED with no outcome for A: the earlier commit does not count.
    await report(f, stop2.id, "succeeded", { state: "stopped" });
    expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
    // Census with nothing pending settles it RECOVERY_REQUIRED.
    await credentialCensus(f);
    expect((await leaseRow(a.leaseId)).state).toBe("RECOVERY_REQUIRED");
  });

  it("30: a non-credential stop failure → ERROR with leases RECOVERY_REQUIRED, or RELEASED when the capture resolved", async () => {
    for (const resolved of [false, true]) {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      const stop = await latestOp(sandboxId, "STOP_SANDBOX");
      await dispatch(f);
      const committed = resolved
        ? await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })
        : null;
      await report(f, stop.id, "failed", undefined, "guest_unavailable");
      // A held ERROR is retried by the system only once no login lease is
      // open (a resolved capture released it); otherwise it waits for the
      // owner's recovery and stays ERROR.
      expect((await sandboxRow(sandboxId)).state).toBe(resolved ? "STOPPING" : "ERROR");
      expect(await latestOp(sandboxId, "STOP_SANDBOX")).toMatchObject(
        resolved
          ? { state: "QUEUED", idempotencyKey: expect.stringMatching(/^teardown-retry:/) }
          : { id: stop.id, state: "FAILED" },
      );
      expect(await leaseRow(a.leaseId)).toMatchObject(
        resolved
          ? { state: "RELEASED", endReason: "captured" }
          : { state: "RECOVERY_REQUIRED", endReason: "teardown_failed" },
      );
      if (committed) expect(committed.ack).toEqual({ outcome: "committed" });
      expect(await residueOf(a.bindingId)).toMatchObject({
        clearedAt: null,
        recoverable: !resolved,
      });
    }
  });

  it("30b: a cancelled never-dispatched KILL → leases ACTIVE when the sandbox is READY, else RECOVERY_REQUIRED", async () => {
    for (const after of ["READY", "ERROR"] as const) {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
      const kill = await latestOp(sandboxId, "KILL_SANDBOX");
      expect(kill.dispatchAttempt).toBe(0);
      // What sharing-access.ts does for an undone access kill, inside one transaction.
      await db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
        await tx.sandboxOperation.update({ where: { id: kill.id }, data: { state: "CANCELLED" } });
        await tx.sandbox.update({ where: { id: sandboxId }, data: { state: after } });
        await settleTerminalTeardown(tx, { id: kill.id, sandboxId, dispatchAttempt: 0 });
      });
      expect((await leaseRow(a.leaseId)).state).toBe(
        after === "READY" ? "ACTIVE" : "RECOVERY_REQUIRED",
      );
    }
  });

  it("26: convergence settles RESERVED / INSTALLING / ACTIVE; census with an envelope → commit releases; without → RECOVERY_REQUIRED and resume reuses it", async () => {
    for (const envelope of [true, false]) {
      const f = await fixture({ instances: 3 });
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      const login = f.logins[0]!;
      const create = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "CREATE_SANDBOX" },
      });
      // Two more leases of the same login on other instances, as an attach would leave them.
      const extra = async (instanceId: string, state: "RESERVED" | "INSTALLING") => {
        const lease = await db.inspect.credentialLease.create({
          data: {
            userId: f.ownerId,
            credentialId: login.id,
            accountId: login.accountId,
            instanceId,
            sandboxId,
            operationId: create.id,
            kind: "WORKLOAD",
            exclusive: true,
            state,
            hostId: f.host.id,
            baseSeq: state === "INSTALLING" ? 1 : null,
          },
        });
        await db.inspect.credentialInstance.update({
          where: { id: instanceId },
          data: { activeLeases: { increment: 1 } },
        });
        if (state === "INSTALLING") {
          const binding = await db.inspect.credentialBinding.create({
            data: {
              leaseId: lease.id,
              instanceId,
              sandboxId,
              hostId: f.host.id,
              grantGeneration: 1,
              baseSeq: 1,
              purpose: "INSTALL",
            },
          });
          await db.inspect.credentialResidue.create({
            data: {
              sandboxId,
              userId: f.ownerId,
              credentialId: login.id,
              instanceId,
              leaseId: lease.id,
              bindingId: binding.id,
              grantGeneration: 1,
              paths: [".config/tool"],
              recoverable: true,
            },
          });
          await db.inspect.credentialLease.update({
            where: { id: lease.id },
            data: { currentBindingId: binding.id },
          });
          return { leaseId: lease.id, bindingId: binding.id };
        }
        return { leaseId: lease.id, bindingId: "" };
      };
      const reserved = await extra(login.instances[1]!, "RESERVED");
      const installing = await extra(login.instances[2]!, "INSTALLING");

      await reconnectHost(f);
      await inventory(f, sandboxId, "stopped");
      expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
      const converged = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "STOP_SANDBOX", state: "SUCCEEDED" },
      });
      expect(await leaseRow(reserved.leaseId)).toMatchObject({ state: "ABANDONED" });
      expect(await leaseRow(installing.leaseId)).toMatchObject({
        state: "RELEASED",
        endReason: "superseded",
      });
      expect((await residueOf(installing.bindingId)).recoverable).toBe(false);
      expect(await leaseRow(a.leaseId)).toMatchObject({
        state: "RELEASING",
        teardownOperationId: converged.id,
      });
      expect(await instanceRow(login.instances[1]!)).toMatchObject({ activeLeases: 0 });
      expect(await instanceRow(login.instances[2]!)).toMatchObject({ activeLeases: 0 });

      if (envelope) {
        const captureId = `cap-${randomUUID().slice(0, 12)}`;
        await credentialCensus(f, [{ h: a, captureId }]);
        expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
        expect((await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })).ack).toEqual({
          outcome: "committed",
        });
        expect(await leaseRow(a.leaseId)).toMatchObject({
          state: "RELEASED",
          endReason: "captured",
        });
        expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 0 });
      } else {
        await credentialCensus(f);
        expect((await leaseRow(a.leaseId)).state).toBe("RECOVERY_REQUIRED");
        expect((await residueOf(a.bindingId)).recoverable).toBe(true);
        // Resume rule 1 reuses the lease on its own instance (no credential.in_use).
        await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
        expect((await leaseRow(a.leaseId)).state).toBe("RECOVERING");
        expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 1 });
      }
    }
  });

  it("26b: DELETED via convergence (pending kill + absence) settles every lease, clears residue, keeps activeLeases consistent", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
    await reconnectHost(f);
    await inventory(f, sandboxId, "absent");
    expect((await sandboxRow(sandboxId)).state).toBe("DELETED");
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "RELEASED",
      endReason: "capture_lost",
    });
    // `rotates` defaults to unknown (≠ no): the previous value may be stale.
    expect(await instanceRow(a.instanceId)).toMatchObject({
      activeLeases: 0,
      state: "NEEDS_LOGIN",
      needsLoginReason: "capture_lost",
    });
    expect(await residueOf(a.bindingId)).toMatchObject({ clearReason: "deleted" });
    expect(
      await db.inspect.credentialEvent.count({
        where: { leaseId: a.leaseId, type: "capture_lost" },
      }),
    ).toBe(1);
    // The READY → NEEDS_LOGIN transition records `needs_login` (webhook N10).
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: a.leaseId, type: "needs_login" },
        select: { reason: true },
      }),
    ).toEqual([{ reason: "capture_lost" }]);
  });

  it("26c: capture lost for a `rotates: no` login keeps the instance READY (its value cannot go stale)", async () => {
    const f = await fixture({ rotates: "no" });
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
    await reconnectHost(f);
    await inventory(f, sandboxId, "absent");
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "RELEASED",
      endReason: "capture_lost",
    });
    expect(await instanceRow(a.instanceId)).toMatchObject({
      activeLeases: 0,
      state: "READY",
      needsLoginReason: null,
    });
    expect(
      await db.inspect.credentialEvent.count({
        where: { leaseId: a.leaseId, type: { in: ["capture_lost", "needs_login"] } },
      }),
    ).toBe(1);
  });

  it("system teardowns: an expiry stop never re-arms; a capture REJECTED after a kill destroyed the disk is lost", async () => {
    {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      const past = new Date(Date.now() - 60_000);
      await db.inspect.sandbox.update({
        where: { id: sandboxId },
        data: { leaseExpiresAt: past, leaseExpireAction: "STOP" },
      });
      expect(await reclaimExpiredSandboxLeases(clock)).toBe(1);
      const stop = await latestOp(sandboxId, "STOP_SANDBOX");
      expect(stop.idempotencyKey.startsWith("lease-expire:")).toBe(true);
      expect(await leaseRow(a.leaseId)).toMatchObject({
        state: "RELEASING",
        teardownOperationId: stop.id,
      });
      await dispatch(f);
      expect(relay.dispatchOperation).toHaveBeenCalledWith(
        f.host.id,
        expect.objectContaining({ kind: "sandbox.stop", credentialTeardown: "system" }),
      );
      await report(f, stop.id, "failed", undefined, "credential_capture_failed");
      expect((await sandboxRow(sandboxId)).state).toBe("ERROR");
      expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RECOVERY_REQUIRED" });
      expect((await residueOf(a.bindingId)).recoverable).toBe(true);
    }
    {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
      const kill = await latestOp(sandboxId, "KILL_SANDBOX");
      await dispatch(f);
      await report(f, kill.id, "succeeded", {
        state: "deleted",
        credentialOutcomes: [
          {
            leaseId: a.leaseId,
            bindingId: a.bindingId,
            capture: { status: "durable", captureId: "cap-late" },
            scrub: "not_run",
          },
        ],
      });
      expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
      const late = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2", tamper: true });
      expect(late.ack).toMatchObject({ outcome: "rejected" });
      expect(await leaseRow(a.leaseId)).toMatchObject({
        state: "RELEASED",
        endReason: "capture_lost",
      });
      expect(await instanceRow(a.instanceId)).toMatchObject({
        activeLeases: 0,
        state: "NEEDS_LOGIN",
        needsLoginReason: "capture_lost",
      });
    }
  });

  it("M8: a user kill of a STOPPED sandbox with recoverable residue is refused unless skip", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [
        {
          leaseId: a.leaseId,
          bindingId: a.bindingId,
          capture: { status: "failed", reason: "pack_failed" },
          scrub: "not_run",
        },
      ],
    });
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "RECOVERY_REQUIRED",
      endReason: "capture_failed",
    });
    await expect(
      killSandbox(f.actor, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` }),
    ).rejects.toSatisfy(
      (e) => (e as { data?: { code?: string } }).data?.code === "credential.recovery_required",
    );
    expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
    await killSandbox(f.actor, {
      id: sandboxId,
      idempotencyKey: `kill-${randomUUID()}`,
      credentialCapture: "skip",
    });
    expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RELEASED", endReason: "skipped" });
    expect((await instanceRow(a.instanceId)).activeLeases).toBe(0);
  });

  it("a cold reconnect the READY gate fails keeps its live hold: the VM is running", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const c = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, c.captureId, "committed")],
    });
    expect((await sandboxRow(sandboxId)).liveResourcesHeld).toBe(false);
    await credentialCensus(f);
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX" },
    });
    await dispatch(f);
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, state: "RESERVED" },
    });
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId,
      leaseId: lease.id,
      operationId: reconnect.id,
    });
    if (granted.kind === "granted") granted.bytes.fill(0);
    expect(granted.kind).toBe("granted");
    // Ready reported while the lease is still INSTALLING.
    await report(f, reconnect.id, "succeeded", { state: "ready" });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: reconnect.id },
        select: { state: true, errorCode: true },
      }),
    ).toEqual({ state: "FAILED", errorCode: "credential_install_failed" });
    expect(await sandboxRow(sandboxId)).toMatchObject({ state: "ERROR", liveResourcesHeld: true });
    expect((await leaseRow(lease.id)).state).toBe("RELEASED");
  });
});

describe("C8c: template capture vs logins, HOST_LOST, UNKNOWN cold reconnect (pg)", () => {
  /** The host can capture templates (stopped captures copy the root on any pool). */
  async function enableCapture(f: Fixture) {
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        imageCacheEpoch: host.connectionEpoch,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 0n,
        imageCacheForeignBytes: 0n,
        daemonFeatures: {
          ...(host.daemonFeatures as Record<string, unknown>),
          image: {
            fetch: true,
            serve: true,
            publish: true,
            capture: true,
            acceptForeign: false,
            leaseFromReady: true,
            captureStorageMarkers: [],
          },
        },
      },
    });
  }
  const captureOf = (f: Fixture, sandboxId: string) =>
    captureSandbox(f.actor, { id: sandboxId, idempotencyKey: `cap-${randomUUID()}` });
  const inProgress = (e: unknown) =>
    (e as { data?: { code?: string } }).data?.code === "credential.capture_in_progress";

  /** READY → user stop whose capture failed → STOPPED with a RECOVERY_REQUIRED lease. */
  async function stoppedWithResidue(f: Fixture) {
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [
        {
          leaseId: a.leaseId,
          bindingId: a.bindingId,
          capture: { status: "failed", reason: "pack_failed" },
          scrub: "not_run",
        },
      ],
    });
    expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
    expect((await leaseRow(a.leaseId)).state).toBe("RECOVERY_REQUIRED");
    return { sandboxId, a };
  }

  it("a capture carries the sandbox's login paths as a scrub-only spec through the chunked transfer", async () => {
    const f = await fixture();
    const { sandboxId, a } = await stoppedWithResidue(f);
    await enableCapture(f);
    const { operationId } = await captureOf(f, sandboxId);
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId },
    });
    const spec = parseCredentialSpec(new Uint8Array(stored.bytes));
    expect(spec.leases).toEqual([]);
    // Capture-only ids (E1-B-01): the host reads only the paths.
    expect(spec.residue).toEqual([
      {
        residueId: "capture-scrub-0",
        bindingId: "capture-scrub-0",
        leaseId: "capture-scrub",
        action: "scrub",
        paths: [".config/tool"],
      },
    ]);
    // The spec reference (never the paths) rides the capture dispatch.
    await dispatch(f);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({
        kind: "sandbox.capture",
        credentialSpec: {
          digest: Buffer.from(stored.digest).toString("hex"),
          bytes: stored.bytes.byteLength,
        },
      }),
    );
    // The capture never touched the sandbox's own lease or residue.
    expect((await leaseRow(a.leaseId)).state).toBe("RECOVERY_REQUIRED");
    expect(await residueOf(a.bindingId)).toMatchObject({ clearedAt: null, recoverable: true });
  });

  it("a capture after a cleared stop still scrubs the path history; a host without spec transfer is refused", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const c = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, c.captureId, "committed")],
    });
    await enableCapture(f);
    const { operationId } = await captureOf(f, sandboxId);
    // E1-B-01: the stop's verified scrub cleared the residue, but that report
    // is no proof for the copied disk: the capture still scrubs the path.
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId },
    });
    expect(parseCredentialSpec(new Uint8Array(stored.bytes)).residue).toEqual([
      expect.objectContaining({ leaseId: "capture-scrub", paths: [".config/tool"] }),
    ]);

    const g = await fixture();
    const { sandboxId: other } = await stoppedWithResidue(g);
    await enableCapture(g);
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: g.host.id } });
    const features = host.daemonFeatures as Record<string, unknown>;
    await db.inspect.sandboxHost.update({
      where: { id: g.host.id },
      data: {
        daemonFeatures: {
          ...features,
          credentials: { ...CREDENTIAL_CAPABILITY, specTransfer: false },
        },
      },
    });
    await expect(captureOf(g, other)).rejects.toMatchObject({
      data: { code: "sandbox.capture_unsupported" },
    });
  });

  it("a capture is refused credential.capture_in_progress while a lease is RELEASING, RECOVERING or INSTALLING", async () => {
    // RELEASING: the stop's capture is durable but not yet committed.
    {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      const stop = await latestOp(sandboxId, "STOP_SANDBOX");
      await dispatch(f);
      await report(f, stop.id, "succeeded", {
        state: "stopped",
        credentialOutcomes: [
          {
            leaseId: a.leaseId,
            bindingId: a.bindingId,
            capture: { status: "durable", captureId: "cap-offline" },
            scrub: "verified",
          },
        ],
      });
      expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
      await enableCapture(f);
      await expect(captureOf(f, sandboxId)).rejects.toSatisfy(inProgress);
      // Once the capture commits, the template capture is accepted.
      await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
      expect((await leaseRow(a.leaseId)).state).toBe("RELEASED");
      await expect(captureOf(f, sandboxId)).resolves.toMatchObject({ state: "QUEUED" });
    }
    // RECOVERING, then INSTALLING after the recovery commits and the grant.
    {
      const f = await fixture();
      const { sandboxId, a } = await stoppedWithResidue(f);
      await credentialCensus(f);
      await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
      expect((await leaseRow(a.leaseId)).state).toBe("RECOVERING");
      expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
      await enableCapture(f);
      await expect(captureOf(f, sandboxId)).rejects.toSatisfy(inProgress);
      await db.inspect.credentialLease.update({
        where: { id: a.leaseId },
        data: { state: "INSTALLING" },
      });
      await expect(captureOf(f, sandboxId)).rejects.toSatisfy(inProgress);
    }
  });

  it("HOST_LOST: ACTIVE and RELEASING leases → RECOVERY_REQUIRED with recoverable residue; launch leases settle as superseded", async () => {
    const f = await fixture({ logins: 2 });
    const { sandboxId, held } = await readySandbox(f);
    const [a, b] = held as [Held, Held];
    // b is mid-teardown (RELEASING) when the host is lost.
    await db.inspect.credentialLease.update({
      where: { id: b.leaseId },
      data: { state: "RELEASING" },
    });
    const sandbox = await sandboxRow(sandboxId);
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
      await tx.sandbox.update({ where: { id: sandboxId }, data: { state: "HOST_LOST" } });
      await settleCredentialsOnHostLost(tx, { sandboxId, generation: sandbox.generation });
    });
    for (const h of [a, b]) {
      expect(await leaseRow(h.leaseId)).toMatchObject({
        state: "RECOVERY_REQUIRED",
        endReason: "host_lost",
        teardownOperationId: null,
      });
      expect(await residueOf(h.bindingId)).toMatchObject({ clearedAt: null, recoverable: true });
      // RECOVERY_REQUIRED still counts against the instance.
      expect((await instanceRow(h.instanceId)).activeLeases).toBe(1);
      expect(
        await db.inspect.credentialEvent.count({
          where: { leaseId: h.leaseId, type: "recovery_required", reason: "host_lost" },
        }),
      ).toBe(1);
    }
  });

  it("UNKNOWN cold reconnect: its launch leases stay until a retry supersedes them; the retry is not refused pending_drain", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const c = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, c.captureId, "committed")],
    });
    await credentialCensus(f);
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    const first = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX" },
    });
    await dispatch(f);
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, state: "RESERVED" },
    });
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId,
      leaseId: lease.id,
      operationId: first.id,
    });
    if (granted.kind !== "granted") throw new Error("grant refused");
    granted.bytes.fill(0);
    await report(f, first.id, "unknown_outcome", undefined, "unknown_outcome");
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: first.id },
        select: { state: true },
      }),
    ).toEqual({ state: "UNKNOWN_OUTCOME" });
    // UNKNOWN is not a definite failure: a late exact receipt may still
    // settle it, so its INSTALLING lease and open binding stay.
    expect((await leaseRow(lease.id)).state).toBe("INSTALLING");
    expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");

    // The documented recovery — retry the reconnect — supersedes it.
    await credentialCensus(f);
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    expect(await leaseRow(lease.id)).toMatchObject({ state: "RELEASED", endReason: "superseded" });
    expect((await residueOf(granted.bindingId)).recoverable).toBe(false);
    const retry = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, state: "RESERVED" },
    });
    expect(retry.instanceId).toBe(a.instanceId);
    expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 1 });
    // The superseded reconnect's spec is gone; the retry's spec scrubs the old residue.
    expect(
      await db.inspect.credentialOperationSpec.count({ where: { operationId: first.id } }),
    ).toBe(0);
    const second = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX", id: { not: first.id } },
    });
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId: second.id },
    });
    expect(parseCredentialSpec(new Uint8Array(stored.bytes)).residue).toEqual([
      expect.objectContaining({ bindingId: granted.bindingId, action: "scrub" }),
    ]);
  });
});

describe("cold reconnect: settle, then claim, in separate transactions (pg)", () => {
  const CLAIM_UPDATE = /^sql:UPDATE credential_instance SET "activeLeases" = "activeLeases" \+ 1/;

  it("an UNKNOWN predecessor's lease on B settles and commits before the retry claims A: no A<B cycle with another sandbox's teardown", async () => {
    const f = await fixture({ logins: 0 });
    const pair = [
      await loginFor(f.actor, 1, ".config/one", undefined, 2),
      await loginFor(f.actor, 1, ".config/two", undefined, 2),
    ].sort((x, y) => (x.id < y.id ? -1 : 1));
    const [la, lb] = pair as [Login, Login];
    const a = la.instances[0]!;
    const b = lb.instances[0]!;
    // X runs with B, stops, and its first cold reconnect ends UNKNOWN with
    // its lease on B RESERVED.
    f.logins = [lb];
    const { sandboxId } = await readySandbox(f);
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    await report(f, stop.id, "succeeded", { state: "stopped" });
    await credentialCensus(f);
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    const first = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX" },
    });
    await dispatch(f);
    const launch = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, state: "RESERVED" },
    });
    await report(f, first.id, "unknown_outcome", undefined, "unknown_outcome");
    expect((await leaseRow(launch.id)).state).toBe("RESERVED");
    // A is attached while stopped: the retry claims it fresh (A sorts first).
    await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: la.id,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    // Y, another sandbox, holds A and B; its teardown locks A, then B.
    const x = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const y = await db.inspect.sandbox.create({
      data: {
        userId: f.ownerId,
        templateId: x.templateId,
        templateRevisionId: x.templateRevisionId,
        originalSelector: x.originalSelector,
        originHostId: f.host.id,
        sandboxHostId: f.host.id,
        hostOwnerId: f.ownerId,
        state: "READY",
      },
      select: { id: true },
    });
    for (const [login, instanceId] of [
      [la, a],
      [lb, b],
    ] as const) {
      await db.inspect.credentialLease.create({
        data: {
          userId: f.ownerId,
          credentialId: login.id,
          accountId: login.accountId,
          instanceId,
          sandboxId: y.id,
          operationId: `op-y-${randomUUID().slice(0, 8)}`,
          kind: "WORKLOAD",
          exclusive: false,
          state: "ACTIVE",
          hostId: f.host.id,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instanceId },
        data: { activeLeases: { increment: 1 } },
      });
    }
    await credentialCensus(f);

    // The retry parks at its first claim (A).
    const gate = db.pauseAt("retry", { before: CLAIM_UPDATE });
    const retry = db.run("retry", () =>
      reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` }),
    );
    await gate.waitReached();
    // The predecessor's lease on B is already settled AND committed: the
    // claiming transaction holds no settled instance.
    expect(await leaseRow(launch.id)).toMatchObject({
      state: "ABANDONED",
      endReason: "superseded",
    });
    const teardown = db.run("y", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${y.id} FOR UPDATE`;
        await settleCredentialTeardown(tx, {
          sandboxId: y.id,
          priorState: "READY",
          generation: 2,
          teardownOperationId: `op-td-${randomUUID().slice(0, 8)}`,
        });
      }),
    );
    // Before the split, Y took A and then waited for B held by the retry.
    await Promise.race([
      teardown.catch(() => undefined),
      db.waitUntilBlocked("y", { by: "retry", timeoutMs: 3_000 }).catch(() => undefined),
    ]);
    gate.release();
    const results = await Promise.allSettled([retry, teardown]);
    expect(results.map((r) => (r.status === "fulfilled" ? "fulfilled" : String(r.reason)))).toEqual(
      ["fulfilled", "fulfilled"],
    );
    const claimed = await db.inspect.credentialLease.findMany({
      where: { sandboxId, state: "RESERVED" },
      select: { instanceId: true },
      orderBy: { instanceId: "asc" },
    });
    expect(claimed.map((lease) => lease.instanceId).sort()).toEqual([a, b].sort());
    expect(await instanceRow(a)).toMatchObject({ activeLeases: 2 });
    expect(await instanceRow(b)).toMatchObject({ activeLeases: 2 });
  });

  it("a crash between the settlement and the claim leaves a consistent STOPPED sandbox; the next retry claims normally", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const c = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, c.captureId, "committed")],
    });
    await credentialCensus(f);
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    const first = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX" },
    });
    await dispatch(f);
    await report(f, first.id, "unknown_outcome", undefined, "unknown_outcome");
    const launch = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, state: "RESERVED" },
    });
    const before = (await sandboxRow(sandboxId)).generation;
    await credentialCensus(f);
    // The process dies in the claiming transaction, after the settlement committed.
    const gate = db.pauseAt("retry", { before: CLAIM_UPDATE });
    const crashed = db
      .run("retry", () =>
        reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` }),
      )
      .catch((error: unknown) => error);
    await gate.waitReached();
    gate.fail(new Error("process died"));
    await crashed;
    expect(await leaseRow(launch.id)).toMatchObject({
      state: "ABANDONED",
      endReason: "superseded",
    });
    expect(await sandboxRow(sandboxId)).toMatchObject({ state: "STOPPED", generation: before + 1 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: first.id },
        select: { state: true },
      }),
    ).toEqual({ state: "CANCEL_REQUESTED" });
    expect(
      await db.inspect.credentialLease.count({ where: { sandboxId, state: "RESERVED" } }),
    ).toBe(0);
    expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 0 });
    // The retry finds nothing left to settle and claims as usual.
    await reconnectSandbox(f.actor, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    expect(
      await db.inspect.credentialLease.findFirstOrThrow({
        where: { sandboxId, state: "RESERVED" },
        select: { instanceId: true },
      }),
    ).toEqual({ instanceId: a.instanceId });
    expect(await instanceRow(a.instanceId)).toMatchObject({ activeLeases: 1 });
    expect((await sandboxRow(sandboxId)).generation).toBe(before + 2);
  });
});

describe("C10 live attach / free (pg)", () => {
  /** A READY sandbox with the fixture's login, plus a second login (other files) to attach. */
  async function readyWithSpare() {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const spare = await loginFor(f.actor, 1, ".config/spare");
    return { f, sandboxId, a: held[0]!, spare };
  }

  async function attachOp(sandboxId: string) {
    return db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "CREDENTIAL_ATTACH" },
      orderBy: { createdAt: "desc" },
    });
  }

  async function freeOp(sandboxId: string) {
    return db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "CREDENTIAL_FREE" },
      orderBy: { createdAt: "desc" },
    });
  }

  /** attach → dispatch → grant → installed → SUCCEEDED; returns the held lease. */
  async function liveAttach(f: Fixture, sandboxId: string, login: Login): Promise<Held> {
    await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: login.id,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    const op = await attachOp(sandboxId);
    await dispatch(f);
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, credentialId: login.id, operationId: op.id },
    });
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId,
      leaseId: lease.id,
      operationId: op.id,
    });
    if (granted.kind !== "granted") throw new Error(`grant refused: ${JSON.stringify(granted)}`);
    granted.bytes.fill(0);
    expect(
      await recordInstalled({
        hostId: f.host.id,
        connectionEpoch: f.epoch,
        leaseId: lease.id,
        bindingId: granted.bindingId,
        storageSeq: granted.storageSeq,
      }),
    ).toBe(true);
    await report(f, op.id, "succeeded", { state: "attached" });
    return { leaseId: lease.id, bindingId: granted.bindingId, login, instanceId: lease.instanceId };
  }

  const attachment = (sandboxId: string, credentialId: string) =>
    db.inspect.sandboxCredential.findFirst({
      where: { sandboxId, credentialId },
      orderBy: { attachedAt: "desc" },
      select: { detachedAt: true, accountId: true, instanceId: true, requestedInstanceId: true },
    });

  it("live attach: credential.attach dispatch with an inject spec; grant → installed → SUCCEEDED; the lease is ACTIVE and attached", async () => {
    const { f, sandboxId, spare } = await readyWithSpare();
    await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    const op = await attachOp(sandboxId);
    expect(op).toMatchObject({ state: "QUEUED", generation: 1 });
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId: op.id },
    });
    const spec = parseCredentialSpec(new Uint8Array(stored.bytes));
    expect(spec.leases).toEqual([
      expect.objectContaining({ credentialId: spare.id, action: "inject" }),
    ]);
    // The create's open binding is a sibling's installed files: never listed.
    expect(spec.residue).toEqual([]);
    await dispatch(f);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({ kind: "credential.attach", credentialSpec: expect.any(Object) }),
    );
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, credentialId: spare.id },
    });
    expect(lease).toMatchObject({ state: "RESERVED", operationId: op.id, hostId: f.host.id });
    // Before install the host's report of success is an install failure.
    const early = await db.inspect.credentialLease.count({
      where: { operationId: op.id, state: "ACTIVE" },
    });
    expect(early).toBe(0);
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId,
      leaseId: lease.id,
      operationId: op.id,
    });
    expect(granted.kind).toBe("granted");
    if (granted.kind === "granted") {
      granted.bytes.fill(0);
      await recordInstalled({
        hostId: f.host.id,
        connectionEpoch: f.epoch,
        leaseId: lease.id,
        bindingId: granted.bindingId,
        storageSeq: granted.storageSeq,
      });
    }
    await report(f, op.id, "succeeded", { state: "attached" });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
    ).toMatchObject({ state: "SUCCEEDED" });
    expect(await leaseRow(lease.id)).toMatchObject({ state: "ACTIVE" });
    expect(await attachment(sandboxId, spare.id)).toMatchObject({
      detachedAt: null,
      instanceId: lease.instanceId,
    });
    expect((await sandboxRow(sandboxId)).generation).toBe(1);
    // The stored spec is removed with the terminal operation.
    expect(await db.inspect.credentialOperationSpec.count({ where: { operationId: op.id } })).toBe(
      0,
    );
    // Attaching it again, or while a stop is in flight, is refused.
    await expect(
      attachSandboxCredential(f.actor, {
        id: sandboxId,
        credentialId: spare.id,
        idempotencyKey: `attach-${randomUUID()}`,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.already_attached" } });
  });

  it("a host that reports success without the install fails the attach; the lease ends and the attachment with it", async () => {
    const { f, sandboxId, spare } = await readyWithSpare();
    await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    const op = await attachOp(sandboxId);
    await dispatch(f);
    await report(f, op.id, "succeeded", { state: "attached" });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
    ).toMatchObject({ state: "FAILED", errorCode: "credential_install_failed" });
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { operationId: op.id },
    });
    expect(lease.state).toBe("ABANDONED");
    expect((await instanceRow(lease.instanceId)).activeLeases).toBe(0);
    expect((await attachment(sandboxId, spare.id))?.detachedAt).not.toBeNull();
    expect((await sandboxRow(sandboxId)).state).toBe("READY");
  });

  it("12: stop during attach — RESERVED → ABANDONED, INSTALLING → RELEASED{superseded}; the superseded attach can never fetch a value", async () => {
    for (const phase of ["RESERVED", "INSTALLING"] as const) {
      const { f, sandboxId, spare } = await readyWithSpare();
      await attachSandboxCredential(f.actor, {
        id: sandboxId,
        credentialId: spare.id,
        idempotencyKey: `attach-${randomUUID()}`,
      });
      const op = await attachOp(sandboxId);
      await dispatch(f);
      const lease = await db.inspect.credentialLease.findFirstOrThrow({
        where: { operationId: op.id },
      });
      let bindingId: string | null = null;
      if (phase === "INSTALLING") {
        const granted = await grantInstallBundle({
          hostId: f.host.id,
          connectionEpoch: f.epoch,
          requestId: `req-${randomUUID()}`,
          sandboxId,
          leaseId: lease.id,
          operationId: op.id,
        });
        if (granted.kind !== "granted") throw new Error("grant refused");
        granted.bytes.fill(0);
        bindingId = granted.bindingId;
        expect((await leaseRow(lease.id)).state).toBe("INSTALLING");
      }
      await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      expect(await leaseRow(lease.id)).toMatchObject(
        phase === "RESERVED"
          ? { state: "ABANDONED", endReason: "superseded" }
          : { state: "RELEASED", endReason: "superseded" },
      );
      expect((await instanceRow(lease.instanceId)).activeLeases).toBe(0);
      if (bindingId) expect(await residueOf(bindingId)).toMatchObject({ recoverable: false });
      // The attach operation is retired; its grant is refused (op generation
      // ≠ sandbox generation), and its spec is gone.
      const retired = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } });
      expect(["CANCEL_REQUESTED", "CANCELLED"]).toContain(retired.state);
      const late = await grantInstallBundle({
        hostId: f.host.id,
        connectionEpoch: f.epoch,
        requestId: `req-${randomUUID()}`,
        sandboxId,
        leaseId: lease.id,
        operationId: op.id,
      });
      expect(late).toEqual({
        kind: "refused",
        code: expect.stringMatching(/stale|not_authorized/),
      });
      expect(
        await db.inspect.credentialOperationSpec.count({ where: { operationId: op.id } }),
      ).toBe(0);
      // B1: the attachment stays; the next start claims the login.
      expect((await attachment(sandboxId, spare.id))?.detachedAt).toBeNull();
      // A new attach or free is refused while the stop is in flight.
      await expect(
        freeSandboxCredential(f.actor, {
          id: sandboxId,
          credentialId: f.logins[0]!.id,
          idempotencyKey: `free-${randomUUID()}`,
        }),
      ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
    }
  });

  it("free on READY: capture COMMITTED + verified scrub → RELEASED, detached, residue cleared; nothing about the sandbox changes", async () => {
    const { f, sandboxId, spare } = await readyWithSpare();
    const b = await liveAttach(f, sandboxId, spare);
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      idempotencyKey: `free-${randomUUID()}`,
    });
    const op = await freeOp(sandboxId);
    expect(await leaseRow(b.leaseId)).toMatchObject({
      state: "RELEASING",
      teardownOperationId: op.id,
    });
    const spec = parseCredentialSpec(
      new Uint8Array(
        (
          await db.inspect.credentialOperationSpec.findUniqueOrThrow({
            where: { operationId: op.id },
          })
        ).bytes,
      ),
    );
    expect(spec.leases).toEqual([
      expect.objectContaining({ leaseId: b.leaseId, bindingId: b.bindingId, action: "none" }),
    ]);
    await dispatch(f);
    expect(relay.dispatchOperation).toHaveBeenCalledWith(
      f.host.id,
      expect.objectContaining({ kind: "credential.free" }),
    );
    const { captureId, ack } = await capture(f, sandboxId, b, {
      captureSeq: 1,
      token: "rotated",
      kind: "free",
    });
    expect(ack).toEqual({ outcome: "committed" });
    // Not released by the commit alone: the free has not finished.
    expect((await leaseRow(b.leaseId)).state).toBe("RELEASING");
    await report(f, op.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [acked(b, captureId, "committed")],
    });
    expect(await leaseRow(b.leaseId)).toMatchObject({ state: "RELEASED", endReason: "captured" });
    expect(await instanceRow(b.instanceId)).toMatchObject({ activeLeases: 0, currentSeq: 2 });
    expect(await residueOf(b.bindingId)).toMatchObject({ clearReason: "scrubbed" });
    expect((await attachment(sandboxId, spare.id))?.detachedAt).not.toBeNull();
    expect(await sandboxRow(sandboxId)).toMatchObject({ state: "READY", generation: 1 });
    const stored = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } });
    expect(JSON.stringify(stored.result)).not.toContain("credentialOutcomes");
    // The freed login can be attached again.
    await liveAttach(f, sandboxId, spare);
  });

  it("free outcomes: REJECTED → RECOVERY_REQUIRED attached (re-freeable), skip → RELEASED{skipped}, a refusal before any effect → ACTIVE", async () => {
    const { f, sandboxId, spare } = await readyWithSpare();
    const b = await liveAttach(f, sandboxId, spare);
    // A refusal before any guest effect (slot busy): the lease is ACTIVE again.
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      idempotencyKey: `free-${randomUUID()}`,
    });
    await dispatch(f);
    await report(f, (await freeOp(sandboxId)).id, "failed", undefined, "state_conflict");
    expect(await leaseRow(b.leaseId)).toMatchObject({ state: "ACTIVE", teardownOperationId: null });

    // REJECTED: no scrub; RECOVERY_REQUIRED with its binding open; attached.
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      idempotencyKey: `free-${randomUUID()}`,
    });
    const rejectedOp = await freeOp(sandboxId);
    await dispatch(f);
    const { captureId, ack } = await capture(f, sandboxId, b, {
      captureSeq: 1,
      token: "x",
      kind: "free",
      tamper: true,
    });
    expect(ack?.outcome).toBe("rejected");
    await report(f, rejectedOp.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [acked(b, captureId, "rejected", "not_run")],
    });
    expect((await leaseRow(b.leaseId)).state).toBe("RECOVERY_REQUIRED");
    expect(
      (await db.inspect.credentialBinding.findUniqueOrThrow({ where: { id: b.bindingId } }))
        .closedAt,
    ).toBeNull();
    expect((await attachment(sandboxId, spare.id))?.detachedAt).toBeNull();

    // "Free anyway (discard)": skip → RELEASED{skipped}, detached.
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      credentialCapture: "skip",
      idempotencyKey: `free-${randomUUID()}`,
    });
    const skipOp = await freeOp(sandboxId);
    expect(
      parseCredentialSpec(
        new Uint8Array(
          (
            await db.inspect.credentialOperationSpec.findUniqueOrThrow({
              where: { operationId: skipOp.id },
            })
          ).bytes,
        ),
      ).leases[0]?.action,
    ).toBe("scrub_only");
    await dispatch(f);
    await report(f, skipOp.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [
        {
          leaseId: b.leaseId,
          bindingId: b.bindingId,
          capture: { status: "none" },
          scrub: "verified",
        },
      ],
    });
    expect(await leaseRow(b.leaseId)).toMatchObject({ state: "RELEASED", endReason: "skipped" });
    expect((await instanceRow(b.instanceId)).activeLeases).toBe(0);
    expect((await attachment(sandboxId, spare.id))?.detachedAt).not.toBeNull();
  });

  it("a stop supersedes an in-flight free: the lease moves to the stop and its free capture still commits", async () => {
    const { f, sandboxId, a } = await readyWithSpare();
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: a.login.id,
      idempotencyKey: `free-${randomUUID()}`,
    });
    await dispatch(f);
    const { captureId } = await capture(f, sandboxId, a, {
      captureSeq: 1,
      token: "v2",
      kind: "free",
    });
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    expect(await leaseRow(a.leaseId)).toMatchObject({
      state: "RELEASING",
      teardownOperationId: stop.id,
    });
    await dispatch(f);
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, captureId, "committed")],
    });
    expect(await leaseRow(a.leaseId)).toMatchObject({ state: "RELEASED", endReason: "captured" });
  });

  it("32: free on STOPPED with a RELEASING lease → pending_drain; once RELEASED the free detaches; a RECOVERY_REQUIRED lease → recovery_required", async () => {
    for (const settle of ["commit", "census"] as const) {
      const f = await fixture();
      const { sandboxId, held } = await readySandbox(f);
      const a = held[0]!;
      await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      const stop = await latestOp(sandboxId, "STOP_SANDBOX");
      await dispatch(f);
      await report(f, stop.id, "succeeded", {
        state: "stopped",
        credentialOutcomes: [
          {
            leaseId: a.leaseId,
            bindingId: a.bindingId,
            capture: { status: "durable", captureId: "cap-offline" },
            scrub: "not_run",
          },
        ],
      });
      expect((await sandboxRow(sandboxId)).state).toBe("STOPPED");
      expect((await leaseRow(a.leaseId)).state).toBe("RELEASING");
      const free = () =>
        freeSandboxCredential(f.actor, {
          id: sandboxId,
          credentialId: a.login.id,
          idempotencyKey: `free-${randomUUID()}`,
        });
      await expect(free()).rejects.toMatchObject({ data: { code: "credential.pending_drain" } });
      expect((await attachment(sandboxId, a.login.id))?.detachedAt).toBeNull();
      if (settle === "commit") {
        expect(await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" })).toMatchObject({
          ack: { outcome: "committed" },
        });
        expect((await leaseRow(a.leaseId)).state).toBe("RELEASED");
        const receipt = await free();
        expect(receipt.state).toBe("SUCCEEDED");
        expect((await attachment(sandboxId, a.login.id))?.detachedAt).not.toBeNull();
      } else {
        // Census settlement: no envelope listed and no outcome → RECOVERY_REQUIRED.
        await credentialCensus(f);
        expect((await leaseRow(a.leaseId)).state).toBe("RECOVERY_REQUIRED");
        await expect(free()).rejects.toMatchObject({
          data: { code: "credential.recovery_required" },
        });
        expect((await attachment(sandboxId, a.login.id))?.detachedAt).toBeNull();
      }
    }
  });

  it("STOPPED attach records the attachment only; the next start prefers the named instance", async () => {
    const f = await fixture();
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const { captureId } = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, captureId, "committed")],
    });
    const spare = await loginFor(f.actor, 2, ".config/spare");
    const receipt = await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: spare.id,
      instanceId: spare.instances[1]!,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    expect(receipt.state).toBe("SUCCEEDED");
    expect(await db.inspect.credentialLease.count({ where: { credentialId: spare.id } })).toBe(0);
    expect(await attachment(sandboxId, spare.id)).toMatchObject({
      detachedAt: null,
      instanceId: spare.instances[1],
    });
    await credentialCensus(f);
    await reconnectSandbox(
      f.actor,
      { id: sandboxId, mode: "cold", idempotencyKey: `start-${randomUUID()}` },
      clock,
    );
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, credentialId: spare.id },
    });
    expect(lease).toMatchObject({ state: "RESERVED", instanceId: spare.instances[1] });
    expect(await attachment(sandboxId, spare.id)).toMatchObject({
      instanceId: spare.instances[1],
    });
  });

  it("resume pins on the start call: a pinned instance is claimed; a pin naming an unattached login is refused", async () => {
    const f = await fixture({ instances: 2 });
    const { sandboxId, held } = await readySandbox(f);
    const a = held[0]!;
    await stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await latestOp(sandboxId, "STOP_SANDBOX");
    await dispatch(f);
    const { captureId } = await capture(f, sandboxId, a, { captureSeq: 1, token: "v2" });
    await report(f, stop.id, "succeeded", {
      state: "stopped",
      credentialOutcomes: [acked(a, captureId, "committed")],
    });
    await credentialCensus(f);
    const other = await loginFor(f.actor, 1, ".config/other");
    await expect(
      reconnectSandbox(
        f.actor,
        {
          id: sandboxId,
          mode: "cold",
          idempotencyKey: `start-${randomUUID()}`,
          credentials: [{ credentialId: other.id }],
        },
        clock,
      ),
    ).rejects.toMatchObject({ data: { code: "credential.not_attached" } });
    const pinned = a.login.instances[1]!;
    await reconnectSandbox(
      f.actor,
      {
        id: sandboxId,
        mode: "cold",
        idempotencyKey: `start-${randomUUID()}`,
        credentials: [{ credentialId: a.login.id, instanceId: pinned }],
      },
      clock,
    );
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, credentialId: a.login.id, state: "RESERVED" },
    });
    expect(lease.instanceId).toBe(pinned);
  });

  it("race: attach vs stop on one sandbox, both orders — never a live attach lease on a stopping sandbox; activeLeases consistent", async () => {
    for (let round = 0; round < 3; round += 1) {
      const { f, sandboxId, spare } = await readyWithSpare();
      const results = await Promise.allSettled([
        attachSandboxCredential(f.actor, {
          id: sandboxId,
          credentialId: spare.id,
          idempotencyKey: `attach-${randomUUID()}`,
        }),
        stopSandbox(f.actor, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` }),
      ]);
      expect(results[1].status).toBe("fulfilled");
      expect((await sandboxRow(sandboxId)).state).toBe("STOPPING");
      const leases = await db.inspect.credentialLease.findMany({
        where: { credentialId: spare.id },
        select: { state: true, instanceId: true },
      });
      for (const lease of leases) expect(["ABANDONED", "RELEASED"]).toContain(lease.state);
      for (const instanceId of spare.instances)
        expect((await instanceRow(instanceId)).activeLeases).toBe(
          leases.filter(
            (l) =>
              l.instanceId === instanceId &&
              !["ABANDONED", "RELEASED", "FORCE_RELEASED"].includes(l.state),
          ).length,
        );
      if (results[0].status === "rejected")
        expect(results[0].reason).toMatchObject({ data: { code: "sandbox.state_conflict" } });
    }
  });

  it("race: two attaches of one exclusive instance on two sandboxes — one lease, the other in_use", async () => {
    const f = await fixture();
    const one = await readySandbox(f);
    const two = await readySandbox({ ...f, logins: [] });
    const spare = await loginFor(f.actor, 1, ".config/spare");
    const results = await Promise.allSettled(
      [one.sandboxId, two.sandboxId].map((id) =>
        attachSandboxCredential(f.actor, {
          id,
          credentialId: spare.id,
          idempotencyKey: `attach-${randomUUID()}`,
        }),
      ),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const refused = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(refused.reason).toMatchObject({ data: { code: "credential.in_use" } });
    expect((await instanceRow(spare.instances[0]!)).activeLeases).toBe(1);
  });
});

describe("C14 proxy mode: credentialProxyEnabled and attach gating (pg)", () => {
  const SECRET = "sk-test-proxy-value";

  /** A PROXY-delivery login: one proxied env entry, no files, no copy-back. */
  async function proxyLoginFor(
    actor: { kind: "session"; ownerId: string },
    names: { entry: string; base: string; host?: string },
  ): Promise<Login> {
    const slug = `api-${randomUUID().slice(0, 8)}`;
    const document = {
      schemaVersion: 1,
      id: slug,
      displayName: "API",
      login: { command: "true", method: "paste" },
      credentials: {
        env: [
          {
            name: names.entry,
            required: true,
            proxy: {
              upstream: `https://${names.host ?? "api.example.test"}/v1`,
              header: "Authorization",
              format: "Bearer {value}",
              baseUrlEnv: names.base,
              placeholderEnv: names.entry,
            },
          },
        ],
        sharing: "exclusive",
      },
    };
    const definition = await service.createDefinition(actor, { document });
    const login = await service.createLogin(actor, {
      name: slug,
      definitionId: definition.id,
      delivery: "PROXY",
    });
    const account = await service.createAccount(actor, { credentialId: login.id });
    const instance = await service.createInstance(actor, {
      credentialId: login.id,
      accountId: account.id,
    });
    await service.writeValue(actor, {
      credentialId: login.id,
      instanceId: instance.id,
      env: { [names.entry]: SECRET },
    });
    const { definitionDigest } = await db.inspect.credential.findUniqueOrThrow({
      where: { id: login.id },
      select: { definitionDigest: true },
    });
    const parsed = parseLoginDefinition(document);
    if (!parsed.success) throw new Error("bad proxy fixture definition");
    return {
      dir: "",
      id: login.id,
      accountId: account.id,
      instances: [instance.id],
      digest: definitionDigest,
      definition: parsed.definition,
    };
  }

  const proxyEnabled = async (sandboxId: string) =>
    (
      await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: sandboxId },
        select: { credentialProxyEnabled: true },
      })
    ).credentialProxyEnabled;

  it("a sandbox created without a proxy login is not proxy-enabled: a live proxy attach is refused before any lease or attachment", async () => {
    const f = await fixture({ proxy: true });
    const { sandboxId } = await readySandbox(f);
    expect(await proxyEnabled(sandboxId)).toBe(false);
    const proxied = await proxyLoginFor(f.actor, { entry: "API_KEY", base: "API_BASE_URL" });
    await expect(
      attachSandboxCredential(f.actor, {
        id: sandboxId,
        credentialId: proxied.id,
        idempotencyKey: `attach-${randomUUID()}`,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.proxy_not_enabled" } });
    expect(
      await db.inspect.credentialLease.count({ where: { sandboxId, credentialId: proxied.id } }),
    ).toBe(0);
    expect(
      await db.inspect.sandboxCredential.count({ where: { sandboxId, credentialId: proxied.id } }),
    ).toBe(0);
    expect(
      await db.inspect.sandboxOperation.count({ where: { sandboxId, kind: "CREDENTIAL_ATTACH" } }),
    ).toBe(0);
  });

  it("a sandbox created with a proxy login is proxy-enabled for life; another proxy login attaches live with a proxy spec; a guest-name clash is env_conflict", async () => {
    const f = await fixture({ logins: 0, proxy: true });
    const first = await proxyLoginFor(f.actor, { entry: "API_KEY", base: "API_BASE_URL" });
    const { sandboxId, held } = await readySandbox({ ...f, logins: [first] });
    expect(await proxyEnabled(sandboxId)).toBe(true);
    expect(await leaseRow(held[0]!.leaseId)).toMatchObject({ state: "ACTIVE" });

    // A second proxy login whose base URL name clashes with the first's.
    const clash = await proxyLoginFor(f.actor, { entry: "OTHER_KEY", base: "API_BASE_URL" });
    await expect(
      attachSandboxCredential(f.actor, {
        id: sandboxId,
        credentialId: clash.id,
        idempotencyKey: `attach-${randomUUID()}`,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.env_conflict" } });

    const second = await proxyLoginFor(f.actor, {
      entry: "B_KEY",
      base: "B_BASE_URL",
      host: "api-b.example.test",
    });
    await attachSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: second.id,
      idempotencyKey: `attach-${randomUUID()}`,
    });
    const op = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "CREDENTIAL_ATTACH" },
    });
    const stored = await db.inspect.credentialOperationSpec.findUniqueOrThrow({
      where: { operationId: op.id },
    });
    const spec = parseCredentialSpec(new Uint8Array(stored.bytes));
    expect(spec.leases).toEqual([
      expect.objectContaining({
        credentialId: second.id,
        action: "inject",
        delivery: "proxy",
        copyBack: false,
        env: ["B_KEY"],
        proxy: [
          {
            name: "B_KEY",
            upstream: "https://api-b.example.test/v1",
            header: "Authorization",
            format: "Bearer {value}",
            baseUrlEnv: "B_BASE_URL",
            placeholderEnv: "B_KEY",
          },
        ],
      }),
    ]);
    // The spec never carries a value.
    expect(Buffer.from(stored.bytes).includes(SECRET)).toBe(false);
    await dispatch(f);
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId, credentialId: second.id },
    });
    const granted = await grantInstallBundle({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      requestId: `req-${randomUUID()}`,
      sandboxId,
      leaseId: lease.id,
      operationId: op.id,
    });
    expect(granted.kind).toBe("granted");
    if (granted.kind !== "granted") return;
    granted.bytes.fill(0);
    await recordInstalled({
      hostId: f.host.id,
      connectionEpoch: f.epoch,
      leaseId: lease.id,
      bindingId: granted.bindingId,
      storageSeq: granted.storageSeq,
    });
    await report(f, op.id, "succeeded", { state: "attached" });
    expect(await leaseRow(lease.id)).toMatchObject({ state: "ACTIVE" });
    // Freeing every proxy login never clears the flag.
    await freeSandboxCredential(f.actor, {
      id: sandboxId,
      credentialId: second.id,
      idempotencyKey: `free-${randomUUID()}`,
    });
    expect(await proxyEnabled(sandboxId)).toBe(true);
  });

  it("a proxy-enabled sandbox's live attach is still refused by a host without the proxy capability", async () => {
    const f = await fixture({ logins: 0, proxy: true });
    const first = await proxyLoginFor(f.actor, { entry: "API_KEY", base: "API_BASE_URL" });
    const { sandboxId } = await readySandbox({ ...f, logins: [first] });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        daemonFeatures: {
          egressPolicy: true,
          terminal: true,
          credentials: { ...CREDENTIAL_CAPABILITY, proxy: false },
        },
      },
    });
    const second = await proxyLoginFor(f.actor, { entry: "B_KEY", base: "B_BASE_URL" });
    await expect(
      attachSandboxCredential(f.actor, {
        id: sandboxId,
        credentialId: second.id,
        idempotencyKey: `attach-${randomUUID()}`,
      }),
    ).rejects.toMatchObject({ data: { code: "credential.host_forbidden" } });
    expect(
      await db.inspect.credentialLease.count({ where: { sandboxId, credentialId: second.id } }),
    ).toBe(0);
  });
});
