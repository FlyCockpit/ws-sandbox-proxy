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
const { grantInstallBundle, recordInstalled } = await import("@wssp/api/credentials/relay");
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
