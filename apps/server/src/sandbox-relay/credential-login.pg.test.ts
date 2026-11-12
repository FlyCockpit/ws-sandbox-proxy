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
 * C12 login sandbox flow against real PostgreSQL: the login
 * claim, the LOGIN binding at READY, the initial save (commit → instance
 * READY → only then destroy), retry after an incomplete capture, cancel, and
 * concurrent logins on one instance.
 */
const db = await pgTestDatabase();
const { createSandbox, runCommand } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const service = await import("@wssp/api/credentials/service");
const sessions = await import("../../../../packages/api/src/credentials/login-sessions");
const { commitCapture, issueCurrentReturnKey } = await import("@wssp/api/credentials/relay");
const { sealToReturnKey } = await import(
  "../../../../packages/api/src/credentials/vault/sealed-box"
);
const { buildEnvelope } = await import("../../../../packages/api/src/credentials/vault/envelope");
const { leaseWireSchema } = await import("@wssp/api/sandbox/lease-wire");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { applyOperationResult } = await import("./operation-handlers.js");
const { parseCredentialSpec } = await import("@wssp/sandbox-contracts");
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
const DIR = ".config/tool";
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
const document = (slug: string, extra: Record<string, unknown> = {}) => ({
  schemaVersion: 1,
  id: slug,
  displayName: "Tool",
  login: { command: "tool login", method: "device-code", verifyCommand: "tool whoami" },
  credentials: {
    files: { required: [DIR], optional: [], exclude: [] },
    sharing: "exclusive",
    ...extra,
  },
});

async function fixture() {
  const ownerId = `login-${randomUUID()}`;
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
      daemonFeatures: { egressPolicy: true, terminal: true, credentials: CREDENTIAL_CAPABILITY },
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
  const definition = await service.createDefinition(actor, { document: document(slug) });
  const login = await service.createLogin(actor, { name: slug, definitionId: definition.id });
  const { definitionDigest } = await db.inspect.credential.findUniqueOrThrow({
    where: { id: login.id },
    select: { definitionDigest: true },
  });
  const parsed = parseLoginDefinition(document(slug));
  if (!parsed.success) throw new Error("bad fixture definition");
  const frame = await issueCurrentReturnKey({
    hostId: host.id,
    hostSlotEpoch: 0,
    serverOrigin: ORIGIN,
  });
  if (!frame) throw new Error("no return key");
  return {
    ownerId,
    actor,
    host,
    template,
    login: { id: login.id, digest: definitionDigest, definition: parsed.definition },
    key: { kidR: frame.kidR, publicKey: Buffer.from(frame.publicKey, "base64url") },
    epoch: 1,
  };
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
  state: "succeeded" | "failed",
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

const newAccountAndInstance = (f: Fixture) => ({
  credentialId: f.login.id,
  newAccount: {},
  newInstance: {},
  sandboxHostId: f.host.id,
  template: `revision/${f.template.id}`,
});

/** startLogin → create dispatched → host reports ready. */
async function readyLogin(f: Fixture, input = newAccountAndInstance(f)) {
  const started = await sessions.startLogin(f.actor, input);
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: started.sandboxId, kind: "CREATE_SANDBOX" },
  });
  await dispatch(f);
  await report(f, create.id, "succeeded", { state: "ready" });
  const lease = await db.inspect.credentialLease.findFirstOrThrow({
    where: { loginSessionId: started.sessionId },
  });
  return { ...started, leaseId: lease.id, instanceId: lease.instanceId };
}

async function loginCapture(
  f: Fixture,
  sandboxId: string,
  lease: { leaseId: string; bindingId: string; instanceId: string },
  o: { captureSeq: number; token?: string; missingRequired?: boolean },
) {
  const captureId = `cap-${randomUUID().slice(0, 12)}`;
  const aad = {
    serverOrigin: ORIGIN,
    hostOwnerId: f.ownerId,
    hostId: f.host.id,
    sandboxOwnerId: f.ownerId,
    sandboxId,
    leaseId: lease.leaseId,
    bindingId: lease.bindingId,
    instanceId: lease.instanceId,
    credentialId: f.login.id,
    captureSeq: String(o.captureSeq),
    captureId,
    kind: "login",
    residueId: "",
  } as Parameters<typeof sealToReturnKey>[2];
  const plaintext = encodeBundle(
    {
      definitionDigest: fromHex(f.login.digest),
      files: o.missingRequired
        ? []
        : [
            { kind: "dir", path: DIR, mode: 0o700 },
            {
              kind: "file",
              path: `${DIR}/token`,
              mode: 0o600,
              data: Buffer.from(o.token ?? "fresh-login"),
            },
          ],
      env: [],
    },
    f.login.definition,
  );
  const seal = sealToReturnKey(plaintext, f.key.publicKey, aad);
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
    leaseId: lease.leaseId,
    bindingId: lease.bindingId,
    kidR: f.key.kidR,
    kind: "login",
    envelopeDigest: createHash("sha256").update(envelope).digest("hex"),
    envelope,
  });
  return { captureId, ack };
}

const sessionRow = (id: string) =>
  db.inspect.credentialLoginSession.findUniqueOrThrow({
    where: { id },
    select: { state: true, sandboxId: true },
  });
const leaseRow = (id: string) =>
  db.inspect.credentialLease.findUniqueOrThrow({
    where: { id },
    select: {
      state: true,
      endReason: true,
      kind: true,
      baseSeq: true,
      hostId: true,
      currentBindingId: true,
      teardownOperationId: true,
    },
  });
const instanceRow = (id: string) =>
  db.inspect.credentialInstance.findUniqueOrThrow({
    where: { id },
    select: { activeLeases: true, currentSeq: true, state: true, loginLeaseId: true },
  });
const freeOp = (sandboxId: string) =>
  db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId, kind: "CREDENTIAL_FREE" },
    orderBy: { createdAt: "desc" },
  });

async function finish(f: Fixture, sessionId: string, sandboxId: string) {
  const out = await sessions.finishLogin(f.actor, { id: sessionId });
  expect(out).toMatchObject({ state: "SAVING" });
  const op = await freeOp(sandboxId);
  await dispatch(f);
  expect(relay.dispatchOperation).toHaveBeenCalledWith(
    f.host.id,
    expect.objectContaining({ kind: "credential.free" }),
  );
  return op;
}

describe("C12 login sandbox flow (pg)", () => {
  it("login claim: a CREDENTIAL_LOGIN sandbox holds the instance (loginLeaseId) against workload claims and uploads", async () => {
    const f = await fixture();
    const started = await sessions.startLogin(f.actor, newAccountAndInstance(f));
    expect(started).toMatchObject({
      state: "PROVISIONING",
      login: { command: "tool login", method: "device-code", supported: true },
    });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: started.sandboxId },
      select: { purpose: true, leaseExpireAction: true },
    });
    expect(sandbox).toMatchObject({ purpose: "CREDENTIAL_LOGIN", leaseExpireAction: "DESTROY" });
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { loginSessionId: started.sessionId },
    });
    expect(lease).toMatchObject({
      kind: "LOGIN",
      state: "RESERVED",
      exclusive: true,
      sandboxId: started.sandboxId,
    });
    expect(await instanceRow(lease.instanceId)).toMatchObject({
      activeLeases: 1,
      loginLeaseId: lease.id,
      state: "EMPTY",
    });
    // The create carries no credential spec: a login sandbox starts clean.
    const create = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: started.sandboxId, kind: "CREATE_SANDBOX" },
    });
    expect(
      await db.inspect.credentialOperationSpec.count({ where: { operationId: create.id } }),
    ).toBe(0);
    // Upload and a workload create naming the held instance are refused.
    await expect(
      service.writeValue(f.actor, {
        credentialId: f.login.id,
        instanceId: lease.instanceId,
        files: [{ path: DIR, kind: "dir" }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.busy" } });
    await expect(
      createSandbox(f.actor, {
        template: `revision/${f.template.id}`,
        sandboxHostId: f.host.id,
        idempotencyKey: `create-${randomUUID()}`,
        credentials: [{ credentialId: f.login.id, instanceId: lease.instanceId }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.needs_login" } });
    // The managed sandbox is hidden from the sandbox list and refuses /v1-style work.
    await expect(
      runCommand(f.actor, {
        id: started.sandboxId,
        idempotencyKey: `cmd-${randomUUID()}`,
        argv: ["true"],
        timeoutMs: 10_000,
      }),
    ).rejects.toMatchObject({ data: { code: "sandbox.managed" } });
  });

  it("refuses PROXY / env-only logins and required env without a value (login_requires_upload)", async () => {
    const f = await fixture();
    const slug = `envonly-${randomUUID().slice(0, 8)}`;
    const envOnly = await service.createDefinition(f.actor, {
      document: {
        schemaVersion: 1,
        id: slug,
        displayName: "Env",
        login: { command: "x", method: "paste" },
        credentials: { env: [{ name: "TOKEN", required: true }] },
      },
    });
    const envLogin = await service.createLogin(f.actor, { name: slug, definitionId: envOnly.id });
    await expect(
      sessions.startLogin(f.actor, { ...newAccountAndInstance(f), credentialId: envLogin.id }),
    ).rejects.toMatchObject({ data: { code: "credential.login_requires_upload" } });
    const slug2 = `reqenv-${randomUUID().slice(0, 8)}`;
    const withEnv = await service.createDefinition(f.actor, {
      document: document(slug2, { env: [{ name: "TOKEN", required: true }] }),
    });
    const envFiles = await service.createLogin(f.actor, { name: slug2, definitionId: withEnv.id });
    await expect(
      sessions.startLogin(f.actor, { ...newAccountAndInstance(f), credentialId: envFiles.id }),
    ).rejects.toMatchObject({ data: { code: "credential.login_requires_upload" } });
    // Nothing was left behind by the refused start.
    expect(await db.inspect.credentialLoginSession.count({ where: { userId: f.ownerId } })).toBe(0);
    expect(
      await db.inspect.credentialInstance.count({ where: { credentialId: envFiles.id } }),
    ).toBe(0);
  });

  it("LOGIN binding: READY makes the lease ACTIVE with a LOGIN binding and residue, baseSeq null for an EMPTY instance", async () => {
    const f = await fixture();
    const s = await readyLogin(f);
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandboxId } })).state).toBe(
      "READY",
    );
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "READY" });
    const lease = await leaseRow(s.leaseId);
    expect(lease).toMatchObject({ state: "ACTIVE", baseSeq: null, hostId: f.host.id });
    const binding = await db.inspect.credentialBinding.findUniqueOrThrow({
      where: { id: lease.currentBindingId! },
    });
    expect(binding).toMatchObject({
      purpose: "LOGIN",
      leaseId: s.leaseId,
      hostId: f.host.id,
      baseSeq: null,
      closedAt: null,
    });
    const residue = await db.inspect.credentialResidue.findUniqueOrThrow({
      where: { bindingId: binding.id },
    });
    expect(residue).toMatchObject({ paths: [DIR], recoverable: true, clearedAt: null });
    expect(await sessions.getLoginSession(f.actor, { id: s.sessionId })).toMatchObject({
      state: "READY",
      sandboxId: s.sandboxId,
      login: { hasVerifyCommand: true },
    });
  });

  it("initial save: free captures kind login → instance READY, lease RELEASED, session SAVED → only then destroy with skip", async () => {
    const f = await fixture();
    const s = await readyLogin(f);
    const op = await finish(f, s.sessionId, s.sandboxId);
    const lease = await leaseRow(s.leaseId);
    expect(lease).toMatchObject({ state: "RELEASING", teardownOperationId: op.id });
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
      expect.objectContaining({
        leaseId: s.leaseId,
        bindingId: lease.currentBindingId,
        kind: "login",
        action: "none",
      }),
    ]);
    const held = {
      leaseId: s.leaseId,
      bindingId: lease.currentBindingId!,
      instanceId: s.instanceId,
    };
    const { captureId, ack } = await loginCapture(f, s.sandboxId, held, { captureSeq: 1 });
    expect(ack).toEqual({ outcome: "committed" });
    expect(await instanceRow(s.instanceId)).toMatchObject({
      state: "READY",
      currentSeq: 1,
      activeLeases: 0,
      loginLeaseId: null,
    });
    expect(await leaseRow(s.leaseId)).toMatchObject({
      state: "RELEASED",
      endReason: "login_saved",
    });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "SAVED" });
    const version = await db.inspect.credentialSecretVersion.findUniqueOrThrow({
      where: { instanceId_storageSeq: { instanceId: s.instanceId, storageSeq: 1 } },
      select: { kind: true, sourceLeaseId: true },
    });
    expect(version).toEqual({ kind: "LOGIN", sourceLeaseId: s.leaseId });
    // The free is still in flight: no destroy yet.
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: s.sandboxId, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
    await report(f, op.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [
        {
          leaseId: s.leaseId,
          bindingId: held.bindingId,
          capture: { status: "acked", captureId, outcome: "committed" },
          scrub: "not_run",
        },
      ],
    });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: s.sandboxId, kind: "KILL_SANDBOX" },
    });
    expect(kill.idempotencyKey).toBe(`login-saved-${s.sessionId}`);
    const killEvent = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { payload: { path: ["operationId"], equals: kill.id } },
    });
    expect(killEvent.payload).toMatchObject({ credentialCapture: "skip" });
    expect(
      await db.inspect.credentialEvent.findMany({
        where: { leaseId: s.leaseId, type: "login_saved" },
        select: { storageSeq: true },
      }),
    ).toEqual([{ storageSeq: 1 }]);
    // The saved instance is now claimable by a workload.
    const workload = await createSandbox(f.actor, {
      template: `revision/${f.template.id}`,
      sandboxHostId: f.host.id,
      idempotencyKey: `create-${randomUUID()}`,
      credentials: [{ credentialId: f.login.id, instanceId: s.instanceId }],
    });
    expect(
      await db.inspect.credentialLease.count({
        where: { sandboxId: workload.id, instanceId: s.instanceId, state: "RESERVED" },
      }),
    ).toBe(1);
  });

  it("an incomplete login capture fails the session, re-arms the lease and keeps the sandbox for a retry", async () => {
    const f = await fixture();
    const s = await readyLogin(f);
    const op = await finish(f, s.sessionId, s.sandboxId);
    const bindingId = (await leaseRow(s.leaseId)).currentBindingId!;
    const held = { leaseId: s.leaseId, bindingId, instanceId: s.instanceId };
    const first = await loginCapture(f, s.sandboxId, held, {
      captureSeq: 1,
      missingRequired: true,
    });
    expect(first.ack).toEqual({ outcome: "discarded", reason: "incomplete" });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "FAILED" });
    await report(f, op.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [
        {
          leaseId: s.leaseId,
          bindingId,
          capture: { status: "acked", captureId: first.captureId, outcome: "discarded" },
          scrub: "not_run",
        },
      ],
    });
    expect(await leaseRow(s.leaseId)).toMatchObject({ state: "ACTIVE", teardownOperationId: null });
    expect(await instanceRow(s.instanceId)).toMatchObject({
      state: "EMPTY",
      loginLeaseId: s.leaseId,
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: s.sandboxId, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
    // Retry from FAILED with the same open binding.
    const retry = await finish(f, s.sessionId, s.sandboxId);
    const second = await loginCapture(f, s.sandboxId, held, { captureSeq: 2 });
    expect(second.ack).toEqual({ outcome: "committed" });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "SAVED" });
    expect(await instanceRow(s.instanceId)).toMatchObject({ state: "READY", loginLeaseId: null });
    await report(f, retry.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [
        {
          leaseId: s.leaseId,
          bindingId,
          capture: { status: "acked", captureId: second.captureId, outcome: "committed" },
          scrub: "not_run",
        },
      ],
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: s.sandboxId, kind: "KILL_SANDBOX" },
      }),
    ).toBe(1);
  });

  it("a late (offline) login commit after the free finished saves and destroys", async () => {
    const f = await fixture();
    const s = await readyLogin(f);
    const op = await finish(f, s.sessionId, s.sandboxId);
    const bindingId = (await leaseRow(s.leaseId)).currentBindingId!;
    const captureId = `cap-${randomUUID().slice(0, 12)}`;
    await report(f, op.id, "succeeded", {
      state: "freed",
      credentialOutcomes: [
        {
          leaseId: s.leaseId,
          bindingId,
          capture: { status: "durable", captureId },
          scrub: "not_run",
        },
      ],
    });
    // Durable: the lease waits for the envelope.
    expect(await leaseRow(s.leaseId)).toMatchObject({ state: "RELEASING" });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "SAVING" });
    const late = await loginCapture(
      f,
      s.sandboxId,
      { leaseId: s.leaseId, bindingId, instanceId: s.instanceId },
      { captureSeq: 1 },
    );
    expect(late.ack).toEqual({ outcome: "committed" });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "SAVED" });
    expect(
      await db.inspect.sandboxOperation.count({
        where: {
          sandboxId: s.sandboxId,
          kind: "KILL_SANDBOX",
          idempotencyKey: `login-saved-${s.sessionId}`,
        },
      }),
    ).toBe(1);
  });

  it("re-login of a READY instance: baseSeq = currentSeq; a commit supersedes it, env carried over", async () => {
    const f = await fixture();
    const first = await readyLogin(f);
    await finish(f, first.sessionId, first.sandboxId);
    const bindingId = (await leaseRow(first.leaseId)).currentBindingId!;
    await loginCapture(
      f,
      first.sandboxId,
      { leaseId: first.leaseId, bindingId, instanceId: first.instanceId },
      { captureSeq: 1 },
    );
    const instance = await db.inspect.credentialInstance.findUniqueOrThrow({
      where: { id: first.instanceId },
      select: { accountId: true },
    });
    const again = await readyLogin(f, {
      credentialId: f.login.id,
      accountId: instance.accountId,
      instanceId: first.instanceId,
      sandboxHostId: f.host.id,
      template: `revision/${f.template.id}`,
    } as never);
    expect(await leaseRow(again.leaseId)).toMatchObject({ state: "ACTIVE", baseSeq: 1 });
    await finish(f, again.sessionId, again.sandboxId);
    const b2 = (await leaseRow(again.leaseId)).currentBindingId!;
    const { ack } = await loginCapture(
      f,
      again.sandboxId,
      { leaseId: again.leaseId, bindingId: b2, instanceId: first.instanceId },
      { captureSeq: 1, token: "relogin" },
    );
    expect(ack).toEqual({ outcome: "committed" });
    expect(await instanceRow(first.instanceId)).toMatchObject({ currentSeq: 2, state: "READY" });
  });

  it("cancel destroys the sandbox with skip; the LOGIN lease is ABANDONED and the instance freed", async () => {
    const f = await fixture();
    const s = await readyLogin(f);
    const cancelled = await sessions.cancelLogin(f.actor, { id: s.sessionId });
    expect(cancelled).toMatchObject({ state: "CANCELLED" });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: s.sandboxId, kind: "KILL_SANDBOX" },
    });
    expect(kill.idempotencyKey).toBe(`login-cancel-${s.sessionId}`);
    expect(await leaseRow(s.leaseId)).toMatchObject({
      state: "ABANDONED",
      endReason: "login_ended",
    });
    expect(await instanceRow(s.instanceId)).toMatchObject({ activeLeases: 0, loginLeaseId: null });
    expect(await sessionRow(s.sessionId)).toMatchObject({ state: "CANCELLED" });
    await expect(sessions.finishLogin(f.actor, { id: s.sessionId })).rejects.toMatchObject({
      data: { code: "credential.login_state" },
    });
    // Repeating the cancel is harmless.
    await sessions.cancelLogin(f.actor, { id: s.sessionId });
    // The freed instance can be logged into again.
    const instance = await db.inspect.credentialInstance.findUniqueOrThrow({
      where: { id: s.instanceId },
      select: { accountId: true },
    });
    await sessions.startLogin(f.actor, {
      credentialId: f.login.id,
      accountId: instance.accountId,
      instanceId: s.instanceId,
      sandboxHostId: f.host.id,
      template: `revision/${f.template.id}`,
    } as never);
  });

  it("concurrent logins on the same instance: exactly one claims it, the other is refused busy and leaves nothing", async () => {
    const f = await fixture();
    const account = await service.createAccount(f.actor, { credentialId: f.login.id });
    const instance = await service.createInstance(f.actor, {
      credentialId: f.login.id,
      accountId: account.id,
    });
    const input = {
      credentialId: f.login.id,
      accountId: account.id,
      instanceId: instance.id,
      sandboxHostId: f.host.id,
      template: `revision/${f.template.id}`,
    } as never;
    const results = await Promise.allSettled([
      sessions.startLogin(f.actor, input),
      sessions.startLogin(f.actor, input),
    ]);
    const ok = results.filter((r) => r.status === "fulfilled");
    const refused = results.filter((r) => r.status === "rejected");
    expect(ok).toHaveLength(1);
    expect(refused).toHaveLength(1);
    expect((refused[0] as PromiseRejectedResult).reason).toMatchObject({
      data: { code: "credential.busy" },
    });
    expect(await instanceRow(instance.id)).toMatchObject({ activeLeases: 1 });
    expect(
      await db.inspect.credentialLease.count({
        where: { instanceId: instance.id, kind: "LOGIN" },
      }),
    ).toBe(1);
    expect(await db.inspect.credentialLoginSession.count({ where: { userId: f.ownerId } })).toBe(1);
    expect(
      await db.inspect.sandbox.count({ where: { userId: f.ownerId, purpose: "CREDENTIAL_LOGIN" } }),
    ).toBe(1);
  });

  it("login vs workload claim on one instance: whichever claims first holds it", async () => {
    const f = await fixture();
    const account = await service.createAccount(f.actor, { credentialId: f.login.id });
    const instance = await service.createInstance(f.actor, {
      credentialId: f.login.id,
      accountId: account.id,
    });
    await service.writeValue(f.actor, {
      credentialId: f.login.id,
      instanceId: instance.id,
      files: [
        { path: DIR, kind: "dir" },
        { path: `${DIR}/token`, contentBase64: Buffer.from("t").toString("base64") },
      ],
    });
    const results = await Promise.allSettled([
      sessions.startLogin(f.actor, {
        credentialId: f.login.id,
        accountId: account.id,
        instanceId: instance.id,
        sandboxHostId: f.host.id,
        template: `revision/${f.template.id}`,
      } as never),
      createSandbox(f.actor, {
        template: `revision/${f.template.id}`,
        sandboxHostId: f.host.id,
        idempotencyKey: `create-${randomUUID()}`,
        credentials: [{ credentialId: f.login.id, instanceId: instance.id }],
      }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const refused = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(["credential.busy", "credential.in_use"]).toContain(refused.reason?.data?.code);
    expect(await instanceRow(instance.id)).toMatchObject({ activeLeases: 1 });
  });

  it("the LOGIN claim passes the claim gate: drain mode switched on after the pre-checks refuses the start and leaves nothing", async () => {
    const f = await fixture();
    const account = await service.createAccount(f.actor, { credentialId: f.login.id });
    const instance = await service.createInstance(f.actor, {
      credentialId: f.login.id,
      accountId: account.id,
    });
    // Parked inside the create transaction, after placement and the
    // pre-checks, right before the flow's rows (and its LOGIN claim).
    const gate = db.pauseAt("login", { before: "credentialInstance.findFirst" });
    const started = db
      .run("login", () =>
        sessions.startLogin(f.actor, {
          credentialId: f.login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxHostId: f.host.id,
          template: `revision/${f.template.id}`,
        } as never),
      )
      .catch((error: unknown) => error);
    await gate.waitReached();
    process.env.CREDENTIALS_ENABLED = "false";
    try {
      gate.release();
      expect(await started).toMatchObject({ data: { code: "credential.unavailable" } });
    } finally {
      process.env.CREDENTIALS_ENABLED = "true";
    }
    expect(await instanceRow(instance.id)).toMatchObject({ activeLeases: 0, loginLeaseId: null });
    expect(await db.inspect.credentialLease.count({ where: { instanceId: instance.id } })).toBe(0);
    expect(await db.inspect.credentialLoginSession.count({ where: { userId: f.ownerId } })).toBe(0);
    expect(
      await db.inspect.sandbox.count({ where: { userId: f.ownerId, purpose: "CREDENTIAL_LOGIN" } }),
    ).toBe(0);
  });

  it("≤ 2 open login sessions per owner", async () => {
    const f = await fixture();
    await sessions.startLogin(f.actor, newAccountAndInstance(f));
    await sessions.startLogin(f.actor, newAccountAndInstance(f));
    await expect(sessions.startLogin(f.actor, newAccountAndInstance(f))).rejects.toMatchObject({
      data: { code: "credential.limit_reached" },
    });
    expect(
      (await sessions.listLoginSessions(f.actor, { limit: 10, open: true })).items,
    ).toHaveLength(2);
  });
});
