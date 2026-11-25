/**
 * Restore of a sandbox with CLI logins on real PostgreSQL: the restore claims its attached logins on the target
 * exactly as a cold reconnect does (lease, launch spec, dispatch reference);
 * foreign targets are excluded for login history and for a login without
 * foreign opt-in; pins must name attached logins; an unresolved earlier
 * capture refuses the restore `credential.pending_drain`.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "restore-admit-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("../budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import * as credentials from "../../credentials/service";
import { dataRootKey } from "../../crypto/data-key";
import type { Principal } from "../contracts";
import { releaseLiveResourcesOnInventoryProof } from "../host-admission";
import { leaseNow } from "../lease";
import { lockHostByEpoch } from "../relay-fence";
import { createSandbox, reconnectSandbox } from "../services/sandboxes";
import {
  OFFLOAD_HOST_FEATURES,
  offloadSandboxForTest,
  seedStoredOffload,
} from "../testing/offload-fixtures";
import { poolFixture } from "../testing/pool-fixtures";
import { seedLaunchHost, seedTemplateRevision } from "../testing/resource-fixtures";
import { loginStateSettled } from "./eligibility";
import { deriveDiskWrapKeys } from "./keys";
import { runRestoreWaitPass } from "./restore-admit";
import { exitRestoreAttempt } from "./restore-exit";

const db = await pgTestDatabase();
afterAll(() => db.close());

// One root for the credential vault and the offload fixtures' key wraps.
const ROOT_HEX = randomBytes(32).toString("hex");
const KEYS = deriveDiskWrapKeys({ current: dataRootKey(ROOT_HEX), previous: null });
const ENV = {
  DATA_ENCRYPTION_KEY: ROOT_HEX,
  CREDENTIALS_ENABLED: "true",
  IMAGE_S3_BUCKET: "b",
  IMAGE_S3_ENDPOINT: "http://127.0.0.1:9",
  IMAGE_S3_ACCESS_KEY_ID: "a",
  IMAGE_S3_SECRET_ACCESS_KEY: "s",
};
const saved: Record<string, string | undefined> = {};
beforeAll(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

/** A current daemon: offload, egress and the CLI-login capability. */
const FEATURES = {
  ...OFFLOAD_HOST_FEATURES,
  egressOpen: true,
  credentials: {
    files: true,
    env: true,
    proxy: false,
    sealedReturn: true,
    checkpoint: true,
    specTransfer: true,
    maxBundleBytes: 4_823_129,
    returnKeyEpoch: 0,
  },
};

type Fixture = Awaited<ReturnType<typeof poolFixture>>;

async function capable(hostIds: readonly string[]) {
  for (const id of hostIds) {
    await db.inspect.sandboxHost.update({
      where: { id },
      data: { daemonFeatures: FEATURES, daemonDiskOffload: true },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: id },
      data: { newRootsAllowed: true },
    });
  }
}

/** A login of `owner` with one READY instance holding a real value. */
async function login(owner: Principal) {
  const slug = `tool-${randomUUID().slice(0, 8)}`;
  const path = `.config/${slug}`;
  const definition = await credentials.createDefinition(owner, {
    document: {
      schemaVersion: 1,
      id: slug,
      displayName: "Tool",
      login: { command: "tool login", method: "device-code" },
      credentials: {
        files: { required: [path], optional: [], exclude: [] },
        sharing: "exclusive",
      },
    },
  });
  const created = await credentials.createLogin(owner, { name: slug, definitionId: definition.id });
  const account = await credentials.createAccount(owner, { credentialId: created.id });
  const instance = await credentials.createInstance(owner, {
    credentialId: created.id,
    accountId: account.id,
  });
  await credentials.writeValue(owner, {
    credentialId: created.id,
    instanceId: instance.id,
    files: [
      { path, kind: "dir" as const },
      { path: `${path}/token`, contentBase64: Buffer.from("v").toString("base64") },
    ],
  });
  return { credentialId: created.id, accountId: account.id, instanceId: instance.id };
}

async function attach(
  ownerId: string,
  sandboxId: string,
  l: Awaited<ReturnType<typeof login>>,
): Promise<void> {
  await db.inspect.sandboxCredential.create({
    data: {
      sandboxId,
      userId: ownerId,
      credentialId: l.credentialId,
      accountId: l.accountId,
      instanceId: l.instanceId,
    },
  });
}

/** A sandbox `owner` created (direct on host one, or in `poolId`), offloaded. */
async function offloaded(
  ownerId: string,
  owner: Principal,
  input: { sandboxHostId: string } | { poolId: string; template: string },
  hostId: string,
  lease: { timeoutMs?: number; lifecycle?: { onTimeout: "stop" | "kill" } } = {},
) {
  const created = await createSandbox(owner, {
    template: "base",
    ...input,
    ...lease,
    idempotencyKey: randomUUID(),
  });
  await offloadSandboxForTest(db.inspect, {
    userId: ownerId,
    sandboxId: created.id,
    hostId,
    keys: KEYS,
  });
  return created.id;
}

const restore = (owner: Principal, id: string, extra: Record<string, unknown> = {}) =>
  reconnectSandbox(owner, { id, idempotencyKey: randomUUID(), ...extra }, leaseNow);
const code = (error: unknown) =>
  (error as { data?: { code?: string } }).data?.code ?? (error as { code?: string }).code;

/** A grantee who places in `f`'s pool through a share: every member is foreign to it. */
async function grantee(f: Fixture) {
  await db.inspect.sandboxPoolMember.updateMany({
    where: { sandboxHostId: f.other.id },
    data: { enabled: false },
  });
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Grantee",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  await db.inspect.share.create({
    data: { poolId: f.pool.id, ownerUserId: f.id, granteeUserId: id },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: f.host.id,
      slug: "foreign",
      label: "Private revision",
      incusFingerprint: f.revision.incusFingerprint,
    },
  });
  const owner = { kind: "session" as const, ownerId: id };
  return { id, owner, template: `revision/${revision.id}` };
}

describe("restore with CLI logins (§4 safeguard 2)", () => {
  it("an attached login is claimed on the own target host, with a launch spec", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
    const l = await login(f.owner);
    await attach(f.id, id, l);
    await db.inspect.sandbox.update({ where: { id }, data: { credentialFilesEver: true } });
    const accepted = await restore(f.owner, id);
    const after = await db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
    expect(after.state).toBe("PROVISIONING");
    expect([f.host.id, f.other.id]).toContain(after.sandboxHostId);
    const lease = await db.inspect.credentialLease.findFirstOrThrow({
      where: { sandboxId: id, credentialId: l.credentialId },
    });
    expect(lease).toMatchObject({
      state: "RESERVED",
      operationId: accepted.operationId,
      hostId: after.sandboxHostId,
      instanceId: l.instanceId,
    });
    expect(
      await db.inspect.credentialOperationSpec.count({
        where: { operationId: accepted.operationId },
      }),
    ).toBe(1);
    const outbox = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: id, eventType: "sandbox.reconnect_requested" },
      orderBy: { createdAt: "desc" },
    });
    expect((outbox.payload as { credentialSpec?: unknown }).credentialSpec).toMatchObject({
      digest: expect.any(String),
    });
    // The attempt ends without READY on a no-effect proof (§8.7): its claim
    // settles with the detach and the spec goes; the next restore claims anew.
    const exited = await db.prisma.$transaction((tx) =>
      exitRestoreAttempt(tx, {
        sandboxId: id,
        userId: f.id,
        attemptOperationId: accepted.operationId,
        attemptGeneration: after.generation,
        proof: { kind: "no_effect", reason: "never_dispatched" },
      }),
    );
    expect(exited).toBe(true);
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).state).toBe("OFFLOADED");
    expect(
      await db.inspect.credentialLease.findUniqueOrThrow({ where: { id: lease.id } }),
    ).toMatchObject({ state: "ABANDONED" });
    expect(
      await db.inspect.credentialOperationSpec.count({
        where: { operationId: accepted.operationId },
      }),
    ).toBe(0);
    const again = await restore(f.owner, id);
    expect(
      await db.inspect.credentialLease.count({
        where: { sandboxId: id, operationId: again.operationId, state: "RESERVED" },
      }),
    ).toBe(1);
  });

  it("a pin naming a login that is not attached is refused credential.not_attached", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
    const l = await login(f.owner);
    await expect(
      restore(f.owner, id, { credentials: [{ credentialId: l.credentialId }] }),
    ).rejects.toSatisfy((error) => code(error) === "credential.not_attached");
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).state).toBe("OFFLOADED");
  });

  it("a lease still RELEASING refuses the restore credential.pending_drain", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
    const l = await login(f.owner);
    await attach(f.id, id, l);
    await db.inspect.credentialLease.create({
      data: {
        userId: f.id,
        credentialId: l.credentialId,
        accountId: l.accountId,
        instanceId: l.instanceId,
        sandboxId: id,
        operationId: "op-old",
        kind: "WORKLOAD",
        exclusive: true,
        state: "RELEASING",
        hostId: f.host.id,
      },
    });
    await expect(restore(f.owner, id)).rejects.toSatisfy(
      (error) => code(error) === "credential.pending_drain",
    );
  });

  it("foreign pool members are excluded for login history and for a login without opt-in", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const g = await grantee(f);
    const input = { poolId: f.pool.id, template: g.template };
    // Control: without logins the grantee restores onto the foreign member.
    const plain = await offloaded(g.id, g.owner, input, f.host.id);
    await restore(g.owner, plain);
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: plain } })).state).toBe(
      "PROVISIONING",
    );
    // Login history (`credentialFilesEver`): own hosts only.
    const history = await offloaded(g.id, g.owner, input, f.host.id);
    await db.inspect.sandbox.update({
      where: { id: history },
      data: { credentialFilesEver: true },
    });
    await expect(restore(g.owner, history)).rejects.toSatisfy(
      (error) => code(error) === "restore_no_allowed_host",
    );
    // An attached login without foreign opt-in (no history yet): the claim
    // context excludes the foreign member too.
    const attached = await offloaded(g.id, g.owner, input, f.host.id);
    await attach(g.id, attached, await login(g.owner));
    await expect(restore(g.owner, attached)).rejects.toSatisfy(
      (error) => code(error) === "restore_no_allowed_host",
    );
    for (const sandboxId of [history, attached]) {
      expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).state).toBe(
        "OFFLOADED",
      );
      expect(await db.inspect.credentialLease.count({ where: { sandboxId } })).toBe(0);
    }
  });
});

/**
 * A sandbox created on host one, then STOPPED there with its disk STORED
 * and cached at seq 1 (live hold released; the create settled).
 */
async function cached(f: Fixture) {
  const created = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  const id = created.id;
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: id },
    data: { state: "SUCCEEDED", completedAt: new Date() },
  });
  await db.prisma.$transaction(async (tx) => {
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    await releaseLiveResourcesOnInventoryProof(tx, {
      hostId: f.host.id,
      ownerId: f.id,
      sandboxId: id,
    });
    await tx.sandbox.update({ where: { id }, data: { state: "STOPPED" } });
  });
  const stored = await seedStoredOffload(db.inspect, {
    userId: f.id,
    sandboxId: id,
    hostId: f.host.id,
    keys: KEYS,
  });
  const generation = (await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).generation;
  await db.inspect.sandboxDiskOffload.update({
    where: { id: stored.offloadId },
    data: { sourceGeneration: generation },
  });
  await db.inspect.sandbox.update({
    where: { id },
    data: { diskOffloadId: stored.offloadId, cachedOffloadSeq: 1, offloadSeq: 1 },
  });
  return { id, offloadId: stored.offloadId };
}

const start = (owner: Principal, id: string) =>
  reconnectSandbox(owner, { id, mode: "cold", idempotencyKey: randomUUID() }, leaseNow);

describe("a start of a cached copy its host may not take back (§5 order 3/4, §7)", () => {
  it("online but ineligible: a server evict grant, then sandbox.disk_evicting", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const c = await cached(f);
    await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { draining: true } });
    await expect(start(f.owner, c.id)).rejects.toSatisfy(
      (error) => code(error) === "sandbox.disk_evicting",
    );
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: c.offloadId } }),
    ).toMatchObject({ state: "EVICTING", evictHostId: f.host.id });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: c.id } })).toMatchObject({
      state: "STOPPED",
      sandboxHostId: f.host.id,
    });
  });

  it("offline: the gated STALE detach, then a restore onto another host", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const c = await cached(f);
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED" },
    });
    const accepted = await start(f.owner, c.id);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: c.id } })).toMatchObject({
      state: "PROVISIONING",
      sandboxHostId: f.other.id,
      diskOffloadId: c.offloadId,
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ launchMode: "NEW_ROOT", restoreOffloadId: c.offloadId });
    expect(
      await db.inspect.sandboxDiskCopy.findFirstOrThrow({ where: { sandboxId: c.id } }),
    ).toMatchObject({ hostId: f.host.id, state: "STALE" });
  });

  it("online, its copy refused (disk_stale or a grant left unused): discard, then restore", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const c = await cached(f);
    // The host refused the copy: the result (or the outlived grant) cleared
    // the cached seq. No grant can be issued for it any more.
    await db.inspect.sandbox.update({ where: { id: c.id }, data: { cachedOffloadSeq: null } });
    const accepted = await start(f.owner, c.id);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: c.id } })).toMatchObject({
      state: "PROVISIONING",
      // R9: the host holding the copy row is not a restore target.
      sandboxHostId: f.other.id,
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ launchMode: "NEW_ROOT" });
    expect(
      await db.inspect.sandboxDiskCopy.findFirstOrThrow({ where: { sandboxId: c.id } }),
    ).toMatchObject({ hostId: f.host.id });
    expect(
      (await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: c.offloadId } })).state,
    ).toBe("STORED");
  });

  it("online and eligible with its seq: a cached cold reconnect (no restore)", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const c = await cached(f);
    const accepted = await start(f.owner, c.id);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ launchMode: "COLD", restoreOffloadId: null });
    expect(await db.inspect.sandboxDiskCopy.count({ where: { sandboxId: c.id } })).toBe(0);
  });
});

describe("restore login edges (§8.3c, §4 safeguard 1/2)", () => {
  /** A credentialed OFFLOADED sandbox whose restore waits for room. */
  async function queuedWithLogin(f: Fixture) {
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
    const l = await login(f.owner);
    await attach(f.id, id, l);
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: { in: [f.host.id, f.other.id] } },
      data: { newRootsAllowed: false },
    });
    const accepted = await restore(f.owner, id, { waitForCapacityMs: 60_000 });
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: accepted.operationId },
      }),
    ).toMatchObject({ state: "WAITING" });
    return { id, l, operationId: accepted.operationId };
  }

  it("a queued restore whose login claim fails permanently ends with that login code", async () => {
    const f = await poolFixture(db);
    const q = await queuedWithLogin(f);
    // The login's stored definition no longer matches its pinned digest:
    // no wait cures it.
    const pinned = await db.inspect.credential.findUniqueOrThrow({
      where: { id: q.l.credentialId },
      select: { definitionId: true },
    });
    await db.inspect.credentialDefinition.update({
      where: { id: pinned.definitionId },
      data: { document: { schemaVersion: 1, id: "tampered" } },
    });
    await capable([f.host.id, f.other.id]);
    await runRestoreWaitPass(leaseNow);
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: q.operationId },
      }),
    ).toMatchObject({ state: "FAILED", intent: null, endReason: "credential.definition_corrupt" });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: q.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "credential.definition_corrupt" });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: q.id } })).toMatchObject({
      state: "OFFLOADED",
      sandboxHostId: null,
    });
    expect(await db.inspect.credentialLease.count({ where: { sandboxId: q.id } })).toBe(0);
    expect(await db.inspect.sandboxPlacement.count({ where: { operationId: q.operationId } })).toBe(
      0,
    );
  });

  it("a transient login refusal at the bind keeps the restore waiting, recorded; the deadline ends with it", async () => {
    const f = await poolFixture(db);
    const q = await queuedWithLogin(f);
    await capable([f.host.id, f.other.id]);
    // An earlier lease of the sandbox is still RELEASING at placement
    // (retryable `credential.pending_drain`): the claim is refused, the
    // restore keeps waiting until it drains or the deadline.
    await db.inspect.credentialLease.create({
      data: {
        userId: f.id,
        credentialId: q.l.credentialId,
        accountId: q.l.accountId,
        instanceId: q.l.instanceId,
        sandboxId: q.id,
        operationId: "op-old",
        kind: "WORKLOAD",
        exclusive: true,
        state: "RELEASING",
        hostId: f.host.id,
      },
    });
    const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: q.id } });
    const placements = await db.inspect.sandboxPlacement.count({ where: { sandboxId: q.id } });
    await runRestoreWaitPass(leaseNow);
    // The bind was undone to its savepoint and the refusal recorded on the
    // still-locked row, in the same committed transaction.
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: q.operationId },
      }),
    ).toMatchObject({ state: "WAITING", lastLoginRefusal: "credential.pending_drain" });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: q.operationId } })).state,
    ).toBe("QUEUED");
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: q.id } })).toMatchObject({
      state: "OFFLOADED",
      generation: before.generation,
      currentPlacementId: before.currentPlacementId,
      sandboxHostId: before.sandboxHostId,
    });
    expect(await db.inspect.sandboxPlacement.count({ where: { sandboxId: q.id } })).toBe(
      placements,
    );
    expect(
      await db.inspect.credentialLease.count({
        where: { sandboxId: q.id, operationId: q.operationId },
      }),
    ).toBe(0);
    // The deadline reads the recorded refusal and ends with it.
    const past = new Date(Date.now() - 60_000);
    await db.inspect.sandboxRestoreWait.update({
      where: { operationId: q.operationId },
      data: { enqueuedAt: new Date(past.getTime() - 1000), deadlineAt: past },
    });
    await runRestoreWaitPass(leaseNow);
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: q.operationId },
      }),
    ).toMatchObject({ state: "TIMED_OUT", endReason: "credential.pending_drain" });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: q.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "credential.pending_drain" });
  });

  for (const [state, refusal] of [
    ["RECOVERY_REQUIRED", "credential.recovery_required"],
    ["RECOVERING", "credential.pending_drain"],
  ] as const)
    it(`a ${state} lease: loginStateSettled refuses the offload and the restore claims nothing`, async () => {
      const f = await poolFixture(db);
      await capable([f.host.id, f.other.id]);
      const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
      const l = await login(f.owner);
      await attach(f.id, id, l);
      const lease = await db.inspect.credentialLease.create({
        data: {
          userId: f.id,
          credentialId: l.credentialId,
          accountId: l.accountId,
          instanceId: l.instanceId,
          sandboxId: id,
          operationId: "op-old",
          kind: "WORKLOAD",
          exclusive: true,
          state,
          hostId: f.host.id,
        },
      });
      expect(await db.prisma.$transaction((tx) => loginStateSettled(tx, id))).toBe(false);
      await expect(restore(f.owner, id)).rejects.toSatisfy((error) => code(error) === refusal);
      // Queued too: refused at acceptance, nothing waits.
      await expect(restore(f.owner, id, { waitForCapacityMs: 60_000 })).rejects.toSatisfy(
        (error) => code(error) === refusal,
      );
      expect(await db.inspect.sandboxRestoreWait.count({ where: { sandboxId: id } })).toBe(0);
      expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).toMatchObject({
        state: "OFFLOADED",
        sandboxHostId: null,
      });
      // The lease is untouched: never reused for recovery on a restore target.
      expect(await db.inspect.credentialLease.findMany({ where: { sandboxId: id } })).toEqual([
        expect.objectContaining({ id: lease.id, state, hostId: f.host.id }),
      ]);
      expect(await db.inspect.credentialBinding.count({ where: { leaseId: lease.id } })).toBe(0);
    });
});

/** Review P2: candidate limits never hide an eligible restore host. */
describe("restore candidate paging (§8.3, review)", () => {
  /** Restore-ineligible per candidate (no image fetch), not by SQL. */
  const NO_FETCH = { ...FEATURES, image: { ...FEATURES.image, fetch: false } };

  async function member(f: Fixture, slug: string, id?: string) {
    const host = await seedLaunchHost(db.inspect, {
      data: {
        ...(id ? { id } : {}),
        userId: f.id,
        slug,
        label: slug,
        status: "CONNECTED",
        egressEnforcement: true,
        daemonLeasePolicy: true,
      },
    });
    await db.inspect.sandboxPoolMember.create({
      data: { userId: f.id, hostOwnerId: f.id, poolId: f.pool.id, sandboxHostId: host.id },
    });
    return host;
  }

  async function ineligible(ids: readonly string[]) {
    await capable(ids);
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [...ids] } },
      data: { daemonFeatures: NO_FETCH },
    });
  }

  it("16 ineligible pool hosts ranked first: the restore places on the 17th", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { poolId: f.pool.id, template: "base" }, f.host.id);
    const extra = [];
    for (let i = 0; i < 15; i += 1) extra.push(await member(f, `inel-${i}`));
    const eligible = await member(f, "eligible");
    await capable([eligible.id]);
    await ineligible([f.host.id, f.other.id, ...extra.map((h) => h.id)]);
    // Rank the eligible host last (highest dominant share).
    await db.inspect.sandboxHost.update({
      where: { id: eligible.id },
      data: { memoryReservedMiB: 32_768, vcpuReserved: 32 },
    });
    await restore(f.owner, id, { poolId: f.pool.id });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).toMatchObject({
      state: "PROVISIONING",
      sandboxHostId: eligible.id,
    });
  });

  it("64 ineligible own hosts ahead by id: the restore places on the 65th", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id);
    const extra = [];
    for (let i = 0; i < 62; i += 1)
      extra.push(await member(f, `own-${i}`, `a${String(i).padStart(3, "0")}${randomUUID()}`));
    const eligible = await member(f, "eligible", `z${randomUUID()}`);
    await capable([eligible.id]);
    await ineligible([f.host.id, f.other.id, ...extra.map((h) => h.id)]);
    await restore(f.owner, id);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).toMatchObject({
      state: "PROVISIONING",
      sandboxHostId: eligible.id,
    });
  });
});

describe("a restore without timeoutMs reuses the remembered lease", () => {
  const H2 = 7_200_000;
  const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
  const operation = (id: string) =>
    db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } });

  it("binds the create's lease and expiry action; an explicit lease wins and is remembered", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id, {
      timeoutMs: H2,
      lifecycle: { onTimeout: "stop" },
    });
    const at = new Date(Date.now() + 60_000);
    const accepted = await reconnectSandbox(
      f.owner,
      { id, idempotencyKey: randomUUID() },
      () => at,
    );
    const bound = await row(id);
    expect(bound).toMatchObject({ state: "PROVISIONING", leaseExpireAction: "STOP" });
    expect(bound.leaseExpiresAt?.getTime()).toBe(at.getTime() + H2);
    expect(await operation(accepted.operationId)).toMatchObject({
      leaseTimeoutMs: H2,
      leaseExpireActionAccepted: "STOP",
    });
    // Back to OFFLOADED; an explicit lease replaces the remembered one.
    await db.prisma.$transaction((tx) =>
      exitRestoreAttempt(tx, {
        sandboxId: id,
        userId: f.id,
        attemptOperationId: accepted.operationId,
        attemptGeneration: bound.generation,
        proof: { kind: "no_effect", reason: "never_dispatched" },
      }),
    );
    const explicit = await reconnectSandbox(
      f.owner,
      { id, idempotencyKey: randomUUID(), timeoutMs: 600_000 },
      () => new Date(at.getTime() + 60_000),
    );
    expect(await row(id)).toMatchObject({ leaseExpireAction: "STOP" });
    expect(await operation(explicit.operationId)).toMatchObject({ leaseTimeoutMs: 600_000 });
    const rebound = await row(id);
    await db.prisma.$transaction((tx) =>
      exitRestoreAttempt(tx, {
        sandboxId: id,
        userId: f.id,
        attemptOperationId: explicit.operationId,
        attemptGeneration: rebound.generation,
        proof: { kind: "no_effect", reason: "never_dispatched" },
      }),
    );
    const later = new Date(at.getTime() + 120_000);
    await reconnectSandbox(f.owner, { id, idempotencyKey: randomUUID() }, () => later);
    expect((await row(id)).leaseExpiresAt?.getTime()).toBe(later.getTime() + 600_000);
  });

  it("a queued restore stores the resolved lease and binds it when placed", async () => {
    const f = await poolFixture(db);
    await capable([f.host.id, f.other.id]);
    const id = await offloaded(f.id, f.owner, { sandboxHostId: f.host.id }, f.host.id, {
      timeoutMs: H2,
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: { in: [f.host.id, f.other.id] } },
      data: { newRootsAllowed: false },
    });
    const accepted = await restore(f.owner, id, { waitForCapacityMs: 60_000 });
    expect(
      await db.inspect.sandboxRestoreWait.findUniqueOrThrow({
        where: { operationId: accepted.operationId },
      }),
    ).toMatchObject({ state: "WAITING", intent: { timeoutMs: H2 } });
    await capable([f.host.id, f.other.id]);
    await runRestoreWaitPass(leaseNow);
    expect(await row(id)).toMatchObject({ state: "PROVISIONING", leaseExpireAction: "DESTROY" });
    expect(await operation(accepted.operationId)).toMatchObject({ leaseTimeoutMs: H2 });
  });
});
