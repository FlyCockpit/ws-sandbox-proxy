/**
 * Restore admission on real PostgreSQL: a restore of an OFFLOADED sandbox through the reconnect
 * service (`operationTransaction` → `acceptRestore` → `placeRestore`), its
 * durable wait (restart, concurrent passes, cancel, generation change,
 * revoked key, deadline), the config rebind and egress copy, the stop
 * refusal, and current-host authority after a dashboard override (V1).
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "restore-wait-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
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
import { checkAcceptedDispatchAuthority } from "../../lib/sdk-key-access";
import type { Principal } from "../contracts";
import { loadExecutionConfig } from "../execution-config";
import { leaseNow } from "../lease";
import { cancelAction } from "../process-controls";
import {
  createSandbox,
  getSandbox,
  reconnectSandbox,
  runCommand,
  stopSandbox,
} from "../services/sandboxes";
import { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } from "../testing/offload-fixtures";
import { allOwnedPoolKey, poolFixture, poolKey } from "../testing/pool-fixtures";
import { placeRestore, runRestoreWaitPass } from "./restore-admit";

const db = await pgTestDatabase();
afterAll(() => db.close());

const ENV = {
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
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

type Fixture = Awaited<ReturnType<typeof poolFixture>>;

/** Both fixture hosts offload-capable; `room` false refuses new roots there. */
async function hosts(f: Fixture, room: { one: boolean; two: boolean }) {
  for (const [host, ok] of [
    [f.host, room.one],
    [f.other, room.two],
  ] as const) {
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: {
        daemonFeatures: { ...OFFLOAD_HOST_FEATURES, egressOpen: true },
        daemonDiskOffload: true,
      },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: host.id },
      data: { newRootsAllowed: ok },
    });
  }
}

/** A sandbox created by `creator` directly on host one, then offloaded. */
async function offloaded(f: Fixture, creator: Principal = f.owner) {
  await hosts(f, { one: true, two: true });
  const created = await createSandbox(creator, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await offloadSandboxForTest(db.inspect, {
    userId: f.id,
    sandboxId: created.id,
    hostId: f.host.id,
  });
  return created.id;
}

const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
const op = (id: string) => db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } });
const wait = (operationId: string) =>
  db.inspect.sandboxRestoreWait.findUniqueOrThrow({ where: { operationId } });
const restore = (owner: Principal, id: string, extra: Record<string, unknown> = {}) =>
  reconnectSandbox(owner, { id, idempotencyKey: randomUUID(), ...extra }, leaseNow);
const pass = () => runRestoreWaitPass(leaseNow);
const code = (error: unknown) =>
  (error as { data?: { code?: string } }).data?.code ?? (error as { code?: string }).code;

describe("restore admission (§8.3)", () => {
  it("places at once: NEW_ROOT + restoreOffloadId, a new placement, PROVISIONING", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    const before = await row(id);
    const accepted = await restore(f.owner, id);
    const operation = await op(accepted.operationId);
    expect(operation).toMatchObject({
      kind: "RECONNECT_SANDBOX",
      launchMode: "NEW_ROOT",
      restoreOffloadId: before.diskOffloadId,
      generation: before.generation + 1,
    });
    expect(operation.digestContext).toMatchObject({
      domain: "restore-intent:v1",
      generation: before.generation,
    });
    const after = await row(id);
    expect(after).toMatchObject({
      state: "PROVISIONING",
      generation: before.generation + 1,
      originHostId: f.host.id,
      diskOffloadId: before.diskOffloadId,
    });
    const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { operationId: accepted.operationId },
    });
    expect(placement).toMatchObject({
      generation: before.generation + 1,
      restoreOffloadId: before.diskOffloadId,
      kind: "DIRECT",
    });
    expect(after.currentPlacementId).toBe(placement.id);
    expect(await db.inspect.sandboxRestoreWait.count({ where: { sandboxId: id } })).toBe(0);
    // §8.5: binding verifies on the target, ack reset, egress unchanged, no
    // CREATE written, origin history unchanged.
    const config = await db.prisma.$transaction((tx) => loadExecutionConfig(tx, id, f.id));
    expect(config).toMatchObject({ hostId: placement.originHostId, acknowledgedEpoch: null });
    expect(after.egressPolicyHash).toBe(before.egressPolicyHash);
    expect(after.egressPolicy).toEqual(before.egressPolicy);
    expect(
      await db.inspect.sandboxOperation.count({ where: { sandboxId: id, kind: "CREATE_SANDBOX" } }),
    ).toBe(1);
    // A same-key replay after placement returns the same receipt.
    const key = randomUUID();
    const g = await poolFixture(db);
    const other = await offloaded(g);
    const first = await reconnectSandbox(g.owner, { id: other, idempotencyKey: key }, leaseNow);
    const again = await reconnectSandbox(g.owner, { id: other, idempotencyKey: key }, leaseNow);
    expect(again.operationId).toBe(first.operationId);
  });

  it("restores onto the other host when the hint names it (config rebound there)", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    const accepted = await restore(f.owner, id, { sandboxHostId: f.other.id });
    const after = await row(id);
    expect(after).toMatchObject({ sandboxHostId: f.other.id, originHostId: f.host.id });
    const config = await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
      where: { sandboxId: id },
    });
    expect(config).toMatchObject({ hostId: f.other.id, acknowledgedEpoch: null });
    expect(config.generation).toBe(after.generation);
    expect((await op(accepted.operationId)).state).toBe("QUEUED");
  });

  it("no capacity and no wait → restore_no_allowed_host; the sandbox stays OFFLOADED", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    await hosts(f, { one: false, two: false });
    await expect(restore(f.owner, id)).rejects.toSatisfy(
      (error) => code(error) === "restore_no_allowed_host",
    );
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  it("an owner stop while restoring is refused sandbox.restoring (409)", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    await restore(f.owner, id);
    await expect(stopSandbox(f.owner, { id, idempotencyKey: randomUUID() })).rejects.toSatisfy(
      (error) => code(error) === "sandbox.restoring",
    );
  });
});

describe("durable restore wait (§8.3c)", () => {
  async function waiting(f: Fixture, owner: Principal = f.owner) {
    const id = await offloaded(f, owner);
    await hosts(f, { one: false, two: false });
    const accepted = await restore(owner, id, { waitForCapacityMs: 60_000 });
    expect((await op(accepted.operationId)).state).toBe("QUEUED");
    expect(await wait(accepted.operationId)).toMatchObject({ state: "WAITING" });
    expect((await row(id)).state).toBe("OFFLOADED");
    return { id, operationId: accepted.operationId };
  }

  it("a fresh pass after capacity returns places exactly once, under the original operation", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    await pass(); // a restarted process: still no room
    expect((await wait(operationId)).state).toBe("WAITING");
    await hosts(f, { one: true, two: true });
    await pass();
    expect(await wait(operationId)).toMatchObject({ state: "PLACED", intent: null });
    expect((await row(id)).state).toBe("PROVISIONING");
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: id, kind: "RECONNECT_SANDBOX" },
      }),
    ).toBe(1);
    expect(await db.inspect.sandboxPlacement.count({ where: { operationId } })).toBe(1);
    await pass();
    expect(await db.inspect.sandboxPlacement.count({ where: { sandboxId: id } })).toBe(2);
  });

  it("two concurrent passes over the same row place once", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    await hosts(f, { one: true, two: true });
    await Promise.all([pass(), pass()]);
    expect(await db.inspect.sandboxPlacement.count({ where: { operationId } })).toBe(1);
    expect((await row(id)).state).toBe("PROVISIONING");
  });

  it("cancel while waiting ends the wait CANCELLED and the operation cancelled", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    await cancelAction(f.owner, { operationId, idempotencyKey: randomUUID() });
    expect(await wait(operationId)).toMatchObject({ state: "CANCELLED", intent: null });
    expect((await op(operationId)).state).toBe("CANCELLED");
    await hosts(f, { one: true, two: true });
    await pass();
    expect(await db.inspect.sandboxPlacement.count({ where: { operationId } })).toBe(0);
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  it("a generation change while waiting fails the operation state_conflict", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    await db.inspect.sandbox.update({ where: { id }, data: { generation: { increment: 1 } } });
    await hosts(f, { one: true, two: true });
    await pass();
    expect(await wait(operationId)).toMatchObject({ state: "CANCELLED", intent: null });
    expect(await op(operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "state_conflict",
    });
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  it("a key revoked while waiting fails the operation credential_inactive", async () => {
    const f = await poolFixture(db);
    const key = await allOwnedPoolKey(f);
    const { id, operationId } = await waiting(f, key.principal);
    await db.inspect.sdkKey.update({
      where: { id: key.principal.keyId },
      data: { revokedAt: new Date() },
    });
    await hosts(f, { one: true, two: true });
    await pass();
    expect(await op(operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "credential_inactive",
    });
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  it("the deadline ends the wait TIMED_OUT with restore_no_allowed_host, intent scrubbed", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    const past = new Date(Date.now() - 60_000);
    await db.inspect.sandboxRestoreWait.update({
      where: { operationId },
      data: { enqueuedAt: new Date(past.getTime() - 1000), deadlineAt: past },
    });
    await pass();
    expect(await wait(operationId)).toMatchObject({
      state: "TIMED_OUT",
      intent: null,
      endReason: "restore_no_allowed_host",
    });
    expect(await op(operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "restore_no_allowed_host",
    });
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  it("the deadline ends with the latest pass's transient login refusal; a no-room pass clears it", async () => {
    const f = await poolFixture(db);
    const { id, operationId } = await waiting(f);
    await db.inspect.sandboxRestoreWait.update({
      where: { operationId },
      data: { lastLoginRefusal: "credential.in_use" },
    });
    // No host has room: this pass's verdict is capacity, clearing the code.
    await pass();
    expect(await wait(operationId)).toMatchObject({ state: "WAITING", lastLoginRefusal: null });
    const past = new Date(Date.now() - 60_000);
    await db.inspect.sandboxRestoreWait.update({
      where: { operationId },
      data: {
        enqueuedAt: new Date(past.getTime() - 1000),
        deadlineAt: past,
        lastLoginRefusal: "credential.needs_login",
      },
    });
    await pass();
    expect(await wait(operationId)).toMatchObject({
      state: "TIMED_OUT",
      intent: null,
      endReason: "credential.needs_login",
    });
    expect(await op(operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "credential.needs_login",
    });
    expect((await row(id)).state).toBe("OFFLOADED");
  });

  describe("verdicts under the wait-row lock (§8.3c)", () => {
    it("a pass skips a row another evaluation holds: no verdict, no expiry interleaves", async () => {
      const f = await poolFixture(db);
      const { operationId } = await waiting(f);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { lastLoginRefusal: "credential.in_use" },
      });
      const past = new Date(Date.now() - 60_000);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { enqueuedAt: new Date(past.getTime() - 1000), deadlineAt: past },
      });
      await db.inspect.$transaction(
        async (tx) => {
          // Evaluation A holds the (due) row, as `placeRestore` does from
          // its lock to its commit.
          await tx.$queryRaw`SELECT "operationId" FROM sandbox_restore_wait
            WHERE "operationId" = ${operationId} FOR UPDATE`;
          // A concurrent pass (expiry, then evaluation) leaves it alone.
          await pass();
          await tx.sandboxRestoreWait.update({
            where: { operationId },
            data: { lastLoginRefusal: "credential.needs_login" },
          });
        },
        { timeout: 30_000 },
      );
      // Nothing of the concurrent pass landed; A's verdict is what the
      // deadline then reads.
      expect(await wait(operationId)).toMatchObject({
        state: "WAITING",
        lastLoginRefusal: "credential.needs_login",
      });
      await pass();
      expect(await wait(operationId)).toMatchObject({
        state: "TIMED_OUT",
        endReason: "credential.needs_login",
      });
      expect(await op(operationId)).toMatchObject({
        state: "FAILED",
        errorCode: "credential.needs_login",
      });
    });

    it("a no-room evaluation clears a recorded refusal; the deadline then ends restore_no_allowed_host", async () => {
      const f = await poolFixture(db);
      const { operationId } = await waiting(f);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { lastLoginRefusal: "credential.in_use" },
      });
      await pass();
      expect(await wait(operationId)).toMatchObject({ state: "WAITING", lastLoginRefusal: null });
      const past = new Date(Date.now() - 60_000);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { enqueuedAt: new Date(past.getTime() - 1000), deadlineAt: past },
      });
      await pass();
      expect(await op(operationId)).toMatchObject({ errorCode: "restore_no_allowed_host" });
    });

    it("an overdue row is never attempted, even with room; the deadline ends it", async () => {
      const f = await poolFixture(db);
      const { id, operationId } = await waiting(f);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { lastLoginRefusal: "credential.busy" },
      });
      await hosts(f, { one: true, two: true });
      const past = new Date(Date.now() - 60_000);
      await db.inspect.sandboxRestoreWait.update({
        where: { operationId },
        data: { enqueuedAt: new Date(past.getTime() - 1000), deadlineAt: past },
      });
      expect(await db.prisma.$transaction((tx) => placeRestore(tx, operationId, leaseNow))).toBe(
        "skipped",
      );
      expect((await row(id)).state).toBe("OFFLOADED");
      expect(await wait(operationId)).toMatchObject({
        state: "WAITING",
        lastLoginRefusal: "credential.busy",
      });
      await pass();
      expect(await wait(operationId)).toMatchObject({
        state: "TIMED_OUT",
        endReason: "credential.busy",
      });
      expect((await row(id)).state).toBe("OFFLOADED");
    });
  });
});

describe("restore-intent authorization and current-host authority (§8.3b, §5a)", () => {
  it("an SDK key sending overrideCreatorAllowlist is forbidden (unrestricted included)", async () => {
    const f = await poolFixture(db);
    const id = await offloaded(f);
    const key = await allOwnedPoolKey(f);
    await expect(
      restore(key.principal, id, { overrideCreatorAllowlist: true }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("an SDK key restores an OFFLOADED sandbox whose last host it may use", async () => {
    const f = await poolFixture(db);
    const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
    const id = await offloaded(f, key.principal);
    const accepted = await restore(key.principal, id);
    expect((await row(id)).sandboxHostId).toBe(f.host.id);
    expect((await op(accepted.operationId)).launchMode).toBe("NEW_ROOT");
  });

  it("the creating key's allowlist bounds the restore; only the owner may override (V1)", async () => {
    const f = await poolFixture(db);
    const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
    await hosts(f, { one: true, two: true });
    const created = await createSandbox(key.principal, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    const id = created.id;
    const sandbox = await row(id);
    const dispatch = () =>
      db.prisma.$transaction((tx) =>
        checkAcceptedDispatchAuthority(
          {
            ownerId: f.id,
            principal: { kind: "sdkKey", keyId: key.principal.keyId },
            context: {
              sandboxId: id,
              sandboxHostId: sandbox.originHostId,
              templateRevisionId: sandbox.templateRevisionId,
              originPoolId: sandbox.originPoolId,
            },
          },
          tx,
        ),
      );
    // Before any move, work the creating key queued still dispatches.
    expect(await dispatch()).toBe("active");
    await offloadSandboxForTest(db.inspect, { userId: f.id, sandboxId: id, hostId: f.host.id });
    // Host one has no room; host two is outside the creating key's allowlist.
    await hosts(f, { one: false, two: true });
    await expect(restore(f.owner, id)).rejects.toSatisfy(
      (error) => code(error) === "restore_no_allowed_host",
    );
    await restore(f.owner, id, { overrideCreatorAllowlist: true });
    expect((await row(id)).sandboxHostId).toBe(f.other.id);
    // Use needs the current host: exec, reconnect and dispatch refuse.
    await expect(
      runCommand(key.principal, { id, idempotencyKey: randomUUID(), argv: ["true"] }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(restore(key.principal, id)).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(await dispatch()).toBe("inactive");
    // History reads are retained.
    await expect(getSandbox(key.principal, { id })).resolves.toMatchObject({ id });
  });

  it("an ALL_OWNED + ALL_USABLE key keeps access after the same move (control)", async () => {
    const f = await poolFixture(db);
    const key = await allOwnedPoolKey(f);
    const id = await offloaded(f, key.principal);
    await restore(f.owner, id, { sandboxHostId: f.other.id, overrideCreatorAllowlist: true });
    await expect(getSandbox(key.principal, { id })).resolves.toMatchObject({ id });
    await expect(
      runCommand(key.principal, { id, idempotencyKey: randomUUID(), argv: ["true"] }),
    ).rejects.toSatisfy((error) => code(error) !== "FORBIDDEN");
  });
});
