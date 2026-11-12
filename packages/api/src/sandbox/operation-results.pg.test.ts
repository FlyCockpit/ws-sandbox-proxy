import { randomUUID } from "node:crypto";
import type { Prisma, SandboxOperationKind } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { encodedJsonBytes, RESULT_LIMITS } from "@wssp/sandbox-contracts";
import { afterAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";

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
const db = await pgTestDatabase();
const { lockOwnerForAdmission, requestAccountDeletion } = await import("@wssp/db/account-deletion");
const {
  reserveOperationResult,
  publishOperationResult,
  releaseTerminalOperationResults,
  getOperationResult,
  storeScalarOperationResult,
  purgeExpiredOperationResults,
  readResultContinuation,
  initialResultFields,
} = await import("./operation-results");
const { assertBeforeResultQuota, resultOutboxLockQuery } = await import("./result-locks");
const { sessionPrincipal } = await import("./contracts");
afterAll(() => db.close());
const entry = {
  name: "x",
  path: "/x",
  type: "file",
  size: 1,
  mode: 0o644,
  permissions: "rw-r--r--",
  uid: 1000,
  gid: 1000,
  owner: null,
  group: null,
  modifiedTime: null,
  symlinkTarget: null,
};
const payload = { type: "file.stat", entry };
const REQUEST_EVENTS: Partial<Record<SandboxOperationKind, [string, Prisma.InputJsonObject]>> = {
  STAT_PATH: ["sandbox.file_stat_requested", { path: "/x" }],
  LIST_DIR: ["sandbox.file_list_requested", { path: "/", depth: 1 }],
  MOVE_PATH: ["sandbox.file_move_requested", { path: "/a", destPath: "/x" }],
  LIST_PROCESSES: ["sandbox.process_list_requested", {}],
};
async function seed(
  kind: SandboxOperationKind = "STAT_PATH",
  ownerId?: string,
  request?: Prisma.InputJsonObject,
) {
  const userId = ownerId ?? randomUUID();
  if (!ownerId)
    await db.inspect.user.create({
      data: { id: userId, name: "Owner", email: `${userId}@example.test` },
    });
  const template = await db.inspect.sandboxTemplate.create({
    data: { userId, slug: randomUUID(), label: "Template" },
  });
  const revision = await db.inspect.sandboxTemplateRevision.create({
    data: {
      userId,
      templateId: template.id,
      revision: 1,
      incusFingerprint: "a".repeat(64),
      architecture: "x86_64",
      manifestDigest: "b".repeat(64),
    },
  });
  const sandbox = await db.inspect.sandbox.create({
    data: {
      hostOwnerId: userId,
      userId,
      templateId: template.id,
      templateRevisionId: revision.id,
      originalSelector: `revision/${revision.id}`,
      originHostId: "deleted-host",
      state: "DELETED",
    },
  });
  const op = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
    },
  });
  const event = REQUEST_EVENTS[kind];
  if (event)
    await db.inspect.outboxEvent.create({
      data: {
        userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        eventType: event[0],
        payload: { ...(request ?? event[1]), operationId: op.id, sandboxId: sandbox.id },
        operationId: op.id,
        // Already dispatched: the request stays as immutable stored arguments.
        processedAt: new Date(),
      },
    });
  return { ownerId: userId, operationId: op.id, sandboxId: sandbox.id };
}
type Fixture = Awaited<ReturnType<typeof seed>>;
/** Production lock hierarchy, before every tested store writer. */
async function locked<T>(f: Fixture, work: (tx: Prisma.TransactionClient) => Promise<T>) {
  return db.prisma.$transaction(
    async (tx) => {
      await lockOwnerForAdmission(tx, f.ownerId);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandboxId} AND "userId" = ${f.ownerId} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.operationId} AND "userId" = ${f.ownerId} FOR UPDATE`;
      return work(tx);
    },
    { timeout: 15_000 },
  );
}
const SENDER = { hostId: "relay-host", connectionEpoch: 1 };
const DISPATCHED = {
  dispatchAttempt: 1,
  dispatchedHostId: SENDER.hostId,
  dispatchedConnectionEpoch: SENDER.connectionEpoch,
};
/** Scalar evidence arrives from the dispatched host on its live epoch. */
async function storeScalar(
  tx: Prisma.TransactionClient,
  input: Omit<Parameters<typeof storeScalarOperationResult>[1], "sender" | "attempt">,
) {
  await tx.sandboxOperation.update({ where: { id: input.operationId }, data: DISPATCHED });
  return storeScalarOperationResult(tx, { ...input, sender: SENDER, attempt: 1 });
}
const reserve = (f: Fixture) => locked(f, (tx) => reserveOperationResult(tx, f));
const hold = (f: Fixture) =>
  db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: f.operationId } });
const operation = (f: Fixture) =>
  db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } });
const read = (f: Fixture) =>
  getOperationResult(sessionPrincipal(f.ownerId), { operationId: f.operationId });
async function publish(f: Fixture, body: unknown = payload, continuation?: unknown) {
  return locked(f, async (tx) => {
    await tx.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "SUCCEEDED", ...DISPATCHED },
    });
    return publishOperationResult(tx, {
      ...f,
      sender: SENDER,
      attempt: 1,
      payload: body,
      continuation,
      observedAt: new Date(),
    });
  });
}
describe("typed results and quota (real PostgreSQL)", () => {
  it("reserves atomically, shrinks to actual stored UTF-8 bytes and preserves the first expiry", async () => {
    const f = await seed();
    await reserve(f);
    const pending = await hold(f);
    expect(pending.reservationBytes).toBe(24 * 1024);
    expect(await publish(f)).toBe(true);
    const stored = await hold(f);
    expect(stored.reservationBytes).toBe(encodedJsonBytes(payload));
    expect(stored.expiresAt).toEqual(pending.expiresAt);
    expect(await publish(f)).toBe(true);
    expect((await hold(f)).expiresAt).toEqual(pending.expiresAt);
    expect(await read(f)).toMatchObject({
      kind: "STAT_PATH",
      result: payload,
      expiresAt: pending.expiresAt.toISOString(),
    });
    await expect(publish(f, { type: "file.remove", removed: true })).rejects.toThrow();
    expect((await hold(f)).payload).toEqual(payload);
  });
  it("reservation rollback leaves neither the child nor the version marker", async () => {
    const f = await seed();
    await expect(
      locked(f, async (tx) => {
        await reserveOperationResult(tx, f);
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect((await operation(f)).resultVersion).toBeNull();
    expect(
      await db.inspect.sandboxOperationResult.count({ where: { operationId: f.operationId } }),
    ).toBe(0);
  });
  it("composite FK rejects owner and sandbox mismatch with P2003", async () => {
    const f = await seed();
    const other = await seed();
    for (const overrides of [{ userId: other.ownerId }, { sandboxId: other.sandboxId }])
      await expect(
        db.inspect.sandboxOperationResult.create({
          data: {
            operationId: f.operationId,
            sandboxId: f.sandboxId,
            userId: f.ownerId,
            generation: 1,
            attempt: 0,
            version: 1,
            reservationBytes: 1,
            expiresAt: new Date(Date.now() + 3600_000),
            ...overrides,
          },
        }),
      ).rejects.toMatchObject({ code: "P2003" });
  });
  it.each(["FAILED", "CANCELLED", "SUCCEEDED"] as const)(
    "terminal %s without content releases exactly once and cannot resurrect",
    async (state) => {
      const f = await seed();
      await reserve(f);
      await locked(f, async (tx) => {
        await tx.sandboxOperation.update({
          where: { id: f.operationId },
          data: { state, completedAt: new Date() },
        });
        expect(await releaseTerminalOperationResults(tx, f.ownerId, [f.operationId])).toBe(1);
        expect(await releaseTerminalOperationResults(tx, f.ownerId, [f.operationId])).toBe(0);
      });
      expect(await hold(f)).toMatchObject({
        reservationState: "RELEASED",
        reservationBytes: 0,
        payload: null,
        continuation: null,
      });
      if (state === "SUCCEEDED")
        await expect(read(f)).rejects.toMatchObject({
          status: 410,
          data: { code: "OPERATION_RESULT_EXPIRED" },
        });
      else
        expect(await read(f)).toMatchObject({
          outcome: state === "FAILED" ? "failed" : "cancelled",
          result: null,
        });
      expect(await publish(f)).toBe(false);
      expect(await reserve(f)).toBe(false);
      expect((await hold(f)).reservationBytes).toBe(0);
    },
  );
  it.each(
    (["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"] as const).flatMap((state) =>
      (["RELEASED", "EXPIRED"] as const).map((hold) => [state, hold] as const),
    ),
  )(
    "terminal %s with a %s hold has a fixed non-retryable answer before expiry",
    async (state, held) => {
      const f = await seed();
      await reserve(f);
      await db.inspect.sandboxOperation.update({
        where: { id: f.operationId },
        data: { state, completedAt: new Date() },
      });
      await db.inspect.sandboxOperationResult.update({
        where: { operationId: f.operationId },
        data: { reservationState: held, reservationBytes: 0 },
      });
      // The fixed deadline is still in the future: only the hold state decides.
      expect((await hold(f)).expiresAt.getTime()).toBeGreaterThan(Date.now());
      if (state === "SUCCEEDED") {
        const error = await read(f).then(
          () => null,
          (cause: unknown) => cause,
        );
        expect(error).toMatchObject({ status: 410, data: { code: "OPERATION_RESULT_EXPIRED" } });
        expect(error).not.toMatchObject({ data: { code: "OPERATION_RESULT_NOT_READY" } });
      } else
        expect(await read(f)).toMatchObject({
          outcome: { FAILED: "failed", CANCELLED: "cancelled", UNKNOWN_OUTCOME: "unknown" }[state],
          result: null,
        });
    },
  );
  it("NOT_READY is reserved for a RESERVED hold on a non-terminal operation", async () => {
    const pending = await seed();
    await reserve(pending);
    await db.inspect.sandboxOperation.update({
      where: { id: pending.operationId },
      data: { state: "RUNNING", dispatchAttempt: 1 },
    });
    await expect(read(pending)).rejects.toMatchObject({
      status: 409,
      data: { code: "OPERATION_RESULT_NOT_READY" },
    });
    const done = await seed();
    await reserve(done);
    await db.inspect.sandboxOperation.update({
      where: { id: done.operationId },
      data: { state: "SUCCEEDED", completedAt: new Date() },
    });
    await expect(read(done)).rejects.toMatchObject({
      status: 410,
      data: { code: "OPERATION_RESULT_EXPIRED" },
    });
  });
  it("interim unknown retains until fixed expiry; late receipts and hold recreation remain fenced", async () => {
    const f = await seed();
    await reserve(f);
    await locked(f, async (tx) => {
      await tx.sandboxOperation.update({
        where: { id: f.operationId },
        data: { state: "UNKNOWN_OUTCOME", completedAt: new Date() },
      });
      expect(await releaseTerminalOperationResults(tx, f.ownerId, [f.operationId])).toBe(0);
    });
    expect((await hold(f)).reservationBytes).toBe(24576);
    expect(await read(f)).toMatchObject({ outcome: "unknown", result: null });
    const past = new Date(Date.now() - 1000);
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { resultExpiresAt: past },
    });
    await db.inspect.sandboxOperationResult.update({
      where: { operationId: f.operationId },
      data: { expiresAt: past },
    });
    await expect(read(f)).rejects.toMatchObject({
      status: 410,
      data: { code: "OPERATION_RESULT_EXPIRED" },
    });
    expect(await publish(f)).toBe(false);
    expect((await hold(f)).reservationState).toBe("EXPIRED");
    expect(await purgeExpiredOperationResults(f.ownerId)).toBe(1);
    expect(await reserve(f)).toBe(false);
    expect((await operation(f)).resultVersion).toBe(1);
  });
  it("observations use one hour, rename uses 24h and continuation inherits the earlier deadline", async () => {
    const stat = await seed();
    const move = await seed("MOVE_PATH", stat.ownerId);
    const page = await seed("LIST_DIR", stat.ownerId);
    await reserve(stat);
    await reserve(move);
    const inherited = (await hold(stat)).expiresAt;
    await locked(page, (tx) =>
      reserveOperationResult(tx, { ...page, inheritedExpiresAt: inherited }),
    );
    expect(
      (await hold(move)).expiresAt.getTime() - (await hold(stat)).expiresAt.getTime(),
    ).toBeGreaterThan(82_799_000);
    expect((await hold(page)).expiresAt).toEqual(inherited);
    const continuation = {
      lastKey: "x",
      root: "/",
      depth: 1,
      limit: 100,
      generation: 1,
      kind: "LIST_DIR" as const,
    };
    await publish(
      page,
      {
        type: "file.list",
        path: "/",
        depth: 1,
        items: [entry],
        nextCursor: page.operationId,
        consistency: "live",
      },
      continuation,
    );
    const publishedPage = await hold(page);
    expect(publishedPage.reservationBytes).toBe(
      encodedJsonBytes(publishedPage.payload) + encodedJsonBytes(continuation),
    );
    const input = { cursor: page.operationId, sandboxId: page.sandboxId, ...continuation };
    expect(await readResultContinuation(sessionPrincipal(page.ownerId), input)).toEqual({
      continuation,
      expiresAt: inherited,
    });
    await expect(
      readResultContinuation(sessionPrincipal(page.ownerId), { ...input, root: "/other" }),
    ).rejects.toMatchObject({ status: 400 });
    await expect(
      readResultContinuation(sessionPrincipal(page.ownerId), { ...input, generation: 2 }),
    ).rejects.toMatchObject({ status: 409 });
    await expect(readResultContinuation(sessionPrincipal("foreign"), input)).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await db.inspect.sandboxOperation.update({
      where: { id: page.operationId },
      data: { resultExpiresAt: new Date(0) },
    });
    await db.inspect.sandboxOperationResult.update({
      where: { operationId: page.operationId },
      data: { expiresAt: new Date(0) },
    });
    await expect(
      readResultContinuation(sessionPrincipal(page.ownerId), input),
    ).rejects.toMatchObject({ status: 410 });
  });
  it("permanent mkdir/remove scalars survive content expiry and retain no guest path", async () => {
    for (const [kind, body] of [
      ["MKDIR", { type: "file.mkdir", created: false }],
      ["REMOVE_PATH", { type: "file.remove", removed: true }],
    ] as const) {
      const f = await seed(kind);
      await locked(f, async (tx) => {
        await tx.sandboxOperation.update({
          where: { id: f.operationId },
          data: { state: "SUCCEEDED" },
        });
        await storeScalar(tx, { ...f, payload: body, observedAt: new Date(0) });
      });
      expect(await read(f)).toMatchObject({ result: body, expiresAt: null });
      expect(
        await db.inspect.sandboxOperationResult.count({ where: { operationId: f.operationId } }),
      ).toBe(0);
      await expect(
        locked(f, (tx) =>
          storeScalar(tx, {
            ...f,
            payload: { ...body, path: "/private" },
            observedAt: new Date(),
          }),
        ),
      ).rejects.toThrow();
    }
  });
  it("unversioned legacy is unsupported, and foreign operations match absent operations", async () => {
    const f = await seed();
    await expect(read(f)).rejects.toMatchObject({ data: { code: "OPERATION_RESULT_UNSUPPORTED" } });
    await expect(
      getOperationResult(sessionPrincipal("foreign"), { operationId: f.operationId }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(
      getOperationResult(sessionPrincipal(f.ownerId), { operationId: "missing" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
  it("DB clock is sampled after quota waits; inherited expiry cannot be refreshed", async () => {
    const f = await seed();
    const gate = db.pauseAt("reserve", { before: /hashtextextended\(\?, 270028\)/ });
    const future = new Date(Date.now() + 120_000);
    const work = db.run("reserve", () =>
      locked(f, (tx) => reserveOperationResult(tx, { ...f, inheritedExpiresAt: future })),
    );
    await gate.waitReached();
    await db.inspect.$executeRaw`SELECT pg_sleep(0.02)`;
    const before = new Date();
    gate.release();
    await work;
    expect((await operation(f)).resultObservedAt!.getTime()).toBeGreaterThanOrEqual(
      before.getTime() - 1,
    );
    expect((await hold(f)).expiresAt).toEqual(future);
  });
  it("last-byte admission serializes independent sandboxes on the common owner quota", async () => {
    const base = await seed();
    const a = await seed("STAT_PATH", base.ownerId);
    const b = await seed("STAT_PATH", base.ownerId);
    // Valid per-row charges: 1364 full pages and one published 8 KiB page.
    const ids = Array.from({ length: 1365 }, () => randomUUID());
    await db.inspect.sandboxOperation.createMany({
      data: ids.map((id) => ({
        ...requestDigestMetadata(),
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }, { generation: 1 }),
        id,
        userId: base.ownerId,
        sandboxId: base.sandboxId,
        generation: 1,
        kind: "STAT_PATH",
        idempotencyKey: id,
        requestBodyHash: "a".repeat(64),
      })),
    });
    await db.inspect.sandboxOperationResult.createMany({
      data: ids.map((id, i) => ({
        operationId: id,
        userId: base.ownerId,
        sandboxId: base.sandboxId,
        generation: 1,
        attempt: 0,
        version: 1,
        expiresAt: new Date(Date.now() + 3600_000),
        reservationBytes: i === 1364 ? 8192 : 24576,
      })),
    });
    const gate = db.pauseAt("a", { after: "sandboxOperationResult.aggregate" });
    const first = db.run("a", () => reserve(a));
    await gate.waitReached();
    const second = db.run("b", () => reserve(b));
    const denied = expect(second).rejects.toMatchObject({
      status: 429,
      data: { code: "OPERATION_RESULT_QUOTA" },
    });
    await db.waitUntilBlocked("b", { by: "a" });
    gate.release();
    await first;
    await denied;
    expect(
      (
        await db.inspect.sandboxOperationResult.aggregate({
          where: { userId: base.ownerId },
          _sum: { reservationBytes: true },
        })
      )._sum.reservationBytes,
    ).toBe(RESULT_LIMITS.ownerReservedMaxBytes);
  });
  it("suffix ranks reject any prefix seek or second owner after quota", async () => {
    const f = await seed();
    await locked(f, async (tx) => {
      await reserveOperationResult(tx, f);
      expect(() => assertBeforeResultQuota(tx)).toThrow("Prefix lock");
      await expect(reserveOperationResult(tx, { ...f, ownerId: "foreign" })).rejects.toThrow();
    });
  });
  it("account finalizer cascades result children and finalizer-first writers cannot insert", async () => {
    const f = await seed();
    await reserve(f);
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "FAILED" },
    });
    expect(await requestAccountDeletion(f.ownerId)).toBe(true);
    expect(await db.inspect.sandboxOperationResult.count({ where: { userId: f.ownerId } })).toBe(0);
    await expect(reserve(f)).rejects.toThrow();
  });
});

it("queued cancellation and lifecycle supersession use the same final commit suffix", async () => {
  const { sandboxOutboxTransaction } = await import("./outbox");
  const { cancelQueuedOperation, settleSupersededOperations, casActiveOperation } = await import(
    "./relay-fence"
  );
  for (const transition of ["cancel", "stop", "failure"] as const) {
    const f = await seed();
    await reserve(f);
    await sandboxOutboxTransaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.ownerId);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandboxId} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.operationId} FOR UPDATE`;
      if (transition === "cancel")
        await cancelQueuedOperation(
          tx,
          { ...f, userId: f.ownerId, generation: 1, attempt: 0, hostId: null, kind: "STAT_PATH" },
          new Date(),
        );
      else if (transition === "failure")
        await casActiveOperation(
          tx,
          { ...f, userId: f.ownerId, generation: 1, attempt: 0, hostId: null },
          { state: "FAILED", completedAt: new Date() },
        );
      else {
        await tx.sandboxOperation.update({
          where: { id: f.operationId },
          data: { state: "CANCEL_REQUESTED", errorCode: "superseded" },
        });
        await settleSupersededOperations(
          tx,
          {
            userId: f.ownerId,
            sandboxId: f.sandboxId,
            generation: 2,
            kind: "STOP_SANDBOX",
            state: "SUCCEEDED",
          },
          new Date(),
        );
      }
    });
    expect(await hold(f)).toMatchObject({ reservationState: "RELEASED", reservationBytes: 0 });
    expect(await publish(f)).toBe(false);
  }
});

it.each(["writer-first", "finalizer-first"])(
  "account finalization lock barrier: %s",
  async (order) => {
    const f = await seed();
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "FAILED" },
    });
    if (order === "writer-first") {
      const gate = db.pauseAt("writer", { before: "$transaction.commit" });
      const writer = db.run("writer", () =>
        locked(f, async (tx) => {
          await tx.sandboxOperation.update({
            where: { id: f.operationId },
            data: { state: "QUEUED" },
          });
          await reserveOperationResult(tx, f);
          await tx.sandboxOperation.update({
            where: { id: f.operationId },
            data: { state: "FAILED" },
          });
        }),
      );
      await gate.waitReached();
      const finalizer = db.run("finalizer", () => requestAccountDeletion(f.ownerId));
      await db.waitUntilBlocked("finalizer", { by: "writer" });
      gate.release();
      await writer;
      expect(await finalizer).toBe(true);
    } else {
      const gate = db.pauseAt("finalizer", { before: "$transaction.commit" });
      const finalizer = db.run("finalizer", () => requestAccountDeletion(f.ownerId));
      await gate.waitReached();
      const writer = db.run("writer", () => reserve(f));
      const denied = expect(writer).rejects.toThrow();
      await db.waitUntilBlocked("writer", { by: "finalizer" });
      gate.release();
      await finalizer;
      await denied;
    }
    expect(await db.inspect.sandboxOperationResult.count({ where: { userId: f.ownerId } })).toBe(0);
  },
);

it("result reads reauthorize scopes before payload IO and again after revocation during a read", async () => {
  const { revalidateSdkKey } = await import("../lib/sdk-key-access");
  const f = await seed("MOVE_PATH");
  await reserve(f);
  await publish(f, { type: "file.rename", entry });
  async function key(scopes: string[]) {
    const row = await db.inspect.sdkKey.create({
      data: {
        userId: f.ownerId,
        name: "Key",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        resourceMode: "ALL_OWNED",
        scopes,
      },
    });
    const principal = await revalidateSdkKey(row.id, f.ownerId);
    if (!principal) throw new Error("key fixture unavailable");
    return principal;
  }
  const writeOnly = await key(["operations:read", "files:write"]);
  const payloadRead = vi.spyOn(db.prisma.sandboxOperationResult, "findFirst");
  await expect(getOperationResult(writeOnly, { operationId: f.operationId })).rejects.toMatchObject(
    { code: "FORBIDDEN" },
  );
  expect(payloadRead).not.toHaveBeenCalled();
  payloadRead.mockRestore();
  const full = await key(["operations:read", "files:write", "files:read"]);
  expect(await getOperationResult(full, { operationId: f.operationId })).toMatchObject({
    result: { type: "file.rename", entry },
  });
  // Retained ALL_OWNED read above worked with a deleted origin host. An
  // ALLOWLIST key does not gain this exception through missing allowlist rows.
  await db.inspect.sdkKey.update({
    where: { id: full.keyId },
    data: { resourceMode: "ALLOWLIST" },
  });
  await expect(getOperationResult(full, { operationId: f.operationId })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
  await db.inspect.sdkKey.update({
    where: { id: full.keyId },
    data: { resourceMode: "ALL_OWNED" },
  });
  const fresh = await key(["operations:read", "files:write", "files:read"]);
  const gate = db.pauseAt("read", { before: "$transaction.commit" });
  const reading = db.run("read", () => getOperationResult(fresh, { operationId: f.operationId }));
  const denied = expect(reading).rejects.toMatchObject({ code: "FORBIDDEN" });
  await gate.waitReached();
  await db.inspect.sdkKey.update({ where: { id: fresh.keyId }, data: { revokedAt: new Date() } });
  gate.release();
  await denied;
  const legacy = await seed("STAT_PATH", f.ownerId);
  const errorKey = await key(["operations:read", "files:read"]);
  let errorGate = db.pauseAt("error-read", { after: "sandboxOperation.findFirst" });
  const rejectedRead = db.run("error-read", () =>
    getOperationResult(errorKey, { operationId: legacy.operationId }),
  );
  const deniedError = expect(rejectedRead).rejects.toMatchObject({ code: "FORBIDDEN" });
  // Entry metadata, body metadata, then the stored-kind authorization read.
  // Revoke after all body authorization, immediately before its legacy error.
  for (let stage = 0; stage < 2; stage++) {
    await errorGate.waitReached();
    const nextGate = db.pauseAt("error-read", { after: "sandboxOperation.findFirst" });
    errorGate.release();
    errorGate = nextGate;
  }
  await errorGate.waitReached();
  await db.inspect.sdkKey.update({
    where: { id: errorKey.keyId },
    data: { revokedAt: new Date() },
  });
  errorGate.release();
  await deniedError;
});

it("result writes take no global transfer rank: two owners never serialize on 270027", async () => {
  const { lockTransferAdmission } = await import("./result-locks");
  const a = await seed();
  const b = await seed();
  // An open transfer admission no longer blocks any owner's result write.
  const transferGate = db.pauseAt("transfer", { before: "$transaction.commit" });
  const transfer = db.run("transfer", () =>
    db.prisma.$transaction((tx) => lockTransferAdmission(tx)),
  );
  await transferGate.waitReached();
  expect(await reserve(a)).toBe(true);
  // Owner A holds its own result rank; owner B proceeds and 270027 stays free.
  const aGate = db.pauseAt("owner-a", { before: "$transaction.commit" });
  const other = await seed("STAT_PATH", a.ownerId);
  const reservingA = db.run("owner-a", () => reserve(other));
  await aGate.waitReached();
  expect(await reserve(b)).toBe(true);
  transferGate.release();
  await transfer;
  const free = await db.inspect.$queryRaw<
    { available: boolean }[]
  >`SELECT pg_try_advisory_xact_lock(270027) AS available`;
  expect(free[0]?.available).toBe(true);
  aGate.release();
  expect(await reservingA).toBe(true);
  // Combined writers keep the documented order: transfer rank, then result
  // quota. The inverse order is refused before it can wait.
  const combined = await seed("STAT_PATH", a.ownerId);
  expect(
    await locked(combined, async (tx) => {
      await lockTransferAdmission(tx);
      return reserveOperationResult(tx, combined);
    }),
  ).toBe(true);
  const inverse = await seed("STAT_PATH", a.ownerId);
  await expect(
    locked(inverse, async (tx) => {
      await reserveOperationResult(tx, inverse);
      await lockTransferAdmission(tx);
    }),
  ).rejects.toThrow("Prefix lock requested after result quota.");
});

it("description cleanup clears expired private data in bounded owner transactions", async () => {
  const { purgeExpiredProcessDescriptions } = await import("./operation-results");
  const f = await seed("RUN_COMMAND");
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: {
      processDescription: { cmd: "private-command" },
      processDescriptionExpiresAt: new Date(0),
      scalarResult: { exitCode: 0 },
    },
  });
  expect(await purgeExpiredProcessDescriptions(f.ownerId)).toBe(1);
  expect(await operation(f)).toMatchObject({
    processDescription: null,
    scalarResult: { exitCode: 0 },
    processDescriptionExpiresAt: new Date(0),
  });
  expect(await purgeExpiredProcessDescriptions(f.ownerId)).toBe(0);
});

it("holds the named owner advisory throughout the quota aggregate and commit", async () => {
  const f = await seed();
  const gate = db.pauseAt("reserve", { after: "sandboxOperationResult.aggregate" });
  const reserving = db.run("reserve", () => reserve(f));
  await gate.waitReached();
  const probe = await db.inspect.$queryRaw<
    { available: boolean }[]
  >`SELECT pg_try_advisory_xact_lock(hashtextextended(${f.ownerId}, 270028)) AS available`;
  expect(probe[0]?.available).toBe(false);
  gate.release();
  await reserving;
});

it("scalar evidence is immutable; a command may only fill its original exit code", async () => {
  const f = await seed("MKDIR");
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: { state: "SUCCEEDED" },
  });
  const body = { type: "file.mkdir", created: true };
  await locked(f, (tx) => storeScalar(tx, { ...f, payload: body, observedAt: new Date(0) }));
  await expect(
    locked(f, (tx) =>
      storeScalar(tx, {
        ...f,
        payload: { ...body, created: false },
        observedAt: new Date(),
      }),
    ),
  ).rejects.toThrow();
  await locked(f, (tx) => storeScalar(tx, { ...f, payload: body, observedAt: new Date() }));
  expect((await operation(f)).resultObservedAt).toEqual(new Date(0));
  const command = await seed("RUN_COMMAND");
  await db.inspect.sandboxOperation.update({
    where: { id: command.operationId },
    data: { state: "RUNNING" },
  });
  const start = {
    type: "command",
    process: {
      sandboxId: command.sandboxId,
      generation: 1,
      processId: "process",
      attempt: 1,
      pid: 42,
    },
    startedAt: "2026-10-27T00:00:00Z",
    exitCode: null,
  };
  await locked(command, (tx) =>
    storeScalar(tx, { ...command, payload: start, observedAt: new Date() }),
  );
  await expect(
    locked(command, (tx) =>
      storeScalar(tx, {
        ...command,
        payload: { ...start, process: { ...start.process, pid: 43 } },
        observedAt: new Date(),
      }),
    ),
  ).rejects.toThrow();
  await db.inspect.sandboxOperation.update({
    where: { id: command.operationId },
    data: { state: "SUCCEEDED" },
  });
  await locked(command, (tx) =>
    storeScalar(tx, {
      ...command,
      payload: { ...start, exitCode: 0 },
      observedAt: new Date(),
    }),
  );
  await expect(
    locked(command, (tx) =>
      storeScalar(tx, {
        ...command,
        payload: { ...start, exitCode: 1 },
        observedAt: new Date(),
      }),
    ),
  ).rejects.toThrow();
});

it("a cursor cannot reuse an old generation by repeating its original qualifiers", async () => {
  const f = await seed("LIST_DIR");
  await reserve(f);
  const continuation = {
    lastKey: "x",
    root: "/",
    depth: 1,
    limit: 100,
    generation: 1,
    kind: "LIST_DIR" as const,
  };
  await publish(
    f,
    {
      type: "file.list",
      path: "/",
      depth: 1,
      items: [entry],
      nextCursor: f.operationId,
      consistency: "live",
    },
    continuation,
  );
  await db.inspect.sandbox.update({ where: { id: f.sandboxId }, data: { generation: 2 } });
  await expect(
    readResultContinuation(sessionPrincipal(f.ownerId), {
      cursor: f.operationId,
      sandboxId: f.sandboxId,
      ...continuation,
    }),
  ).rejects.toMatchObject({ status: 409, data: { code: "RESULT_CURSOR_STALE" } });
  // Historical result content still remains readable until its fixed deadline.
  expect(await read(f)).toMatchObject({ generation: 1, result: { type: "file.list" } });
});

it("expired private content can be removed while account deletion awaits live work", async () => {
  const f = await seed();
  await reserve(f);
  await db.inspect.sandboxOperationResult.update({
    where: { operationId: f.operationId },
    data: { expiresAt: new Date(0) },
  });
  await db.inspect.user.update({
    where: { id: f.ownerId },
    data: { deletionRequestedAt: new Date() },
  });
  expect(await purgeExpiredOperationResults(f.ownerId)).toBe(1);
});

it("host result cap includes the complete payload and private continuation before publication", async () => {
  const f = await seed("LIST_DIR");
  await reserve(f);
  const items = Array.from({ length: 60 }, (_, i) => {
    const name = `x${String(i).padStart(3, "0")}`;
    return { ...entry, name, path: `/${name}`, owner: "n".repeat(128), group: "g".repeat(128) };
  });
  const body = {
    type: "file.list",
    path: "/",
    depth: 1,
    items,
    nextCursor: null,
    consistency: "live",
  };
  expect(encodedJsonBytes({ payload: body, continuation: null })).toBeGreaterThan(
    RESULT_LIMITS.hostResultMaxBytes,
  );
  await expect(publish(f, body)).rejects.toThrow();
  expect(await hold(f)).toMatchObject({
    reservationState: "RESERVED",
    reservationBytes: RESULT_LIMITS.hostResultMaxBytes,
  });

  const root = "/" + Array.from({ length: 14 }, () => "p".repeat(250)).join("/");
  const deep = await seed("LIST_DIR", f.ownerId, { path: root, depth: 1 });
  await reserve(deep);
  const shortItems = Array.from({ length: 5 }, (_, i) => {
    const name = `x${String(i).padStart(3, "0")}`;
    return { ...entry, name, path: `${root}/${name}` };
  });
  const page = {
    type: "file.list",
    path: root,
    depth: 1,
    items: shortItems,
    nextCursor: deep.operationId,
    consistency: "live",
  };
  const continuation = {
    lastKey: "x004",
    root,
    depth: 1,
    limit: 100,
    generation: 1,
    kind: "LIST_DIR" as const,
  };
  expect(encodedJsonBytes(page)).toBeLessThan(RESULT_LIMITS.hostResultMaxBytes);
  expect(encodedJsonBytes({ payload: page, continuation })).toBeGreaterThan(
    RESULT_LIMITS.hostResultMaxBytes,
  );
  await expect(publish(deep, page, continuation)).rejects.toThrow();
  // The same page minus the continuation fits, so the cap (not the request
  // binding) is what refused the wrapper above.
  expect(await publish(deep, { ...page, nextCursor: null })).toBe(true);
});

it.each([
  [{ depth: 2 }, 2],
  [{}, 1],
  [{ maxDepth: 2 }, 1],
] as const)(
  "binds listing results to stored depth %j (defaulting to one)",
  async (shape, depth) => {
    const f = await seed("LIST_DIR", undefined, { path: "/", ...shape });
    await reserve(f);
    const listing = {
      type: "file.list",
      path: "/",
      depth,
      items: [entry],
      nextCursor: null,
      consistency: "live",
    };
    await expect(publish(f, { ...listing, depth: depth === 1 ? 2 : 1 })).rejects.toThrow();
    expect(await publish(f, listing)).toBe(true);
  },
);

it("binds published paths to the stored request, including the `..` probe", async () => {
  const stat = await seed("STAT_PATH", undefined, { path: "/etc/./shadow" });
  await reserve(stat);
  const shadow = { ...entry, name: "shadow", path: "/etc/shadow" };
  for (const path of ["/a/../etc/shadow", "/a/shadow", "/etc//shadow"])
    await expect(
      publish(stat, { type: "file.stat", entry: { ...shadow, path } }),
    ).rejects.toThrow();
  expect((await hold(stat)).reservationState).toBe("RESERVED");
  expect(await publish(stat, { type: "file.stat", entry: shadow })).toBe(true);

  const move = await seed("MOVE_PATH", stat.ownerId, { path: "/a", destPath: "/b/x" });
  await reserve(move);
  await expect(
    publish(move, { type: "file.rename", entry: { ...entry, path: "/a/x" } }),
  ).rejects.toThrow();
  expect(await publish(move, { type: "file.rename", entry: { ...entry, path: "/b/x" } })).toBe(
    true,
  );

  const list = await seed("LIST_DIR", stat.ownerId, { path: "/d", depth: 1 });
  await reserve(list);
  const child = { ...entry, path: "/d/x" };
  const listing = { type: "file.list", path: "/d", depth: 1, items: [child], nextCursor: null };
  for (const body of [
    { ...listing, path: "/e", items: [{ ...child, path: "/e/x" }] },
    { ...listing, depth: 2 },
    { ...listing, items: [{ ...child, path: "/d/../x" }] },
  ])
    await expect(publish(list, { ...body, consistency: "live" })).rejects.toThrow();
  const capped = await seed("LIST_DIR", stat.ownerId, { path: "/d", depth: 1, limit: 1 });
  await reserve(capped);
  await expect(
    publish(capped, {
      ...listing,
      items: [child, { ...child, name: "y", path: "/d/y" }],
      consistency: "live",
    }),
  ).rejects.toThrow();
  expect((await hold(list)).reservationState).toBe("RESERVED");
  expect(await publish(list, { ...listing, consistency: "live" })).toBe(true);
});

it("cleanup caps rows and owners and preserves progress between bounded ticks", async () => {
  const { sweepOperationResults } = await import("./operation-results");
  const marker = `z-${randomUUID()}-`;
  for (let i = 0; i < 12; i++) {
    const ownerId = `${marker}${String(i).padStart(2, "0")}`;
    await db.inspect.user.create({
      data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
    });
    const f = await seed("STAT_PATH", ownerId);
    await reserve(f);
    await db.inspect.sandboxOperationResult.update({
      where: { operationId: f.operationId },
      data: { expiresAt: new Date(0) },
    });
  }
  const cursor = await sweepOperationResults(marker, 100);
  expect(cursor).toBe(`${marker}09`);
  expect(
    await db.inspect.sandboxOperationResult.count({ where: { userId: { startsWith: marker } } }),
  ).toBe(2);
  await sweepOperationResults(cursor, 100);
  expect(
    await db.inspect.sandboxOperationResult.count({ where: { userId: { startsWith: marker } } }),
  ).toBe(0);
  const f = await seed();
  const ids = Array.from({ length: 101 }, () => randomUUID());
  await db.inspect.sandboxOperation.createMany({
    data: ids.map((id) => ({
      ...requestDigestMetadata(),
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }, { generation: 1 }),
      id,
      userId: f.ownerId,
      sandboxId: f.sandboxId,
      generation: 1,
      kind: "STAT_PATH",
      state: "FAILED",
      idempotencyKey: id,
      requestBodyHash: "hash",
      resultVersion: 1,
      resultExpiresAt: new Date(0),
    })),
  });
  await db.inspect.sandboxOperationResult.createMany({
    data: ids.map((operationId) => ({
      operationId,
      userId: f.ownerId,
      sandboxId: f.sandboxId,
      generation: 1,
      attempt: 0,
      version: 1,
      expiresAt: new Date(0),
      reservationBytes: 0,
      reservationState: "RELEASED",
    })),
  });
  expect(await purgeExpiredOperationResults(f.ownerId, 1000)).toBe(100);
  expect(await purgeExpiredOperationResults(f.ownerId, 1000)).toBe(1);
});

it("rechecks the stored kind at egress rather than trusting retained JSON", async () => {
  const f = await seed();
  await reserve(f);
  await publish(f);
  await db.inspect.sandboxOperationResult.update({
    where: { operationId: f.operationId },
    data: { payload: { type: "file.remove", removed: true } },
  });
  await expect(read(f)).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
});

it("publication becomes visible only at commit and returns after the atomic shrink", async () => {
  const f = await seed();
  await reserve(f);
  const gate = db.pauseAt("publish", { before: "$transaction.commit" });
  let returned = false;
  const publishing = db
    .run("publish", () => publish(f))
    .then((value) => {
      returned = true;
      return value;
    });
  await gate.waitReached();
  expect(returned).toBe(false);
  expect(await hold(f)).toMatchObject({
    reservationState: "RESERVED",
    reservationBytes: 24576,
    payload: null,
  });
  expect((await operation(f)).state).toBe("QUEUED");
  gate.release();
  expect(await publishing).toBe(true);
  expect(await hold(f)).toMatchObject({
    reservationState: "PUBLISHED",
    reservationBytes: encodedJsonBytes(payload),
  });
});

it.each(["cancel", "failure", "stop"] as const)(
  "publication and %s serialize in both lock orders without resurrection",
  async (transition) => {
    const { sandboxOutboxTransaction } = await import("./outbox");
    const { cancelQueuedOperation, settleSupersededOperations, casActiveOperation } = await import(
      "./relay-fence"
    );
    for (const first of ["terminal", "publish"] as const) {
      const f = await seed();
      await reserve(f);
      if (transition === "stop")
        await db.inspect.sandboxOperation.update({
          where: { id: f.operationId },
          data: { state: "CANCEL_REQUESTED", errorCode: "superseded" },
        });
      const prefix = <T>(work: (tx: Prisma.TransactionClient) => Promise<T>) =>
        sandboxOutboxTransaction(async (tx) => {
          await lockOwnerForAdmission(tx, f.ownerId);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandboxId} FOR UPDATE`;
          await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.operationId} FOR UPDATE`;
          return work(tx);
        });
      const fence = { ...f, userId: f.ownerId, generation: 1, attempt: 0, hostId: null };
      const terminal = () =>
        prefix(async (tx) => {
          if (transition === "cancel")
            await cancelQueuedOperation(tx, { ...fence, kind: "STAT_PATH" }, new Date());
          else if (transition === "failure")
            await casActiveOperation(tx, fence, { state: "FAILED", completedAt: new Date() });
          else
            await settleSupersededOperations(
              tx,
              {
                userId: f.ownerId,
                sandboxId: f.sandboxId,
                generation: 2,
                kind: "STOP_SANDBOX",
                state: "SUCCEEDED",
              },
              new Date(),
            );
        });
      const publishFenced = () =>
        prefix(async (tx) => {
          await casActiveOperation(tx, fence, { state: "SUCCEEDED", ...DISPATCHED });
          return publishOperationResult(tx, {
            ...f,
            sender: SENDER,
            attempt: 1,
            payload,
            observedAt: new Date(),
          });
        });
      const gate = db.pauseAt("winner", { before: "$transaction.commit" });
      const winner = db.run("winner", async () => {
        if (first === "terminal") await terminal();
        else await publishFenced();
      });
      await gate.waitReached();
      const loser = db
        .run("loser", async () => {
          if (first === "terminal") await publishFenced();
          else await terminal();
        })
        .then(
          () => "settled",
          () => "fenced",
        );
      await db.waitUntilBlocked("loser", { by: "winner" });
      gate.release();
      await winner;
      await loser;
      const stored = await hold(f);
      expect(stored.reservationState).toBe(first === "terminal" ? "RELEASED" : "PUBLISHED");
      expect(stored.reservationBytes).toBe(first === "terminal" ? 0 : encodedJsonBytes(payload));
    }
  },
);

it("owned action receipts are unsupported typed results; foreign receipts remain absent", async () => {
  const f = await seed();
  const receipt = await db.inspect.sandboxActionReceipt.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: f.ownerId,
      sandboxId: f.sandboxId,
      hostId: "deleted-host",
      action: "commands.writeStdin",
      idempotencyKey: randomUUID(),
      requestBodyHash: "hash",
      state: "SUCCEEDED",
    },
  });
  await expect(
    getOperationResult(sessionPrincipal(f.ownerId), { operationId: receipt.id }),
  ).rejects.toMatchObject({ status: 400, data: { code: "OPERATION_RESULT_UNSUPPORTED" } });
  await expect(
    getOperationResult(sessionPrincipal("foreign"), { operationId: receipt.id }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("expired pending tombstones prevent a queued operation from reserving again after physical cleanup", async () => {
  const f = await seed();
  await reserve(f);
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: { resultExpiresAt: new Date(0) },
  });
  await db.inspect.sandboxOperationResult.update({
    where: { operationId: f.operationId },
    data: { expiresAt: new Date(0) },
  });
  expect(await purgeExpiredOperationResults(f.ownerId)).toBe(1);
  await expect(read(f)).rejects.toMatchObject({
    status: 410,
    data: { code: "OPERATION_RESULT_EXPIRED" },
  });
  expect(await reserve(f)).toBe(false);
  expect(
    await db.inspect.sandboxOperationResult.count({ where: { operationId: f.operationId } }),
  ).toBe(0);
  expect(await operation(f)).toMatchObject({
    state: "QUEUED",
    dispatchAttempt: 0,
    resultVersion: 1,
    resultExpiresAt: new Date(0),
  });
});

it.each(["FAILED", "CANCELLED", "UNKNOWN_OUTCOME"] as const)(
  "retains command evidence privately while projecting %s with a null result",
  async (state) => {
    const f = await seed("RUN_COMMAND");
    const start = {
      type: "command",
      process: {
        sandboxId: f.sandboxId,
        generation: 1,
        processId: "process",
        attempt: 1,
        pid: 42,
      },
      startedAt: "2026-10-27T00:00:00Z",
      exitCode: null,
    };
    await locked(f, async (tx) => {
      await tx.sandboxOperation.update({
        where: { id: f.operationId },
        data: { state: "RUNNING" },
      });
      await storeScalar(tx, { ...f, payload: start, observedAt: new Date() });
      await tx.sandboxOperation.update({ where: { id: f.operationId }, data: { state } });
    });
    const outcome = state === "FAILED" ? "failed" : state === "CANCELLED" ? "cancelled" : "unknown";
    expect(await read(f)).toMatchObject({ outcome, result: null, expiresAt: null });
    const final = { ...start, exitCode: 137 };
    await locked(f, (tx) => storeScalar(tx, { ...f, payload: final, observedAt: new Date() }));
    expect((await operation(f)).scalarResult).toEqual(final);
    expect(await read(f)).toMatchObject({ outcome, result: null, expiresAt: null });
  },
);

it("stores re-check the dispatched host, epoch, attempt and process identity", async () => {
  const wrong = [
    { sender: { ...SENDER, hostId: "other-host" }, attempt: 1 },
    { sender: { ...SENDER, connectionEpoch: 2 }, attempt: 1 },
    { sender: SENDER, attempt: 2 },
  ];
  const f = await seed();
  await reserve(f);
  await locked(f, (tx) =>
    tx.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "SUCCEEDED", ...DISPATCHED },
    }),
  );
  for (const binding of wrong)
    await expect(
      locked(f, (tx) =>
        publishOperationResult(tx, { ...f, ...binding, payload, observedAt: new Date() }),
      ),
    ).rejects.toThrow();
  expect((await hold(f)).reservationState).toBe("RESERVED");

  const command = await seed("RUN_COMMAND", f.ownerId);
  await db.inspect.sandboxOperation.update({
    where: { id: command.operationId },
    data: { state: "RUNNING", ...DISPATCHED, processId: "bound", processPid: 42 },
  });
  const start = {
    type: "command",
    process: {
      sandboxId: command.sandboxId,
      generation: 1,
      processId: "bound",
      attempt: 1,
      pid: 42,
    },
    startedAt: "2026-10-27T00:00:00Z",
    exitCode: null,
  };
  const scalar = (
    body: unknown,
    binding: (typeof wrong)[number] = { sender: SENDER, attempt: 1 },
  ) =>
    locked(command, (tx) =>
      storeScalarOperationResult(tx, {
        ...command,
        ...binding,
        payload: body,
        observedAt: new Date(),
      }),
    );
  for (const binding of wrong) await expect(scalar(start, binding)).rejects.toThrow();
  for (const process of [
    { ...start.process, processId: "foreign" },
    { ...start.process, pid: 43 },
    { ...start.process, attempt: 2 },
  ])
    await expect(scalar({ ...start, process })).rejects.toThrow();
  expect((await operation(command)).scalarResult).toBeNull();
  await scalar(start);
  expect((await operation(command)).scalarResult).toEqual(start);

  const signal = await seed("SIGNAL_PROCESS", f.ownerId);
  await db.inspect.outboxEvent.create({
    data: {
      userId: f.ownerId,
      aggregateType: "sandbox",
      aggregateId: signal.sandboxId,
      eventType: "sandbox.process_signal_requested",
      payload: { operationId: signal.operationId, pid: 42, signal: "SIGTERM" },
      operationId: signal.operationId,
      processedAt: new Date(),
    },
  });
  // The fixture command lives in another sandbox, so it is foreign here.
  await db.inspect.sandboxOperation.update({
    where: { id: signal.operationId },
    data: { state: "SUCCEEDED", ...DISPATCHED },
  });
  const local = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: f.ownerId,
      sandboxId: signal.sandboxId,
      generation: 1,
      kind: "RUN_COMMAND",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      processId: "local",
      processPid: 42,
      dispatchAttempt: 1,
    },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: signal.sandboxId, eventType: "sandbox.process_signal_requested" },
    data: {
      payload: {
        operationId: signal.operationId,
        targetOperationId: local.id,
        process: {
          sandboxId: signal.sandboxId,
          generation: 1,
          processId: "local",
          attempt: 1,
          pid: 42,
        },
        signal: "SIGTERM",
      },
    },
  });
  const accepted = (targetOperationId: string, processId: string, pid = 42) => ({
    type: "process.signal",
    process: { sandboxId: signal.sandboxId, generation: 1, processId, attempt: 1, pid },
    targetOperationId,
    signal: "SIGTERM",
    accepted: true,
    delivery: "process_group",
  });
  const otherOwned = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: f.ownerId,
      sandboxId: signal.sandboxId,
      generation: 1,
      kind: "RUN_COMMAND",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      processId: "other-owned",
      processPid: 44,
      dispatchAttempt: 1,
    },
  });
  const signalStore = (body: unknown) =>
    locked(signal, (tx) =>
      storeScalarOperationResult(tx, {
        ...signal,
        sender: SENDER,
        attempt: 1,
        payload: body,
        observedAt: new Date(),
      }),
    );
  for (const body of [
    accepted(command.operationId, "bound"),
    accepted(otherOwned.id, "other-owned", 44),
    accepted(local.id, "foreign"),
    accepted(local.id, "local", 43),
    { ...accepted(local.id, "local"), signal: "SIGKILL" },
  ])
    await expect(signalStore(body)).rejects.toThrow();
  await signalStore(accepted(local.id, "local"));
  expect((await operation(signal)).scalarResult).toMatchObject({ targetOperationId: local.id });
});

it("the suffix outbox lock is an index condition on the named sandboxes (B1-C-3)", async () => {
  const f = await seed();
  // A heavy owner: thousands of historical events on another sandbox.
  const history = await seed("STAT_PATH", f.ownerId);
  await db.inspect.outboxEvent.createMany({
    data: Array.from({ length: 5000 }, () => {
      const operationId = randomUUID();
      return {
        userId: f.ownerId,
        aggregateType: "sandbox",
        aggregateId: history.sandboxId,
        eventType: "sandbox.file_stat_requested",
        payload: { operationId, path: "/x" },
        operationId,
        processedAt: new Date(),
      };
    }),
  });
  await db.inspect.$executeRaw`ANALYZE sandbox_dispatch_outbox`;
  const plan = await db.prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SET LOCAL enable_seqscan = off`;
    const [row] = await tx.$queryRaw<{ "QUERY PLAN": unknown }[]>(
      PrismaValue.sql`EXPLAIN (FORMAT JSON) ${resultOutboxLockQuery(f.ownerId, {
        sandboxIds: [f.sandboxId],
        operationIds: [f.operationId],
      })}`,
    );
    return row?.["QUERY PLAN"];
  });
  const conditions: string[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === "object")
      for (const [key, value] of Object.entries(node)) {
        if (key === "Index Cond" && typeof value === "string") conditions.push(value);
        else walk(value);
      }
  };
  walk(plan);
  expect(conditions.some((cond) => cond.includes("aggregateId"))).toBe(true);
  // The lock still finds exactly the operation's own request event.
  const locked = await db.prisma.$transaction((tx) =>
    tx.$queryRaw<{ id: string }[]>(
      resultOutboxLockQuery(f.ownerId, {
        sandboxIds: [f.sandboxId],
        operationIds: [f.operationId],
      }),
    ),
  );
  expect(locked).toHaveLength(1);
});

it.each(["RUN_COMMAND", "MKDIR", "REMOVE_PATH", "SIGNAL_PROCESS"] as const)(
  "a 10.5 %s reads as versioned from creation, in flight or failed before start",
  async (kind) => {
    expect(initialResultFields(kind, false)).toEqual({});
    const f = await seed(kind);
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: initialResultFields(kind, true),
    });
    expect((await operation(f)).resultVersion).toBe(RESULT_LIMITS.resultVersion);
    await expect(read(f)).rejects.toMatchObject({
      status: 409,
      data: { code: "OPERATION_RESULT_NOT_READY" },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "FAILED", completedAt: new Date(), errorCode: "unsupported_capability" },
    });
    expect(await read(f)).toMatchObject({ kind, outcome: "failed", result: null, expiresAt: null });
    // The same row without the creation stamp is indistinguishable from legacy.
    const legacy = await seed(kind, f.ownerId);
    await expect(read(legacy)).rejects.toMatchObject({
      data: { code: "OPERATION_RESULT_UNSUPPORTED" },
    });
  },
);
it("content kinds are versioned by their hold, never at creation", () => {
  for (const kind of ["STAT_PATH", "LIST_DIR", "MOVE_PATH", "LIST_PROCESSES", "GET_FILE"])
    expect(initialResultFields(kind, true)).toEqual({});
});

it("a cursor read uses one snapshot: a generation bump after the pre-read is stale (B1-C-9)", async () => {
  const f = await seed("LIST_DIR");
  await reserve(f);
  const continuation = {
    lastKey: "x",
    root: "/",
    depth: 1,
    limit: 100,
    generation: 1,
    kind: "LIST_DIR" as const,
  };
  await publish(
    f,
    {
      type: "file.list",
      path: "/",
      depth: 1,
      items: [entry],
      nextCursor: f.operationId,
      consistency: "live",
    },
    continuation,
  );
  const input = { cursor: f.operationId, sandboxId: f.sandboxId, ...continuation };
  expect((await readResultContinuation(sessionPrincipal(f.ownerId), input)).continuation).toEqual(
    continuation,
  );
  // The authorization pre-read sees generation 1; the sandbox advances
  // before the snapshot transaction begins.
  const original = db.prisma.sandboxOperation.findFirst.bind(db.prisma.sandboxOperation);
  const spy = vi
    .spyOn(db.prisma.sandboxOperation, "findFirst")
    .mockImplementationOnce(async (args) => {
      const row = await original(args as never);
      await db.inspect.sandbox.update({ where: { id: f.sandboxId }, data: { generation: 2 } });
      return row as never;
    });
  try {
    await expect(readResultContinuation(sessionPrincipal(f.ownerId), input)).rejects.toMatchObject({
      status: 409,
      data: { code: "RESULT_CURSOR_STALE" },
    });
    expect(spy).toHaveBeenCalledTimes(1);
  } finally {
    spy.mockRestore();
  }
});

it.each(["STAT_PATH", "MKDIR"] as const)(
  "B1R2-C-1 %s store locks O before reading the dispatch fence",
  async (kind) => {
    const f = await seed(kind);
    if (kind === "STAT_PATH") await reserve(f);
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "SUCCEEDED", ...DISPATCHED },
    });
    const gate = db.pauseAt("replacement", { before: "$transaction.commit" });
    const replacement = db.run("replacement", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.sandboxOperation.update({
          where: { id: f.operationId },
          data: { dispatchAttempt: 2 },
        });
      }),
    );
    await gate.waitReached();
    // Isolate the store's own O-lock guarantee. Production ingress has already
    // taken owner/H/S; neither actor in this probe seeks any earlier lock.
    const write = db.run("store", () =>
      db.prisma.$transaction((tx) =>
        kind === "STAT_PATH"
          ? publishOperationResult(tx, {
              ...f,
              sender: SENDER,
              attempt: 1,
              payload,
              observedAt: new Date(),
            })
          : storeScalarOperationResult(tx, {
              ...f,
              sender: SENDER,
              attempt: 1,
              payload: { type: "file.mkdir", created: true },
              observedAt: new Date(),
            }),
      ),
    );
    const refused = expect(write).rejects.toThrow();
    const blocked = await db.waitUntilBlocked("store", { by: "replacement" });
    expect(blocked.query).toContain("FOR UPDATE");
    gate.release();
    await replacement;
    await refused;
    expect((await operation(f)).scalarResult).toBeNull();
    if (kind === "STAT_PATH") expect((await hold(f)).reservationState).toBe("RESERVED");
  },
);

it.each([false, true])(
  "B1R2-T-3 process pages bind owned incarnations and accepted descriptions (truncated=%s)",
  async (argsTruncated) => {
    const f = await seed("LIST_PROCESSES");
    await reserve(f);
    const startedAt = "2026-10-27T00:00:00.000Z";
    const command = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: f.ownerId,
        sandboxId: f.sandboxId,
        generation: 1,
        kind: "RUN_COMMAND",
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
        ...DISPATCHED,
        processId: randomUUID(),
        processPid: 42,
        processStartedAt: new Date(startedAt),
        processDescription: { cmd: "true", args: ["prefix"], argsTruncated, cwd: "/" },
      },
    });
    const item = {
      process: {
        sandboxId: f.sandboxId,
        generation: 1,
        attempt: 1,
        processId: command.processId!,
        pid: 42,
      },
      operationId: command.id,
      kind: "command",
      cmd: "true",
      args: ["prefix"],
      argsTruncated,
      cwd: "/",
      startedAt,
      observedAt: startedAt,
    };
    const page = (entry: typeof item) => ({
      type: "process.list",
      items: [entry],
      nextCursor: null,
      consistency: "live",
    });
    for (const entry of [
      { ...item, cmd: "false" },
      { ...item, args: ["mislabelled"] },
      { ...item, cwd: "/other" },
      { ...item, argsTruncated: !argsTruncated },
      { ...item, operationId: "unknown" },
      { ...item, process: { ...item.process, processId: "foreign" } },
      { ...item, process: { ...item.process, pid: 43 } },
      { ...item, process: { ...item.process, attempt: 2 } },
    ])
      await expect(publish(f, page(entry))).rejects.toThrow();
    const foreign = await seed("RUN_COMMAND");
    await expect(publish(f, page({ ...item, operationId: foreign.operationId }))).rejects.toThrow();
    await publish(f, page(item));
    expect((await hold(f)).reservationState).toBe("PUBLISHED");
  },
);

it("private descriptions expire with first completion even when an older UNKNOWN/lifecycle writer omits their deadline", async () => {
  const { purgeExpiredProcessDescriptions, sweepOperationResults } = await import(
    "./operation-results"
  );
  const ownerId = "zz-b4-description-owner";
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: "description@example.test" },
  });
  const f = await seed("RUN_COMMAND", ownerId);
  const active = await seed("RUN_COMMAND", f.ownerId);
  const description = { cmd: "private-command", args: [], argsTruncated: false, cwd: "/" };
  for (const operationId of [f.operationId, active.operationId])
    await db.inspect.sandboxOperation.update({
      where: { id: operationId },
      data: { processDescription: description },
    });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: {
      state: "UNKNOWN_OUTCOME",
      completedAt: new Date(Date.now() - 86_400_001),
      processDescriptionExpiresAt: null,
    },
  });
  await sweepOperationResults("z");
  expect((await operation(f)).processDescription).toBeNull();
  expect((await operation(active)).processDescription).toEqual(description);
  expect(await purgeExpiredProcessDescriptions(f.ownerId)).toBe(0);
});
