import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { IMAGE_ENCRYPTION_RECORD_BYTES } from "@wssp/sandbox-contracts";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64), BETTER_AUTH_URL: "http://localhost:3000" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: {},
  ensureRunnableJob: vi.fn(),
}));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * The disk offload store against real PostgreSQL: markStored's two CASes and the start×verify race,
 * the admission supersede (start×upload), shred completeness at every
 * terminal, quota and ledger sums, enqueue under locks, verify with real
 * record crypto over an in-memory object, and the maintenance passes.
 */
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
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

const { seedOwner } = await import("../../webhooks/testing/fixtures");
const service = await import("../../credentials/service");
const { seedOpenDiskSession, seedStoppedOnHost } = await import("../testing/offload-fixtures");
const {
  abortDiskSession,
  completeDiskSession,
  generateDiskDek,
  loadDiskObjectKey,
  newDiskSessionWrap,
  readDiskWrapKeys,
} = await import("./keys");
const store = await import("./store");
const { offloadSpentTodayBytes, offloadUsageBytes } = await import("./quota");
const {
  enqueueOffload,
  offloadCandidates,
  OFFLOAD_RELEASE_WAIT_MS,
  OFFLOAD_RETRY_BACKOFF_MS,
  OFFLOAD_STAGING_RETRY_MS,
} = await import("./enqueue");
const { verifyDiskOffload } = await import("./verify");
const { maintainDiskOffloads } = await import("./maintenance");
const { encryptRecord } = await import("../image-store/s3");

const keys = () => readDiskWrapKeys() ?? undefined;

async function world() {
  const owner = await seedOwner(db.inspect);
  const seeded = await seedStoppedOnHost(db.inspect, { userId: owner });
  return { owner, ...seeded };
}

/** An offload of `w.sandbox` moved to VERIFYING by the real Complete CAS. */
async function verifying(w: Awaited<ReturnType<typeof world>>, generation?: number) {
  const open = await db.prisma.$transaction((tx) =>
    seedOpenDiskSession(tx, {
      userId: w.owner,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      keys: keys(),
    }),
  );
  await db.inspect.sandboxDiskOffload.update({
    where: { id: open.offloadId },
    data: {
      sourceGeneration: generation ?? w.sandbox.generation,
      fingerprint: `sha256:${"d".repeat(64)}`,
      sizeBytes: 1024n,
    },
  });
  expect(await db.prisma.$transaction((tx) => completeDiskSession(tx, open))).toBe(true);
  const row = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
    where: { id: open.offloadId },
  });
  return { ...open, objectKey: row.objectKey! };
}

/** Every wrap held anywhere for one offload (S3 shred completeness). */
async function wrapsHeld(offloadId: string) {
  const [row] = await db.inspect.$queryRaw<{ offload: number; sessions: number }[]>`SELECT
    (SELECT count(*)::int FROM sandbox_disk_offload WHERE id = ${offloadId}
      AND ("wrappedKey" IS NOT NULL OR "wrapSalt" IS NOT NULL OR "wrapNonce" IS NOT NULL)) AS offload,
    (SELECT count(*)::int FROM sandbox_image_upload_session WHERE "diskOffloadId" = ${offloadId}
      AND ("wrappedKey" IS NOT NULL OR "wrapSalt" IS NOT NULL OR "wrappedKeyNonce" IS NOT NULL)) AS sessions`;
  return row;
}

describe("markStored (T1)", () => {
  it("VERIFYING → STORED binds the sandbox's diskOffloadId and cachedOffloadSeq", async () => {
    const w = await world();
    const v = await verifying(w);
    expect(
      await store.markStored(v.offloadId, {
        completedSessionId: v.sessionId,
        objectKey: v.objectKey,
      }),
    ).toEqual({
      kind: "stored",
      offloadId: v.offloadId,
    });
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: v.offloadId },
    });
    expect(offload.state).toBe("STORED");
    expect(offload.verifiedAt).not.toBeNull();
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } }),
    ).toMatchObject({ diskOffloadId: v.offloadId, cachedOffloadSeq: offload.seq });
  });

  it("start×verify: a generation bump before STORED supersedes and shreds instead", async () => {
    const w = await world();
    const v = await verifying(w);
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { generation: { increment: 1 } },
    });
    const outcome = await store.markStored(v.offloadId, {
      completedSessionId: v.sessionId,
      objectKey: v.objectKey,
    });
    expect(outcome.kind).toBe("superseded");
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: v.offloadId },
    });
    expect(offload).toMatchObject({ state: "SUPERSEDED", liveSandboxId: null });
    expect(offload.shreddedAt).not.toBeNull();
    expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 0, sessions: 0 });
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } })).diskOffloadId,
    ).toBeNull();
  });

  it("an offload the admission already superseded is a no-op, never a second terminal write", async () => {
    const w = await world();
    const v = await verifying(w);
    const ended = await db.prisma.$transaction(async (tx) => {
      await store.lockSandboxRow(tx, w.sandbox.id);
      return store.supersedeLiveOffload(tx, w.sandbox.id);
    });
    expect(ended?.objectKey).toBe(v.objectKey);
    const before = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: v.offloadId },
    });
    expect(
      await store.markStored(v.offloadId, {
        completedSessionId: v.sessionId,
        objectKey: v.objectKey,
      }),
    ).toEqual({ kind: "noop" });
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } }),
    ).toEqual(before);
  });

  it("unsettled logins at STORED → FAILED(login_unsettled) with a shred (U8)", async () => {
    const w = await world();
    const v = await verifying(w);
    const actor = { kind: "session", ownerId: w.owner } as const;
    const definition = await service.createDefinition(actor, {
      document: {
        schemaVersion: 1,
        id: "fakecli",
        displayName: "Fake CLI",
        login: { command: "fakecli login", method: "device-code" },
        credentials: { files: { required: [".fakecli/token"], optional: [], exclude: [] } },
      },
    });
    const login = await service.createLogin(actor, {
      name: "fakecli",
      definitionId: definition.id,
    });
    const account = await service.createAccount(actor, { credentialId: login.id, name: "a" });
    const instance = await service.createInstance(actor, {
      credentialId: login.id,
      accountId: account.id,
    });
    await db.inspect.credentialLease.create({
      data: {
        userId: w.owner,
        credentialId: login.id,
        accountId: account.id,
        instanceId: instance.id,
        sandboxId: w.sandbox.id,
        operationId: "op",
        kind: "WORKLOAD",
        exclusive: false,
        state: "ACTIVE",
      },
    });
    const outcome = await store.markStored(v.offloadId, {
      completedSessionId: v.sessionId,
      objectKey: v.objectKey,
    });
    expect(outcome.kind).toBe("login_unsettled");
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } }),
    ).toMatchObject({ state: "FAILED", failureCode: "login_unsettled", liveSandboxId: null });
    expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 0, sessions: 0 });
  });
});

describe("admission supersede (X2) and shred completeness (S3)", () => {
  it("start×upload: the OPEN session is aborted, wraps nulled, transfer cancelled; the next offload inserts", async () => {
    const w = await world();
    const open = await db.prisma.$transaction((tx) =>
      seedOpenDiskSession(tx, {
        userId: w.owner,
        sandboxId: w.sandbox.id,
        hostId: w.host.id,
        keys: keys(),
      }),
    );
    await db.inspect.sandboxImageUploadSession.update({
      where: { id: open.sessionId },
      data: { uploadId: "up-1" },
    });
    const ended = await db.prisma.$transaction(async (tx) => {
      await store.lockSandboxRow(tx, w.sandbox.id);
      return store.supersedeLiveOffload(tx, w.sandbox.id);
    });
    expect(ended?.sessions).toEqual([
      expect.objectContaining({ id: open.sessionId, uploadId: "up-1" }),
    ]);
    expect(await wrapsHeld(open.offloadId)).toEqual({ offload: 0, sessions: 0 });
    expect(
      await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { id: open.sessionId },
      }),
    ).toMatchObject({ state: "ABORTED", liveDiskOffloadId: null });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: open.transferId } }),
    ).toMatchObject({ state: "CANCELLED", endReason: "superseded" });
    const calls: string[] = [];
    await store.finishEndedOffload(
      {
        abortMultipart: async (_key: string, id: string) => {
          calls.push(`abort ${id}`);
        },
        deleteObject: async (key: string) => {
          calls.push(`delete ${key}`);
        },
      },
      ended,
    );
    expect(calls).toEqual(["abort up-1"]);
    // liveSandboxId is free again.
    await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        seq: 2,
        sourceGeneration: 1,
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        liveSandboxId: w.sandbox.id,
      },
    });
    // A STORED offload is never superseded here.
    expect(
      await db.prisma.$transaction((tx) => store.endLiveOffload(tx, open.offloadId, "FAILED", "x")),
    ).toBeNull();
  });

  it.each([["FAILED"], ["SUPERSEDED"]] as const)(
    "%s at VERIFYING leaves no wrap in either table",
    async (terminal) => {
      const w = await world();
      const v = await verifying(w);
      expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 1, sessions: 0 });
      await db.prisma.$transaction(async (tx) => {
        await store.lockSandboxRow(tx, w.sandbox.id);
        await store.endLiveOffload(tx, v.offloadId, terminal, "x");
      });
      expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 0, sessions: 0 });
    },
  );
});

describe("quota and ledger (§6, §6a, R11)", () => {
  it("usage sums live rows (a completed row's bytes, else its OPEN session's); CONSUMED never counts", async () => {
    const w = await world();
    const v = await verifying(w);
    const stored = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: v.offloadId },
    });
    const other = await seedStoppedOnHost(db.inspect, { userId: w.owner });
    await db.prisma.$transaction((tx) =>
      seedOpenDiskSession(tx, {
        userId: w.owner,
        sandboxId: other.sandbox.id,
        hostId: other.host.id,
        keys: keys(),
      }),
    );
    const usage = () => db.prisma.$transaction((tx) => offloadUsageBytes(tx, w.owner));
    expect(await usage()).toBe((stored.storedBytes ?? 0n) + 1056n);
    await db.inspect
      .$executeRaw`UPDATE sandbox_disk_offload SET state = 'FAILED', "liveSandboxId" = NULL
      WHERE id = ${v.offloadId}`;
    await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        seq: 9,
        sourceGeneration: 1,
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        state: "CONSUMED",
        storedBytes: 1n << 40n,
        consumedAt: new Date(),
        deleteAfter: new Date(Date.now() + 3_600_000),
      },
    });
    expect(await usage()).toBe(1056n);
  });

  it("the ledger counts today's OFFLOAD_UPLOAD bytes only (never RESTORE_FETCH, never yesterday)", async () => {
    const owner = await seedOwner(db.inspect);
    const now = new Date();
    const transfer = (purpose: "OFFLOAD_UPLOAD" | "RESTORE_FETCH", createdAt: Date, size: bigint) =>
      db.inspect.sandboxImageTransfer.create({
        data: {
          userId: owner,
          fingerprint: `sha256:${"d".repeat(64)}`,
          purpose,
          mode: "S3",
          state: "COMPLETE",
          sizeBytes: size,
          partSize: 1,
          partCount: 1,
          expiresAt: now,
          createdAt,
        },
      });
    await transfer("OFFLOAD_UPLOAD", now, 10n);
    await transfer("OFFLOAD_UPLOAD", now, 5n);
    await transfer("RESTORE_FETCH", now, 1000n);
    await transfer("OFFLOAD_UPLOAD", new Date(now.getTime() - 2 * 86_400_000), 1000n);
    expect(await offloadSpentTodayBytes(db.prisma, owner, now)).toBe(15n);
  });
});

describe("enqueue (§7: one export per host, two per account; §4, N4)", () => {
  it("a candidate inserts PENDING with seq = ++offloadSeq; a second for the same host waits", async () => {
    const w = await world();
    const [candidate] = (await offloadCandidates()).filter((c) => c.sandboxId === w.sandbox.id);
    expect(candidate).toBeDefined();
    const enqueued = await enqueueOffload(candidate!);
    expect(enqueued).toMatchObject({ sandboxId: w.sandbox.id, seq: 1, generation: 1 });
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: enqueued!.offloadId } }),
    ).toMatchObject({ state: "PENDING", liveSandboxId: w.sandbox.id, sourceHostId: w.host.id });
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } })).offloadSeq,
    ).toBe(1);
    // A second sandbox on the same host: one export per host.
    const { seedSandboxInstance } = await import("../testing/resource-fixtures");
    const twin = await seedSandboxInstance(db.inspect, {
      data: {
        userId: w.owner,
        templateId: w.revision.id,
        sandboxHostId: w.host.id,
        hostOwnerId: w.owner,
        originHostId: w.host.id,
        state: "STOPPED",
      },
    });
    expect((await offloadCandidates()).some((c) => c.sandboxId === twin.id)).toBe(false);
    expect(
      await enqueueOffload({ ...candidate!, sandboxId: twin.id, generation: twin.generation }),
    ).toBeNull();
    // C9 live: still busy at VERIFYING (the daemon holds that export's
    // staging until the stored ack), free once the export ends.
    await db.inspect.sandboxDiskOffload.update({
      where: { id: enqueued!.offloadId },
      data: { state: "VERIFYING" },
    });
    expect((await offloadCandidates()).some((c) => c.sandboxId === twin.id)).toBe(false);
    expect(
      await enqueueOffload({ ...candidate!, sandboxId: twin.id, generation: twin.generation }),
    ).toBeNull();
    await db.inspect.sandboxDiskOffload.update({
      where: { id: enqueued!.offloadId },
      data: { state: "FAILED", liveSandboxId: null },
    });
    expect((await offloadCandidates()).some((c) => c.sandboxId === twin.id)).toBe(true);
  });

  it("a STORED export holds its host's slot until the daemon confirms the release", async () => {
    const w = await world();
    const { seedSandboxInstance } = await import("../testing/resource-fixtures");
    const { seedStoredOffload } = await import("../testing/offload-fixtures");
    const exported = await seedSandboxInstance(db.inspect, {
      data: {
        userId: w.owner,
        templateId: w.revision.id,
        sandboxHostId: w.host.id,
        hostOwnerId: w.owner,
        originHostId: w.host.id,
        state: "STOPPED",
      },
    });
    const stored = await db.prisma.$transaction((tx) =>
      seedStoredOffload(tx, {
        userId: w.owner,
        sandboxId: exported.id,
        hostId: w.host.id,
        keys: keys(),
      }),
    );
    const now = new Date();
    const candidate = async () =>
      (await offloadCandidates(now)).find((c) => c.sandboxId === w.sandbox.id) ?? null;
    // The scheduler's ack raced the verification: STORED, not yet released.
    expect(await candidate()).toBeNull();
    expect(
      await enqueueOffload(
        {
          sandboxId: w.sandbox.id,
          userId: w.owner,
          generation: w.sandbox.generation,
          hostId: w.host.id,
          hostOwnerId: w.owner,
          epoch: w.host.connectionEpoch,
        },
        now,
      ),
    ).toBeNull();
    // Liveness backstop: an unreleased row stops holding the slot later.
    const later = new Date(now.getTime() + OFFLOAD_RELEASE_WAIT_MS + 1000);
    expect((await offloadCandidates(later)).some((c) => c.sandboxId === w.sandbox.id)).toBe(true);
    // `disk.offload.released` frees it now.
    await db.inspect.sandboxDiskOffload.update({
      where: { id: stored.offloadId },
      data: { sourceReleasedAt: now },
    });
    const free = await candidate();
    expect(free).not.toBeNull();
    expect(await enqueueOffload(free!, now)).toMatchObject({ sandboxId: w.sandbox.id });
  });

  it("at most two exports per account; managed purposes and unsettled receipts never enqueue", async () => {
    const owner = await seedOwner(db.inspect);
    const worlds = [];
    for (let i = 0; i < 3; i++) worlds.push(await seedStoppedOnHost(db.inspect, { userId: owner }));
    const mine = () => offloadCandidates().then((all) => all.filter((c) => c.userId === owner));
    const started = [];
    for (const c of await mine()) {
      const e = await enqueueOffload(c);
      if (e) started.push(e);
    }
    expect(started).toHaveLength(2);
    expect(await mine()).toEqual([]);
    // Managed purpose: never a candidate.
    const managed = await seedOwner(db.inspect);
    const build = await seedStoppedOnHost(db.inspect, {
      userId: managed,
      sandbox: { purpose: "TEMPLATE_BUILD", buildId: randomUUID() },
    });
    expect((await offloadCandidates()).some((c) => c.sandboxId === build.sandbox.id)).toBe(false);
    // An in-flight command of the stopped generation refuses under locks.
    const busy = await world();
    await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v1" }),
        ...requestDigestMetadata(),

        userId: busy.owner,
        sandboxId: busy.sandbox.id,
        kind: "RUN_COMMAND",
        state: "UNKNOWN_OUTCOME",
        generation: busy.sandbox.generation,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
      },
    });
    const [candidate] = (await offloadCandidates()).filter((c) => c.sandboxId === busy.sandbox.id);
    expect(await enqueueOffload(candidate!)).toBeNull();
  });

  it("a failed attempt of the same generation backs off", async () => {
    const w = await world();
    await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        seq: 1,
        sourceGeneration: w.sandbox.generation,
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        state: "FAILED",
      },
    });
    expect((await offloadCandidates()).some((c) => c.sandboxId === w.sandbox.id)).toBe(false);
    expect(
      (await offloadCandidates(new Date(Date.now() + 3_600_000))).some(
        (c) => c.sandboxId === w.sandbox.id,
      ),
    ).toBe(true);
  });

  it("a staging_full attempt retries after minutes, not the half-hour backoff", async () => {
    const w = await world();
    await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: w.sandbox.id,
        userId: w.owner,
        seq: 1,
        sourceGeneration: w.sandbox.generation,
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        state: "FAILED",
        failureCode: "staging_full",
      },
    });
    const at = (ms: number) =>
      offloadCandidates(new Date(Date.now() + ms)).then((all) =>
        all.some((c) => c.sandboxId === w.sandbox.id),
      );
    expect(await at(0)).toBe(false);
    expect(await at(OFFLOAD_STAGING_RETRY_MS + 5_000)).toBe(true);
    expect(OFFLOAD_STAGING_RETRY_MS).toBeLessThan(OFFLOAD_RETRY_BACKOFF_MS);
    // Any other failure still waits the full backoff.
    await db.inspect.sandboxDiskOffload.updateMany({
      where: { sandboxId: w.sandbox.id },
      data: { failureCode: "io" },
    });
    expect(await at(OFFLOAD_STAGING_RETRY_MS + 5_000)).toBe(false);
  });
});

/** An in-memory object holding `plain` sealed with the offload's own key. */
async function sealedObject(offloadId: string, plain: Buffer) {
  const key = await loadDiskObjectKey(db.prisma, offloadId);
  const records = Math.max(1, Math.ceil(plain.length / IMAGE_ENCRYPTION_RECORD_BYTES));
  const parts: Buffer[] = [];
  for (let i = 0; i < records; i++)
    parts.push(
      encryptRecord(
        key,
        i,
        i === records - 1,
        plain.subarray(i * IMAGE_ENCRYPTION_RECORD_BYTES, (i + 1) * IMAGE_ENCRYPTION_RECORD_BYTES),
      ),
    );
  key.fill(0);
  return Buffer.concat(parts);
}

function memoryStore(objects: Map<string, Buffer>, deleted: string[]) {
  return {
    getObjectStream: async (key: string) => {
      const body = objects.get(key);
      if (!body) throw Object.assign(new Error("NoSuchKey"), { name: "NoSuchKey" });
      return (async function* () {
        yield new Uint8Array(body);
      })();
    },
    deleteObject: async (key: string) => {
      deleted.push(key);
      objects.delete(key);
    },
    abortMultipart: async () => {},
    objectExists: async (key: string) => objects.has(key),
  } as never;
}

describe("disk verify (S1)", () => {
  it("a transient stream failure preserves VERIFYING and its wrapped key", async () => {
    const w = await world();
    const v = await verifying(w);
    const before = await wrapsHeld(v.offloadId);
    const failure = Object.assign(new Error("connection reset"), { code: "ECONNRESET" });
    const deleted = vi.fn(async () => {});
    await expect(
      verifyDiskOffload(v.offloadId, {
        getObjectStream: async () =>
          (async function* () {
            yield Buffer.alloc(2);
            throw failure;
          })(),
        deleteObject: deleted,
      } as never),
    ).rejects.toBe(failure);
    expect(
      (await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } })).state,
    ).toBe("VERIFYING");
    expect(before.offload).toBe(1);
    expect(await wrapsHeld(v.offloadId)).toEqual(before);
    expect(deleted).not.toHaveBeenCalled();
  });

  async function verifiable(plain: Buffer) {
    const w = await world();
    const v = await verifying(w);
    await db.inspect.sandboxDiskOffload.update({
      where: { id: v.offloadId },
      data: {
        fingerprint: `sha256:${createHash("sha256").update(plain).digest("hex")}`,
        sizeBytes: BigInt(plain.length),
      },
    });
    return { w, v };
  }

  it("decrypts, hashes and sizes the object, then stores it", async () => {
    const plain = randomBytes(3000);
    const { w, v } = await verifiable(plain);
    const objects = new Map([[v.objectKey, await sealedObject(v.offloadId, plain)]]);
    expect(await verifyDiskOffload(v.offloadId, memoryStore(objects, []))).toBe("stored");
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } })).diskOffloadId,
    ).toBe(v.offloadId);
  });

  it("a tampered object is FAILED(corrupt), shredded and deleted, never STORED", async () => {
    const plain = randomBytes(3000);
    const { v } = await verifiable(plain);
    const sealed = await sealedObject(v.offloadId, plain);
    sealed[10] = (sealed[10] ?? 0) ^ 1;
    const deleted: string[] = [];
    expect(
      await verifyDiskOffload(v.offloadId, memoryStore(new Map([[v.objectKey, sealed]]), deleted)),
    ).toBe("corrupt");
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } }),
    ).toMatchObject({ state: "FAILED", failureCode: "corrupt" });
    expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 0, sessions: 0 });
    expect(deleted).toEqual([v.objectKey]);
  });
});

describe("maintenance (§3 retention, §6a grace, backstops)", () => {
  it.each([true, false])(
    "verification expires after 24h as unavailable and shreds wraps (store configured: %s)",
    async (configured) => {
      const w = await world();
      const expired = await verifying(w);
      const retryWorld = await world();
      const retry = await verifying(retryWorld);
      const now = new Date();
      const cutoff = new Date(now.getTime() - 24 * 3_600_000);
      await db.inspect.sandboxDiskOffload.update({
        where: { id: expired.offloadId },
        data: { updatedAt: cutoff },
      });
      await db.inspect.sandboxDiskOffload.update({
        where: { id: retry.offloadId },
        data: { updatedAt: new Date(cutoff.getTime() + 1) },
      });
      expect(await offloadUsageBytes(db.prisma, w.owner)).toBeGreaterThan(0n);
      const objects = new Map([[expired.objectKey, Buffer.from("untrusted")]]);
      const deleted: string[] = [];
      const enqueued: string[] = [];
      await maintainDiskOffloads(
        configured ? memoryStore(objects, deleted) : null,
        now,
        async (id) => {
          enqueued.push(id);
        },
      );
      const row = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
        where: { id: expired.offloadId },
      });
      expect(row).toMatchObject({
        state: "FAILED",
        failureCode: "verify_unavailable",
        liveSandboxId: null,
      });
      expect(row.shreddedAt).not.toBeNull();
      expect(await wrapsHeld(expired.offloadId)).toEqual({ offload: 0, sessions: 0 });
      expect(await offloadUsageBytes(db.prisma, w.owner)).toBe(0n);
      expect(enqueued).not.toContain(expired.offloadId);
      expect(deleted).toEqual(configured ? [expired.objectKey] : []);
      expect(
        await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: retry.offloadId } }),
      ).toMatchObject({ state: "VERIFYING", failureCode: null, shreddedAt: null });
      expect(enqueued.includes(retry.offloadId)).toBe(configured);
    },
  );

  it("verification completed after the timeout scan survives the locked re-check", async () => {
    const w = await world();
    const v = await verifying(w);
    const now = new Date();
    await db.inspect.sandboxDiskOffload.update({
      where: { id: v.offloadId },
      data: { updatedAt: new Date(now.getTime() - 25 * 3_600_000) },
    });
    const scan = db.pauseAt("verify-timeout", { after: "sandboxDiskOffload.findMany" });
    const deleted: string[] = [];
    const maintenance = db.run("verify-timeout", () =>
      maintainDiskOffloads(memoryStore(new Map(), deleted), now),
    );
    try {
      await scan.waitReached();
      expect(
        await store.markStored(v.offloadId, {
          completedSessionId: v.sessionId,
          objectKey: v.objectKey,
        }),
      ).toMatchObject({ kind: "stored" });
    } finally {
      scan.release();
    }
    await maintenance;
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } }),
    ).toMatchObject({ state: "STORED", failureCode: null, shreddedAt: null });
    expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 1, sessions: 0 });
    expect(deleted).not.toContain(v.objectKey);
  });

  it("a begin committed after the stale scan preserves the fresh upload and session wrap", async () => {
    const w = await world();
    const now = new Date();
    const open = await db.prisma.$transaction((tx) =>
      seedOpenDiskSession(tx, {
        userId: w.owner,
        sandboxId: w.sandbox.id,
        hostId: w.host.id,
        keys: keys(),
      }),
    );
    // Begin replaces the candidate's expired session while cleanup is parked.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: open.transferId },
      data: { expiresAt: new Date(now.getTime() - 1000) },
    });
    const scanned = db.pauseAt("maintenance", {
      after: /SELECT o.id, o."sandboxId" FROM sandbox_disk_offload o WHERE/,
    });
    const maintenance = db.run("maintenance", () => maintainDiskOffloads(null, now));
    try {
      await scanned.waitReached();
      await db.inspect.$transaction(async (tx) => {
        await store.lockSandboxRow(tx, w.sandbox.id);
        await abortDiskSession(tx, open.sessionId, "superseded");
        await tx.sandboxImageTransfer.update({
          where: { id: open.transferId },
          data: { state: "CANCELLED", endReason: "superseded" },
        });
        const transfer = await tx.sandboxImageTransfer.create({
          data: {
            userId: w.owner,
            fingerprint: `sha256:${"d".repeat(64)}`,
            purpose: "OFFLOAD_UPLOAD",
            mode: "S3",
            sourceHostId: w.host.id,
            sourceHostOwnerId: w.owner,
            sizeBytes: 1024n,
            partSize: 1024,
            partCount: 1,
            expiresAt: new Date(now.getTime() + 60_000),
            diskOffloadId: open.offloadId,
          },
        });
        const sessionId = store.newDiskSessionId();
        const dek = generateDiskDek();
        const wrap = await newDiskSessionWrap(
          tx,
          {
            userId: w.owner,
            sandboxId: w.sandbox.id,
            offloadId: open.offloadId,
            seq: 1,
            sessionId,
          },
          dek,
          keys(),
        );
        dek.fill(0);
        await tx.sandboxImageUploadSession.create({
          data: {
            id: sessionId,
            transferId: transfer.id,
            diskOffloadId: open.offloadId,
            liveDiskOffloadId: open.offloadId,
            userId: w.owner,
            hostId: w.host.id,
            hostEpoch: w.host.connectionEpoch,
            objectKey: store.diskStoreObjectKey("wssp", {
              ownerId: w.owner,
              sandboxId: w.sandbox.id,
              offloadId: open.offloadId,
              sessionId,
            }),
            sizeBytes: 1024n,
            storedBytes: 1056n,
            partSize: 1056,
            ...wrap,
          },
        });
        await tx.sandboxDiskOffload.update({
          where: { id: open.offloadId },
          data: { updatedAt: now },
        });
      });
    } finally {
      scanned.release();
    }
    await maintenance;
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: open.offloadId } }),
    ).toMatchObject({ state: "UPLOADING", shreddedAt: null, failureCode: null });
    expect(await wrapsHeld(open.offloadId)).toEqual({ offload: 0, sessions: 1 });
    expect(
      await db.inspect.sandboxImageUploadSession.count({
        where: { liveDiskOffloadId: open.offloadId, state: "OPEN" },
      }),
    ).toBe(1);
  });

  it("a sandbox that moved on supersedes its live offload; a stale PENDING fails", async () => {
    const w = await world();
    const v = await verifying(w);
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "READY" } });
    const pending = await world();
    const old = await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: pending.sandbox.id,
        userId: pending.owner,
        seq: 1,
        sourceGeneration: pending.sandbox.generation,
        sourceHostId: pending.host.id,
        sourceHostOwnerId: pending.owner,
        liveSandboxId: pending.sandbox.id,
        updatedAt: new Date(Date.now() - 3 * 3_600_000),
      },
    });
    const result = await maintainDiskOffloads(
      memoryStore(new Map(), []),
      new Date(),
      async () => {},
    );
    expect(result.superseded).toBeGreaterThanOrEqual(1);
    expect(
      (await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: v.offloadId } })).state,
    ).toBe("SUPERSEDED");
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: old.id } }),
    ).toMatchObject({ state: "FAILED", failureCode: "stale" });
  });

  it("a CONSUMED copy past its grace is shredded, then its object deleted; retention forgets old rows only once the object is gone", async () => {
    const w = await world();
    const v = await verifying(w);
    // C6's READY consume, written here as data: STORED copy consumed with a past grace.
    await db.inspect.$executeRaw`UPDATE sandbox_disk_offload SET state = 'CONSUMED',
      "liveSandboxId" = NULL, "consumedAt" = now(), "deleteAfter" = now() - interval '1 minute',
      "verifiedAt" = now() WHERE id = ${v.offloadId}`;
    const objects = new Map([[v.objectKey, Buffer.from("x")]]);
    const deleted: string[] = [];
    const kept = () => store.keptDiskObjectKeys(db.prisma, [v.objectKey], new Date());
    expect((await kept()).size).toBe(0);
    await maintainDiskOffloads(memoryStore(objects, deleted), new Date(), async () => {});
    const row = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: v.offloadId },
    });
    expect(row.shreddedAt).not.toBeNull();
    expect(await wrapsHeld(v.offloadId)).toEqual({ offload: 0, sessions: 0 });
    expect(deleted).toEqual([v.objectKey]);
    // 31 days later the row goes; while the object still exists it stays.
    const later = new Date(Date.now() + 31 * 86_400_000);
    objects.set(v.objectKey, Buffer.from("x"));
    await maintainDiskOffloads(memoryStore(objects, deleted), later, async () => {});
    expect(await db.inspect.sandboxDiskOffload.count({ where: { id: v.offloadId } })).toBe(1);
    await maintainDiskOffloads(memoryStore(objects, deleted), later, async () => {});
    expect(await db.inspect.sandboxDiskOffload.count({ where: { id: v.offloadId } })).toBe(0);
    // Sessions and transfers cascade.
    expect(await db.inspect.sandboxImageUploadSession.count({ where: { id: v.sessionId } })).toBe(
      0,
    );
  });

  it("keep set: VERIFYING/STORED objects and OPEN sessions are kept; superseded sessions are not", async () => {
    const w = await world();
    const open = await db.prisma.$transaction((tx) =>
      seedOpenDiskSession(tx, {
        userId: w.owner,
        sandboxId: w.sandbox.id,
        hostId: w.host.id,
        keys: keys(),
      }),
    );
    const openKey = (
      await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { id: open.sessionId },
      })
    ).objectKey;
    const unknown = `wssp/owners/${w.owner}/sandboxes/${w.sandbox.id}/${randomUUID()}/x.wsspenc`;
    expect([
      ...(await store.keptDiskObjectKeys(db.prisma, [openKey, unknown], new Date())),
    ]).toEqual([openKey]);
    await db.prisma.$transaction(async (tx) => {
      await store.lockSandboxRow(tx, w.sandbox.id);
      await store.supersedeLiveOffload(tx, w.sandbox.id);
    });
    expect((await store.keptDiskObjectKeys(db.prisma, [openKey], new Date())).size).toBe(0);
  });
});
