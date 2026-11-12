import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64) },
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));

import { dataRootKey } from "../../crypto/data-key";
import { promoteDataKey, readDataKeyEpoch } from "../../crypto/data-key-epoch";
import { readDataKeyStatus } from "../../crypto/data-key-status";
import { seedOwner, seedSandbox } from "../../webhooks/testing/fixtures";
import {
  OFFLOAD_FIXTURE_KEYS,
  offloadSandboxForTest,
  seedOpenDiskSession,
  seedStoredOffload,
} from "../testing/offload-fixtures";
import {
  deriveDiskWrapKeys,
  loadDiskObjectKey,
  loadOpenDiskSessionKey,
  rewrapDiskKeyBatch,
  shredOffloadKeys,
} from "./keys";

/**
 * Disk offload keys and the §2 CHECKs against real PostgreSQL : Complete moves the wrap from the session to the offload; the
 * shredder aborts OPEN sessions before it nulls the offload wrap (T13) and
 * every CHECK holds at every statement; the two data-key status sources count
 * exactly the rows that hold a key; the rewrap tick moves both sources to the
 * epoch's kid; and the key CHECKs reject the rows the plan forbids. The steps
 * share this file's clone.
 */
const db = await pgTestDatabase();
const prisma = db.prisma;
afterAll(() => db.close());

const ROOT_ID = OFFLOAD_FIXTURE_KEYS.current.rootKeyId;

async function world() {
  const userId = await seedOwner(db.inspect);
  const host = await db.inspect.sandboxHost.create({
    data: { userId, slug: `h-${randomBytes(4).toString("hex")}`, label: "Host" },
    select: { id: true },
  });
  const sandbox = await seedSandbox(db.inspect, userId, "STOPPED");
  return { userId, hostId: host.id, sandboxId: sandbox.id };
}

type PgClient = {
  connect(): Promise<void>;
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  end(): Promise<void>;
};
const { Client } = createRequire(import.meta.url)("pg") as {
  Client: new (options: { connectionString: string }) => PgClient;
};
const client = new Client({ connectionString: db.url });
beforeAll(() => client.connect());
afterAll(() => client.end());

/**
 * Runs one statement in a transaction that is always rolled back; returns
 * "ok" or the refusing constraint (name without its hash suffix) and SQLSTATE.
 */
async function refused(sql: string, values: unknown[] = []): Promise<string> {
  await client.query("BEGIN");
  try {
    await client.query(sql, values);
    return "ok";
  } catch (error) {
    const { code, constraint } = error as { code?: string; constraint?: string };
    return `${code}:${(constraint ?? "").replace(/_ck[0-9a-f]{8}$/, "")}`;
  } finally {
    await client.query("ROLLBACK");
  }
}

describe("Complete and shred (§3, T13)", () => {
  it("Complete moves the session wrap to the offload; the object key opens from the offload row", async () => {
    const w = await world();
    const stored = await prisma.$transaction((tx) => seedStoredOffload(tx, w));
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { id: stored.sessionId },
      select: { state: true, liveDiskOffloadId: true, encryption: true, keyId: true },
    });
    expect(session).toEqual({
      state: "COMPLETE",
      liveDiskOffloadId: null,
      encryption: null,
      keyId: null,
    });
    const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
      where: { id: stored.offloadId },
      select: { state: true, completedSessionId: true, rootKid: true },
    });
    expect(offload).toEqual({
      state: "STORED",
      completedSessionId: stored.sessionId,
      rootKid: ROOT_ID,
    });
    const key = await prisma.$transaction((tx) =>
      loadDiskObjectKey(tx, stored.offloadId, OFFLOAD_FIXTURE_KEYS.all),
    );
    expect(key.equals(stored.dek)).toBe(true);
  });

  it("refuses to shred a STORED row and shreds it once terminal; OPEN sessions abort first", async () => {
    const w = await world();
    const stored = await prisma.$transaction((tx) => seedStoredOffload(tx, w));
    await expect(
      prisma.$transaction((tx) => shredOffloadKeys(tx, stored.offloadId)),
    ).rejects.toMatchObject({ code: "not_terminal" });
    await prisma.$transaction(async (tx) => {
      await tx.sandboxDiskOffload.update({
        where: { id: stored.offloadId },
        data: { state: "SUPERSEDED", liveSandboxId: null },
      });
      await expect(shredOffloadKeys(tx, stored.offloadId)).resolves.toEqual({
        abortedSessions: [],
      });
    });
    const shredded = await db.inspect.$queryRaw<
      { wrapped: boolean; shredded: boolean }[]
    >`SELECT "wrappedKey" IS NOT NULL AS wrapped, "shreddedAt" IS NOT NULL AS shredded
      FROM sandbox_disk_offload WHERE id = ${stored.offloadId}`;
    expect(shredded).toEqual([{ wrapped: false, shredded: true }]);
    await expect(
      prisma.$transaction((tx) =>
        loadDiskObjectKey(tx, stored.offloadId, OFFLOAD_FIXTURE_KEYS.all),
      ),
    ).rejects.toMatchObject({
      code: "not_stored",
    });

    // An OPEN session of a failing offload: aborted (state and wrap) before the shred.
    const w2 = await world();
    const open = await prisma.$transaction((tx) => seedOpenDiskSession(tx, w2));
    const resumeKey = await prisma.$transaction((tx) =>
      loadOpenDiskSessionKey(tx, open.sessionId, OFFLOAD_FIXTURE_KEYS.all),
    );
    expect(resumeKey.equals(open.dek)).toBe(true);
    await prisma.$transaction(async (tx) => {
      await tx.sandboxDiskOffload.update({
        where: { id: open.offloadId },
        data: { state: "FAILED", liveSandboxId: null, failureCode: "test" },
      });
      await expect(shredOffloadKeys(tx, open.offloadId)).resolves.toEqual({
        abortedSessions: [{ id: open.sessionId, transferId: open.transferId }],
      });
    });
    const ended = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { id: open.sessionId },
      select: {
        state: true,
        liveDiskOffloadId: true,
        encryption: true,
        keyId: true,
        endReason: true,
      },
    });
    expect(ended).toEqual({
      state: "ABORTED",
      liveDiskOffloadId: null,
      encryption: null,
      keyId: null,
      endReason: "shredded",
    });
  });
});

describe("data-key status and rewrap sources (§3)", () => {
  it("counts only rows holding a key, keeps the old root unremovable, and rewraps both sources", async () => {
    // Fresh epoch state for this step: the fixture root is the current kid.
    expect((await readDataKeyEpoch(prisma))?.currentKid).toBe(ROOT_ID);
    const w = await world();
    const live = await prisma.$transaction((tx) => seedStoredOffload(tx, w));
    const w2 = await world();
    const open = await prisma.$transaction((tx) => seedOpenDiskSession(tx, w2));
    const status = await readDataKeyStatus({ ring: null, client: prisma });
    const count = (source: string) =>
      status.counts
        .filter((row) => row.source === source && row.kid === ROOT_ID)
        .reduce((sum, row) => sum + row.rows, 0);
    // Live offload wraps (the shredded rows above hold none) and OPEN sessions.
    const liveOffloads = await db.inspect.$queryRaw<{ n: number }[]>`SELECT count(*)::int AS n
      FROM sandbox_disk_offload WHERE "wrappedKey" IS NOT NULL`;
    expect(count("sandbox_disk_offload.rootKid")).toBe(liveOffloads[0]?.n);
    expect(count("sandbox_image_upload_session.keyId")).toBeGreaterThanOrEqual(1);

    // Rotate to a new root: the old one is not removable while a wrap remains.
    const nextRoot = dataRootKey(randomBytes(32).toString("hex"));
    const oldRoot = dataRootKey("5a".repeat(32));
    const ring = { current: nextRoot, previous: oldRoot };
    expect(await promoteDataKey(ring, nextRoot.id)).toMatchObject({ ok: true, changed: true });
    const before = await readDataKeyStatus({ ring, client: prisma });
    expect(before.kids.find((kid) => kid.kid === ROOT_ID)?.safeToRemove).toBe(false);

    const keys = deriveDiskWrapKeys(ring);
    let cursor = { offload: null as string | null, session: null as string | null };
    let rewrapped = 0;
    for (let pass = 0; pass < 10; pass++) {
      const result = await prisma.$transaction((tx) =>
        rewrapDiskKeyBatch(tx, keys.current, cursor, 2, keys.all),
      );
      expect(result.failed).toBe(0);
      rewrapped += result.rewrapped;
      cursor = result.next;
      if (result.scanned === 0) break;
    }
    expect(rewrapped).toBeGreaterThanOrEqual(2);
    const after = await readDataKeyStatus({ ring, client: prisma });
    expect(after.kids.find((kid) => kid.kid === ROOT_ID)?.safeToRemove).toBe(true);

    // Both rewrapped keys still open, now under the new root, with their AAD.
    const { readDiskWrapKeys } = await import("./keys");
    const saved = process.env.DATA_ENCRYPTION_KEY;
    const savedPrevious = process.env.DATA_ENCRYPTION_KEY_PREVIOUS;
    process.env.DATA_ENCRYPTION_KEY = nextRoot.key.toString("hex");
    delete process.env.DATA_ENCRYPTION_KEY_PREVIOUS;
    try {
      expect(readDiskWrapKeys()?.current.rootKeyId).toBe(nextRoot.id);
      const objectKey = await prisma.$transaction((tx) => loadDiskObjectKey(tx, live.offloadId));
      expect(objectKey.equals(live.dek)).toBe(true);
      const sessionKey = await prisma.$transaction((tx) =>
        loadOpenDiskSessionKey(tx, open.sessionId),
      );
      expect(sessionKey.equals(open.dek)).toBe(true);
      // Back to the fixture root, so later steps' fixtures can write.
      expect(await promoteDataKey({ current: oldRoot, previous: nextRoot }, ROOT_ID)).toMatchObject(
        { ok: true, changed: true },
      );
    } finally {
      if (saved === undefined) delete process.env.DATA_ENCRYPTION_KEY;
      else process.env.DATA_ENCRYPTION_KEY = saved;
      if (savedPrevious !== undefined) process.env.DATA_ENCRYPTION_KEY_PREVIOUS = savedPrevious;
    }
  });
});

describe("§2 CHECKs reject the forbidden rows", () => {
  it("OFFLOADED is hostless and needs a stored disk; DELETED and READY never keep one", async () => {
    const w = await world();
    await prisma.$transaction((tx) => offloadSandboxForTest(tx, w));
    const other = await world();
    const foreign = await prisma.$transaction((tx) => seedStoredOffload(tx, other));
    const update = (set: string, values: unknown[] = []) =>
      refused(`UPDATE sandbox_instance SET ${set} WHERE id = $1`, [w.sandboxId, ...values]);
    expect(await update(`"sandboxHostId" = $2, "hostOwnerId" = $3`, [w.hostId, w.userId])).toBe(
      "23514:sandbox_instance_offloaded",
    );
    expect(await update(`"accessGraceUntil" = now(), "accessGraceReason" = 'access'`)).toBe(
      "23514:sandbox_instance_offloaded",
    );
    expect(await update(`"leaseExpiresAt" = now()`)).toBe("23514:sandbox_instance_offloaded");
    expect(await update(`"diskOffloadId" = NULL`)).toBe("23514:sandbox_instance_offloaded");
    expect(await update(`state = 'DELETED'`)).toBe("23514:sandbox_instance_deleted_offload");
    expect(await update(`state = 'READY'`)).toBe("23514:sandbox_instance_offload_parked");
    expect(await update(`"offloadSeq" = -1`)).toBe("23514:sandbox_instance_offload_seq");
    // U8: the current offload must be this sandbox's own row (composite FK).
    expect(await update(`"diskOffloadId" = $2`, [foreign.offloadId])).toMatch(/^23505:|^23503:/);
    expect(await update(`state = 'DELETED', "diskOffloadId" = NULL`)).toBe("ok");
  });

  it("rejects EVICTING without a grant, STORED without proof, a shredded wrap and a half wrap", async () => {
    const w = await world();
    const stored = await prisma.$transaction((tx) => seedStoredOffload(tx, w));
    const update = (set: string, values: unknown[] = []) =>
      refused(`UPDATE sandbox_disk_offload SET ${set} WHERE id = $1`, [
        stored.offloadId,
        ...values,
      ]);
    const grant = `"evictGrantId" = 'g', "evictHostId" = $2, "evictGrantEpoch" = 1, "evictGrantExpiresAt" = now()`;
    expect(await update(`state = 'EVICTING'`)).toBe("23514:sandbox_disk_offload_evict");
    expect(await update(grant, [w.hostId])).toBe("23514:sandbox_disk_offload_evict");
    expect(await update(`state = 'EVICTING', ${grant}`, [w.hostId])).toBe("ok");
    expect(await update(`state = 'EVICTING', "evictGrantId" = 'g'`)).toBe(
      "23514:sandbox_disk_offload_evict",
    );
    expect(await update(`"verifiedAt" = NULL`)).toBe("23514:sandbox_disk_offload_stored");
    expect(await update(`fingerprint = 'nope'`)).toBe("23514:sandbox_disk_offload_stored");
    expect(await update(`state = 'CONSUMED'`)).toBe("23514:sandbox_disk_offload_live");
    expect(await update(`state = 'CONSUMED', "liveSandboxId" = NULL, "shreddedAt" = now()`)).toBe(
      "23514:sandbox_disk_offload_shredded",
    );
    expect(await update(`state = 'CONSUMED', "liveSandboxId" = NULL, "wrapNonce" = NULL`)).toBe(
      "23514:sandbox_disk_offload_wrap_all",
    );
    expect(await update(`state = 'CONSUMED', "liveSandboxId" = NULL`)).toBe("ok");
  });

  it("rejects a disk session OPEN without a wrap, closed with one, without a salt, or with two targets", async () => {
    const w = await world();
    const open = await prisma.$transaction((tx) => seedOpenDiskSession(tx, w));
    const update = (set: string) =>
      refused(`UPDATE sandbox_image_upload_session SET ${set} WHERE id = $1`, [open.sessionId]);
    const nullWrap = `encryption = NULL, "wrappedKey" = NULL, "wrappedKeyNonce" = NULL, "keyId" = NULL, "wrapSalt" = NULL`;
    expect(await update(nullWrap)).toBe("23514:sandbox_image_upload_session_disk_key");
    expect(await update(`state = 'ABORTED', "liveDiskOffloadId" = NULL`)).toBe(
      "23514:sandbox_image_upload_session_disk_key",
    );
    expect(await update(`"wrapSalt" = NULL`)).toBe("23514:sandbox_image_upload_session_disk_key");
    expect(await update(`state = 'ABORTED', ${nullWrap}`)).toBe(
      "23514:sandbox_image_upload_session_live",
    );
    expect(await update(`"artifactId" = 'art'`)).toBe("23514:sandbox_image_upload_session_target");
    expect(await update(`state = 'ABORTED', "liveDiskOffloadId" = NULL, ${nullWrap}`)).toBe("ok");
    // S1: one OPEN session per offload.
    expect(
      await refused(
        `INSERT INTO sandbox_image_upload_session (id, "transferId", "diskOffloadId", "liveDiskOffloadId", "userId", "hostId", "hostEpoch", "objectKey", "sizeBytes", "storedBytes", "partSize", encryption, "wrappedKey", "wrappedKeyNonce", "keyId", "wrapSalt", "updatedAt")
         SELECT 'ses-dup', 'transfer-dup', "diskOffloadId", "liveDiskOffloadId", "userId", "hostId", 1, "objectKey" || '.2', "sizeBytes", "storedBytes", "partSize", encryption, "wrappedKey", "wrappedKeyNonce", "keyId", "wrapSalt", now()
         FROM sandbox_image_upload_session WHERE id = $1`,
        [open.sessionId],
      ),
    ).toMatch(/^23505:|^23503:/);
  });

  it("rejects restore-only operation fields elsewhere and a malformed restore wait", async () => {
    const w = await world();
    const op = await db.inspect.sandboxOperation.create({
      data: {
        digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
        ...requestDigestMetadata(),

        userId: w.userId,
        sandboxId: w.sandboxId,
        kind: "RECONNECT_SANDBOX",
        generation: 1,
        idempotencyKey: `idem-${randomBytes(4).toString("hex")}`,
        requestBodyHash: "h",
        launchMode: "NEW_ROOT",
        restoreOffloadId: "off-x",
      },
      select: { id: true },
    });
    expect(
      await refused(`UPDATE sandbox_mutation_operation SET "launchMode" = 'COLD' WHERE id = $1`, [
        op.id,
      ]),
    ).toBe("23514:sandbox_operation_launch_mode");
    expect(
      await refused(`UPDATE sandbox_mutation_operation SET kind = 'KILL_SANDBOX' WHERE id = $1`, [
        op.id,
      ]),
    ).toBe("23514:sandbox_operation_launch_mode");
    expect(
      await refused(
        `UPDATE sandbox_mutation_operation SET "progressPhase" = 'importing_disk' WHERE id = $1`,
        [op.id],
      ),
    ).toBe("ok");
    const insert = (columns: string, values: string) =>
      refused(
        `INSERT INTO sandbox_restore_wait ("operationId", "sandboxId", "userId", "expectedGeneration", "deadlineAt"${columns})
         VALUES ($1, $2, $3, 1, now() + interval '1 minute'${values})`,
        [op.id, w.sandboxId, w.userId],
      );
    expect(await insert("", "")).toBe("23514:sandbox_restore_wait_intent");
    expect(await insert(`, intent, "enqueuedAt"`, `, '{}', now() + interval '2 minutes'`)).toBe(
      "23514:sandbox_restore_wait_deadline",
    );
    expect(await insert(`, intent, state`, `, '{}', 'FAILED'`)).toBe(
      "23514:sandbox_restore_wait_intent",
    );
    expect(await insert(`, intent`, `, '{}'`)).toBe("ok");
  });
});
