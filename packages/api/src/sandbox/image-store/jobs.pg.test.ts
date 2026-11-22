import { digestContextSnapshot } from "../digest-context";
import { requestDigestMetadata } from "../idempotency";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-jobs-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: {},
  ensureRunnableJob: vi.fn(),
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../testing/resource-fixtures";
import {
  endTransfersOfEndedOperations,
  gcImageArtifacts,
  originImagesToRelease,
  pruneTemplateRevisions,
  sweepImageStore,
  verifyImageArtifact,
} from "./jobs";
import type { ImageStore } from "./s3";

const db = await pgTestDatabase();
afterAll(() => db.close());
beforeEach(() => {
  // Zero grace: an unreferenced artifact is deleted on the run that marks it.
  process.env.IMAGE_GC_GRACE_DAYS = "0";
});

let n = 0;
const fp = () =>
  `sha256:${String(++n).padStart(8, "0")}${(randomUUID() + randomUUID()).replaceAll("-", "").slice(0, 56)}`;

async function fixture() {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: { id: ownerId, name: "O", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: ownerId, slug: "h", label: "h", status: "CONNECTED" },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "b",
      label: "B",
      incusFingerprint: fp(),
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "STOPPED",
    },
  });
  return { ownerId, host, revision, sandbox };
}
type F = Awaited<ReturnType<typeof fixture>>;

async function artifact(f: F, fingerprint: string, id?: string) {
  return db.inspect.sandboxImageArtifact.create({
    data: {
      ...(id ? { id } : {}),
      userId: f.ownerId,
      fingerprint,
      architecture: "x86_64",
      sizeBytes: 4096n,
      storeKind: "PEER",
      state: "LOCAL",
    },
  });
}
async function operation(f: F, state: "RUNNING" | "FAILED" | "SUCCEEDED") {
  return db.inspect.sandboxOperation.create({
    data: {
      digestContext: digestContextSnapshot({ domain: "wssp-request-v2" }),
      ...requestDigestMetadata(),

      userId: f.ownerId,
      sandboxId: f.sandbox.id,
      kind: "CAPTURE_TEMPLATE",
      state,
      generation: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "hash",
    },
  });
}
async function capture(f: F, operationId: string, state: string, fingerprint: string | null) {
  await db.inspect.$executeRaw`INSERT INTO sandbox_template_capture
    ("operationId","userId","sandboxId","templateId",tag,"hostId","hostOwnerId",state,fingerprint,"updatedAt")
    VALUES (${operationId}, ${f.ownerId}, ${f.sandbox.id}, ${f.revision.templateId}, 'latest',
      ${f.host.id}, ${f.ownerId}, ${state}::"TemplateCaptureState", ${fingerprint}, now())`;
}
async function transfer(f: F, fingerprint: string, operationId: string | null, state = "OPEN") {
  return db.inspect.sandboxImageTransfer.create({
    data: {
      userId: f.ownerId,
      fingerprint,
      purpose: "CAPTURE_UPLOAD",
      mode: "RELAY",
      operationId,
      state: state as "OPEN",
      sizeBytes: 4096n,
      partSize: 4096,
      partCount: 1,
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
}
const stateOf = async (id: string) =>
  (await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id } })).state;
const gcPass = async () => {
  // Full pass from the start: GC keeps a durable cursor between runs.
  await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
  for (let run = 0; run < 3; run++) await gcImageArtifacts(null);
};

describe("image store maintenance against real PostgreSQL", () => {
  it.each(["objectKey", "updatedAt"] as const)(
    "a stale verifier cannot condemn or delete a re-upload after %s changes",
    async (changed) => {
      const f = await fixture();
      const a = await artifact(f, fp());
      await db.inspect.sandboxImageArtifact.update({
        where: { id: a.id },
        data: { state: "VERIFYING", objectKey: "old-key" },
      });
      const read = db.pauseAt("verify", { after: "sandboxImageArtifact.findFirst" });
      const deleted = vi.fn(async () => {});
      const verifying = db.run("verify", () =>
        verifyImageArtifact(a.id, {
          getObjectStream: async () =>
            (async function* () {
              yield Buffer.from("bad");
            })(),
          deleteObject: deleted,
        } as never),
      );
      try {
        await read.waitReached();
        const before = await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
          where: { id: a.id },
        });
        await db.inspect.sandboxImageArtifact.update({
          where: { id: a.id },
          data:
            changed === "objectKey"
              ? { objectKey: "new-key", updatedAt: before.updatedAt }
              : { updatedAt: new Date(before.updatedAt.getTime() + 1000) },
        });
      } finally {
        read.release();
      }
      expect(await verifying).toBe("skipped");
      expect(await stateOf(a.id)).toBe("VERIFYING");
      expect(deleted).not.toHaveBeenCalled();
    },
  );

  it("P2-9: GC keeps an artifact an unfinished capture references (its result, or its finished upload) until the capture ends", async () => {
    const f = await fixture();
    const captured = fp();
    const uploaded = fp();
    const a = await artifact(f, captured);
    const b = await artifact(f, uploaded);
    const op1 = await operation(f, "RUNNING");
    await capture(f, op1.id, "CAPTURED", captured);
    // Upload already COMPLETE, host result not yet recorded (PENDING, no fingerprint).
    const op2 = await operation(f, "RUNNING");
    await capture(f, op2.id, "PENDING", null);
    await transfer(f, uploaded, op2.id, "COMPLETE");
    await gcPass();
    expect(await stateOf(a.id)).toBe("LOCAL");
    expect(await stateOf(b.id)).toBe("LOCAL");
    await db.inspect.$executeRaw`UPDATE sandbox_template_capture SET state = 'FAILED'
      WHERE "operationId" IN (${op1.id}, ${op2.id})`;
    await gcPass();
    expect(await stateOf(a.id)).toBe("DELETED");
    expect(await stateOf(b.id)).toBe("DELETED");
  });

  it("round-2 P2-7: a failed DeleteObject leaves DELETING, the next GC run retries it, and finalization is conditional", async () => {
    const f = await fixture();
    const s3Artifact = (fingerprint: string) =>
      db.inspect.sandboxImageArtifact.create({
        data: {
          userId: f.ownerId,
          fingerprint,
          architecture: "x86_64",
          sizeBytes: 4096n,
          storeKind: "S3",
          state: "STORED",
          objectKey: `p/owners/${f.ownerId}/${fingerprint.slice(7)}/image.tar`,
          verifiedAt: new Date(),
        },
      });
    const failing = await s3Artifact(fp());
    const deletes: string[] = [];
    let failNext = true;
    let onDelete: ((key: string) => Promise<void>) | null = null;
    const store = {
      async deleteObject(key: string) {
        deletes.push(key);
        if (onDelete) await onDelete(key);
        if (key === failing.objectKey && failNext) {
          failNext = false;
          throw new Error("injected DeleteObject failure");
        }
      },
      async listObjectsPage() {
        return {
          objects: [{ key: failing.objectKey ?? "", lastModified: new Date(0) }],
          next: undefined,
        };
      },
      async listUploadsPage() {
        return { uploads: [], next: undefined };
      },
    } as unknown as ImageStore;
    const runUntil = async (id: string, want: string) => {
      await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
      for (let run = 0; run < 20 && (await stateOf(id)) !== want; run++)
        await gcImageArtifacts(store);
    };
    await runUntil(failing.id, "DELETING");
    expect(await stateOf(failing.id)).toBe("DELETING");
    expect(deletes.filter((k) => k === failing.objectKey)).toHaveLength(1);
    // A later run retries the condemned object instead of skipping DELETING.
    await runUntil(failing.id, "DELETED");
    expect(await stateOf(failing.id)).toBe("DELETED");
    expect(deletes.filter((k) => k === failing.objectKey)).toHaveLength(2);
    expect(
      (await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: failing.id } }))
        .objectKey,
    ).toBeNull();

    // Finalization only moves a row that is still DELETING.
    const raced = await s3Artifact(fp());
    onDelete = async (key) => {
      if (key === raced.objectKey)
        await db.inspect.sandboxImageArtifact.update({
          where: { id: raced.id },
          data: { state: "FAILED" },
        });
    };
    await runUntil(raced.id, "FAILED");
    expect(await stateOf(raced.id)).toBe("FAILED");
    onDelete = null;

    // The orphan sweep treats a DELETING row's object as condemned, not known.
    const condemned = await s3Artifact(fp());
    await db.inspect.sandboxImageArtifact.update({
      where: { id: condemned.id },
      data: { state: "DELETING" },
    });
    failing.objectKey = condemned.objectKey;
    failNext = false;
    const before = deletes.length;
    await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
    const swept = await sweepImageStore(store);
    expect(swept.orphans).toBe(1);
    expect(deletes.slice(before)).toContain(condemned.objectKey);
  });

  it("round-5 P2-2: the sweeper ends a dead job's upload session and aborts ended sessions' multipart uploads, retrying a failed abort", async () => {
    const f = await fixture();
    const fingerprint = fp();
    const uploading = await db.inspect.sandboxImageArtifact.create({
      data: {
        userId: f.ownerId,
        fingerprint,
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "S3",
        state: "UPLOADING",
        lastProgressAt: new Date(),
      },
    });
    const session = async (state: "OPEN" | "ABORTED", uploadId: string, transferState: string) =>
      db.inspect.sandboxImageUploadSession.create({
        data: {
          transferId: (await transfer(f, fingerprint, null, transferState)).id,
          artifactId: uploading.id,
          liveArtifactId: state === "OPEN" ? uploading.id : null,
          state,
          userId: f.ownerId,
          hostId: f.host.id,
          hostEpoch: 1,
          objectKey: `p/owners/${f.ownerId}/${fingerprint.slice(7)}/image.tar`,
          uploadId,
          sizeBytes: 4096n,
          storedBytes: 4096n,
          partSize: 4096,
        },
      });
    const dead = await session("OPEN", "upload-dead", "FAILED");
    const lost = await session("ABORTED", "upload-lost", "CANCELLED");
    const aborts: string[] = [];
    let failLost = true;
    const store = {
      async listObjectsPage() {
        return { objects: [], next: undefined };
      },
      async listUploadsPage() {
        return { uploads: [], next: undefined };
      },
      async abortMultipart(_key: string, uploadId: string) {
        aborts.push(uploadId);
        if (uploadId === "upload-lost" && failLost) {
          failLost = false;
          throw new Error("injected AbortMultipartUpload failure");
        }
      },
    } as unknown as ImageStore;
    const row = (id: string) =>
      db.inspect.sandboxImageUploadSession.findUniqueOrThrow({ where: { id } });
    await sweepImageStore(store);
    expect(await row(dead.id)).toMatchObject({
      state: "ABORTED",
      liveArtifactId: null,
      uploadId: null,
      // Its transfer ended with no reason recorded: the generic cause.
      endReason: "upload_failed",
    });
    // The session it ended was the artifact's live one: no capture waits on
    // it, and the artifact carries the cause.
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: uploading.id } }),
    ).toMatchObject({ state: "FAILED", failureDetail: "upload_failed" });
    expect((await row(lost.id)).uploadId).toBe("upload-lost");
    await sweepImageStore(store);
    expect((await row(lost.id)).uploadId).toBeNull();
    expect(aborts.sort()).toEqual(["upload-dead", "upload-lost", "upload-lost"]);
  });

  it("the orphan sweep prefilters a page in one read and re-checks each candidate before deleting it", async () => {
    const f = await fixture();
    const key = (fingerprint: string) => `p/owners/${f.ownerId}/${fingerprint.slice(7)}/image.tar`;
    const owned = await db.inspect.sandboxImageArtifact.create({
      data: {
        userId: f.ownerId,
        fingerprint: fp(),
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "S3",
        state: "STORED",
        objectKey: key(fp()),
        verifiedAt: new Date(),
      },
    });
    const orphanKey = key(fp());
    const racedFingerprint = fp();
    const racedKey = key(racedFingerprint);
    const deletes: string[] = [];
    const store = {
      async listObjectsPage() {
        return {
          objects: [
            { key: owned.objectKey ?? "", lastModified: new Date(0) },
            { key: orphanKey, lastModified: new Date(0) },
            { key: racedKey, lastModified: new Date(0) },
          ],
          next: undefined,
        };
      },
      async listUploadsPage() {
        return { uploads: [], next: undefined };
      },
      async deleteObject(objectKey: string) {
        deletes.push(objectKey);
        // A row for the next object commits after the page prefilter ran.
        if (objectKey === orphanKey)
          await db.inspect.sandboxImageArtifact.create({
            data: {
              userId: f.ownerId,
              fingerprint: racedFingerprint,
              architecture: "x86_64",
              sizeBytes: 4096n,
              storeKind: "S3",
              state: "VERIFYING",
              objectKey: racedKey,
              lastProgressAt: new Date(),
            },
          });
      },
    } as unknown as ImageStore;
    await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
    const swept = await sweepImageStore(store, new Date(), async () => {});
    expect(deletes).toEqual([orphanKey]);
    expect(swept.orphans).toBe(1);
  });

  it("JS-1: the sweeper re-publishes verify for an artifact stuck VERIFYING over an hour", async () => {
    const f = await fixture();
    const verifying = (lastProgressAt: Date) => {
      const fingerprint = fp();
      return db.inspect.sandboxImageArtifact.create({
        data: {
          userId: f.ownerId,
          fingerprint,
          architecture: "x86_64",
          sizeBytes: 4096n,
          storeKind: "S3",
          state: "VERIFYING",
          objectKey: `p/owners/${f.ownerId}/${fingerprint.slice(7)}/image.tar`,
          lastProgressAt,
        },
      });
    };
    const now = new Date();
    const stuck = await verifying(new Date(now.getTime() - 2 * 3_600_000));
    const fresh = await verifying(new Date(now.getTime() - 60_000));
    const store = {
      async listObjectsPage() {
        return { objects: [], next: undefined };
      },
      async listUploadsPage() {
        return { uploads: [], next: undefined };
      },
    } as unknown as ImageStore;
    const enqueued: string[] = [];
    const swept = await sweepImageStore(store, now, async (id) => {
      enqueued.push(id);
      if (id === stuck.id) return;
      throw new Error("injected enqueue failure");
    });
    expect(enqueued).toContain(stuck.id);
    expect(enqueued).not.toContain(fresh.id);
    expect(swept.reverified).toBeGreaterThanOrEqual(1);
    // Without a store nothing can be verified, so nothing is re-published.
    enqueued.length = 0;
    await sweepImageStore(null, now, async (id) => {
      enqueued.push(id);
    });
    expect(enqueued).toEqual([]);
  });

  it("verification backstop fails unavailable images after 24h without reporting corruption", async () => {
    const f = await fixture();
    const now = new Date();
    const create = (storedAt: Date | null, updatedAt: Date) =>
      db.inspect.sandboxImageArtifact.create({
        data: {
          userId: f.ownerId,
          fingerprint: fp(),
          architecture: "x86_64",
          sizeBytes: 4096n,
          storeKind: "S3",
          state: "VERIFYING",
          objectKey: `timeout-${randomUUID()}`,
          storedAt,
          updatedAt,
          lastProgressAt: new Date(now.getTime() - 2 * 3_600_000),
        },
      });
    const cutoff = new Date(now.getTime() - 24 * 3_600_000);
    // storedAt is completion time; a later metadata update cannot reset the age.
    const expired = await create(cutoff, new Date(now.getTime() - 2 * 3_600_000));
    const legacy = await create(null, cutoff);
    const retry = await create(new Date(cutoff.getTime() + 1), cutoff);
    const enqueued: string[] = [];
    const store = {
      listObjectsPage: async () => ({ objects: [] }),
      listUploadsPage: async () => ({ uploads: [] }),
    } as unknown as ImageStore;
    await sweepImageStore(store, now, async (id) => {
      enqueued.push(id);
    });
    for (const row of [expired, legacy]) {
      expect(
        await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: row.id } }),
      ).toMatchObject({ state: "FAILED", corruptReports: 0, objectKey: row.objectKey });
      expect(enqueued).not.toContain(row.id);
    }
    expect(enqueued).toContain(retry.id);
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: retry.id } }),
    ).toMatchObject({ state: "VERIFYING", corruptReports: 0 });
    // Configuration can be entirely absent; aging out still releases the row.
    await sweepImageStore(null, new Date(now.getTime() + 1), async () => {
      throw new Error("must not enqueue without store");
    });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: retry.id } }),
    ).toMatchObject({ state: "FAILED", corruptReports: 0 });
  });

  it("verification timeout cannot condemn an image replaced after the candidate scan", async () => {
    const f = await fixture();
    const now = new Date();
    const old = new Date(now.getTime() - 25 * 3_600_000);
    const artifact = await db.inspect.sandboxImageArtifact.create({
      data: {
        userId: f.ownerId,
        fingerprint: fp(),
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "S3",
        state: "VERIFYING",
        objectKey: "old-timeout-object",
        storedAt: old,
        updatedAt: old,
      },
    });
    const scan = db.pauseAt("verify-timeout", { after: "sandboxImageArtifact.findMany" });
    const sweeping = db.run("verify-timeout", () => sweepImageStore(null, now));
    try {
      await scan.waitReached();
      await db.inspect.sandboxImageArtifact.update({
        where: { id: artifact.id },
        data: {
          state: "VERIFYING",
          objectKey: "replacement-object",
          storedAt: now,
          updatedAt: now,
        },
      });
    } finally {
      scan.release();
    }
    await sweeping;
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
    ).toMatchObject({ state: "VERIFYING", objectKey: "replacement-object", corruptReports: 0 });
  });

  it("P2-14: GC continues from a durable cursor, so a later unreferenced artifact is reached past a full page of referenced ones", async () => {
    const f = await fixture();
    await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
    // 200 referenced artifacts sort first (ids "0..."), one unreferenced after them ("z...").
    const fingerprints = Array.from({ length: 200 }, () => fp());
    await db.inspect.sandboxImageArtifact.createMany({
      data: fingerprints.map((fingerprint, i) => ({
        id: `0gc${String(i).padStart(4, "0")}${randomUUID().slice(0, 8)}`,
        userId: f.ownerId,
        fingerprint,
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "PEER" as const,
        state: "LOCAL" as const,
      })),
    });
    for (const fingerprint of fingerprints) await transfer(f, fingerprint, null);
    const late = await artifact(f, fp(), `zgc${randomUUID().slice(0, 8)}`);
    // Pages of 200 from the cursor: the late artifact needs more than one run.
    let runs = 0;
    while ((await stateOf(late.id)) !== "DELETED" && runs < 20) {
      await gcImageArtifacts(null);
      runs++;
    }
    expect(await stateOf(late.id)).toBe("DELETED");
    expect(runs).toBeGreaterThan(1);
    // Every referenced artifact survived.
    expect(
      await db.inspect.sandboxImageArtifact.count({
        where: { userId: f.ownerId, state: "DELETED" },
      }),
    ).toBe(1);
  });

  it("P2-13: OPEN transfers of an ended operation are cancelled with their links; a running one stays", async () => {
    const f = await fixture();
    const ended = await operation(f, "FAILED");
    const running = await operation(f, "RUNNING");
    const dead = await transfer(f, fp(), ended.id);
    const live = await transfer(f, fp(), running.id);
    await db.inspect.sandboxImageLink.create({
      data: {
        transferId: dead.id,
        hostId: f.host.id,
        hostEpoch: 1,
        role: "SOURCE",
        partNumber: 1,
        tokenDigest: randomUUID().replaceAll("-", "").padEnd(64, "0"),
        expiresAt: new Date(Date.now() + 600_000),
      },
    });
    expect(await endTransfersOfEndedOperations()).toContain(dead.id);
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: dead.id } }),
    ).toMatchObject({ state: "CANCELLED", endReason: "operation_ended" });
    expect(await db.inspect.sandboxImageLink.count({ where: { transferId: dead.id } })).toBe(0);
    expect(
      (await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: live.id } })).state,
    ).toBe("OPEN");
    // Idempotent.
    expect(await endTransfersOfEndedOperations()).not.toContain(dead.id);
  });
  it("round-3 P2-5: auto-prune rotates a durable cursor, so templates past the first page of 200 are reached", async () => {
    const ownerId = randomUUID();
    await db.inspect.user.create({
      data: { id: ownerId, name: "O", email: `${ownerId}@example.test` },
    });
    const old = new Date(Date.now() - 10 * 86_400_000);
    const templateIds = Array.from({ length: 201 }, () => `tpl-${randomUUID()}`);
    await db.inspect.sandboxTemplate.createMany({
      data: templateIds.map((id, i) => ({
        id,
        userId: ownerId,
        slug: `t${i}`,
        label: `T${i}`,
        pruneAfterDays: 1,
        captureKeep: 1,
      })),
    });
    // Each template: an old untagged revision 1 (eligible) and a newer revision 2 (kept).
    await db.inspect.sandboxTemplateRevision.createMany({
      data: templateIds.flatMap((templateId) =>
        [1, 2].map((revision) => ({
          userId: ownerId,
          templateId,
          revision,
          architecture: "x86_64",
          manifestDigest: "d".repeat(64),
          incusFingerprint: fp(),
          createdAt: old,
        })),
      ),
    });
    const unretired = () =>
      db.inspect.sandboxTemplateRevision.count({
        where: { userId: ownerId, revision: 1, retiredAt: null },
      });
    // Processed templates stay eligible; the next run must continue past them.
    await pruneTemplateRevisions();
    await pruneTemplateRevisions();
    expect(await unretired()).toBe(0);
    expect(
      await db.inspect.sandboxTemplateRevision.count({
        where: { userId: ownerId, revision: 2, retiredAt: null },
      }),
    ).toBe(201);
  });
});

describe("origin-pin GC (peer mode: captured copies of retired revisions)", () => {
  /** A retired (or live) captured revision and its pinned origin copy. */
  async function originCopy(f: F, input: { retired: boolean; fingerprint?: string }) {
    const fingerprint = input.fingerprint ?? fp();
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.ownerId,
        slug: `c-${randomUUID().slice(0, 8)}`,
        label: "C",
        incusFingerprint: fingerprint,
        retiredAt: input.retired ? new Date(Date.now() - 60_000) : null,
      },
    });
    // The retired revision's tag moved on (retention keeps tagged revisions).
    if (input.retired)
      await db.inspect.sandboxTemplateTag.deleteMany({ where: { revisionId: revision.id } });
    const row = await db.inspect.sandboxHostImageCache.upsert({
      where: {
        hostId_fingerprint_imageOwnerId: {
          hostId: f.host.id,
          fingerprint,
          imageOwnerId: f.ownerId,
        },
      },
      create: {
        hostId: f.host.id,
        hostOwnerId: f.ownerId,
        imageOwnerId: f.ownerId,
        fingerprint,
        compressedBytes: 4096n,
        origin: "captured",
        pinned: true,
        connectionEpoch: f.host.connectionEpoch,
        reportedAt: new Date(),
      },
      update: {},
    });
    return { fingerprint, revision, row };
  }
  /** One full pass from the start of the durable cursor. */
  const pass = async (now = new Date()) => {
    await db.inspect.appSetting.deleteMany({ where: { key: "image-store.origin-release.cursor" } });
    return (await originImagesToRelease(now)).map((copy) => copy.fingerprint);
  };

  it("a retired revision's origin image nothing references is released once per retry interval", async () => {
    const f = await fixture();
    const retired = await originCopy(f, { retired: true });
    const now = new Date();
    const released = await pass(now);
    expect(released).toContain(retired.fingerprint);
    const stamped = await db.inspect.sandboxHostImageCache.findUniqueOrThrow({
      where: { id: retired.row.id },
    });
    expect(stamped.releaseSentAt).toEqual(now);
    // Not re-sent before the retry interval; re-sent after it while still pinned.
    expect(await pass(new Date(now.getTime() + 1_000))).not.toContain(retired.fingerprint);
    expect(await pass(new Date(now.getTime() + 61_000))).toContain(retired.fingerprint);
  });

  it("the only copy of a live revision is kept, as is a retired image still in use", async () => {
    const f = await fixture();
    // The sole (origin) copy of a live revision: never released.
    const live = await originCopy(f, { retired: false });
    // A retired revision sharing its image with a live one: kept.
    const shared = await originCopy(f, { retired: true, fingerprint: live.fingerprint });
    // A retired revision a live sandbox still runs from: kept.
    const running = await originCopy(f, { retired: true });
    await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.ownerId,
        templateId: running.revision.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "READY",
      },
    });
    // A retired revision another node is still fetching: kept.
    const fetching = await originCopy(f, { retired: true });
    await transfer(f, fetching.fingerprint, null);
    // A retired revision an unfinished build is based on: kept.
    const base = await originCopy(f, { retired: true });
    await db.inspect.$executeRaw`INSERT INTO sandbox_template_build
      (id, "userId", "templateId", tag, "principalKind", "idempotencyKey", "requestBodyHash",
       recipe, "recipeDigest", "buildDigest", "sourceFormat", "baseRevisionId", "baseFingerprint",
       "requestedHostId", "targetKey", "principalKey", "cpuCount", "memoryMiB", "diskGiB",
       "defaultDiskGiB", "timeoutMinutes", "reservedMinutes", "chargeMonth", state, "updatedAt")
      VALUES (${randomUUID()}, ${f.ownerId}, ${base.revision.templateId}, 'latest', 'session',
        ${randomUUID()}, 'h', '{}'::jsonb, ${"a".repeat(64)}, ${"b".repeat(64)}, 'RECIPE',
        ${base.revision.id}, ${base.fingerprint}, ${f.host.id}, ${f.host.id}, 's', 1, 1024, 8,
        8, 10, 10, date_trunc('month', now())::date, 'QUEUED', now())`;
    const released = await pass();
    for (const kept of [live, shared, running, fetching, base])
      expect(released).not.toContain(kept.fingerprint);
    const rows = await db.inspect.sandboxHostImageCache.findMany({
      where: { hostId: f.host.id, imageOwnerId: f.ownerId },
      select: { releaseSentAt: true },
    });
    expect(rows.every((row) => row.releaseSentAt === null)).toBe(true);
    // Once the live revision retires and nothing else holds it, it is released.
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: live.revision.id },
      data: { retiredAt: new Date() },
    });
    expect(await pass()).toContain(live.fingerprint);
  });
});
