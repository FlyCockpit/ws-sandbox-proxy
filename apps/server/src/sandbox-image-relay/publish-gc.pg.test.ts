/**
 * GC and the publish backfill agree on what is referenced (the churn loop):
 * GC deleted an archived template's image, the backfill uploaded it again
 * from a host's AVAILABLE copy, and the reused artifact row kept its past
 * `deleteAfter`, so the next GC deleted it again at once.
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import type { ServerImageMessage } from "@wssp/sandbox-contracts";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "publish-gc-fixture",
    SANDBOX_MAX_TIMEOUT_MS: 86_400_000,
    IMAGE_RELAY_MAX_ACTIVE: 1000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
  consumeImageGrantBudget: async () => {},
}));
vi.mock("../sandbox-relay/session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
  },
}));
const fakeS3 = vi.hoisted(() => ({
  calls: [] as string[],
  /** Runs inside the next DeleteObject (then cleared): GC is mid-pass. */
  onDelete: null as (() => Promise<void>) | null,
}));
vi.mock("@wssp/api/sandbox/image-store/s3", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/s3")>();
  const store = {
    settings: { prefix: "test", presignTtlSeconds: 600 },
    createMultipart: async () => "upload-1",
    presignUploadPart: async (_key: string, upload: string, n: number) =>
      `https://s3.example.test/part?upload=${upload}&n=${n}`,
    listParts: async () => [],
    completeMultipart: async () => {},
    abortMultipart: async () => {},
    deleteObject: async (key: string) => {
      fakeS3.calls.push(`delete:${key}`);
      const during = fakeS3.onDelete;
      fakeS3.onDelete = null;
      await during?.();
    },
  };
  return { ...real, imageStore: () => store as never, imageMasterKey: () => null };
});
vi.mock("@wssp/api/sandbox/image-store/config", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/config")>();
  return { ...real, imageDistributionMode: () => "s3" };
});

const db = await pgTestDatabase();
afterAll(() => db.close());
const { publishBackfill } = await import("./scheduler.js");
const { gcImageArtifacts } = await import("@wssp/api/sandbox/image-store/jobs");
const { imageStore } = await import("@wssp/api/sandbox/image-store/s3");
const { handleImageUploadBegin } = await import("../sandbox-relay/image-handlers.js");

const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: false,
    leaseFromReady: false,
    captureStorageMarkers: [],
  },
};
const fpOf = () => `sha256:${(randomUUID() + randomUUID()).replaceAll("-", "").slice(0, 64)}`;
const PAST = new Date(Date.now() - 3_600_000);

/** An owner whose connected, publish-capable host holds an AVAILABLE copy
 * of a captured revision, and that image's artifact row in `state`. */
async function fixture(input: {
  archived: boolean;
  state: "DELETED" | "STORED" | "FAILED";
  /** The artifact row's id (GC walks rows in id order). */
  id?: string;
}) {
  const ownerId = `pgc-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "O", email: `${ownerId}@example.test`, emailVerified: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "src",
      label: "src",
      status: "CONNECTED",
      connectionEpoch: 1,
      daemonFeatures: FEATURES,
    },
  });
  const fingerprint = fpOf();
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "b",
      label: "B",
      incusFingerprint: fingerprint,
    },
  });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: revision.id, hostId: host.id },
    data: { sizeBytes: 4096n, imageFormat: "unified" },
  });
  if (input.archived)
    await db.inspect.sandboxTemplate.update({
      where: { id: revision.templateId },
      data: { archivedAt: new Date() },
    });
  // As GC leaves a deleted object (and as the test deploy had them): the
  // grace marks of the object it deleted are still set and in the past.
  const artifact = await db.inspect.sandboxImageArtifact.create({
    data: {
      ...(input.id ? { id: input.id } : {}),
      userId: ownerId,
      fingerprint,
      architecture: "x86_64",
      sizeBytes: 4096n,
      storeKind: "S3",
      state: input.state,
      ...(input.state === "STORED"
        ? {
            objectKey: `test/owners/${ownerId}/${fingerprint.slice(7)}/s1/image.tar`,
            verifiedAt: new Date(),
          }
        : { unreferencedSince: PAST, deleteAfter: PAST }),
    },
  });
  return { ownerId, host, fingerprint, revision, artifact };
}
type F = Awaited<ReturnType<typeof fixture>>;

const sent: Array<{ hostId: string; fingerprint: string }> = [];
const send = (hostId: string, _epoch: number, frame: ServerImageMessage) => {
  sent.push({ hostId, fingerprint: "fingerprint" in frame ? String(frame.fingerprint) : "" });
  return true;
};
const sentFor = (f: F) => sent.filter((s) => s.fingerprint === f.fingerprint);
/** One full GC pass from the start (GC keeps a durable cursor). */
const gcPass = async (now = new Date()) => {
  await db.inspect.appSetting.deleteMany({ where: { key: { startsWith: "image-store." } } });
  return gcImageArtifacts(imageStore(), now);
};
const artifactOf = (f: F) =>
  db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: f.artifact.id } });

async function beginPublish(f: F) {
  const transfer = await db.inspect.sandboxImageTransfer.create({
    data: {
      userId: f.ownerId,
      fingerprint: f.fingerprint,
      purpose: "PUBLISH",
      mode: "S3",
      sourceHostId: f.host.id,
      sourceHostOwnerId: f.ownerId,
      sourceEpoch: 1,
      sizeBytes: 4096n,
      partSize: 4096,
      partCount: 1,
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  const replies: Array<Record<string, unknown>> = [];
  await handleImageUploadBegin(
    {
      sender: { userId: f.ownerId, hostId: f.host.id, connectionEpoch: 1, isCurrent: () => true },
      reply: (frame: unknown) => replies.push(frame as Record<string, unknown>),
      sendTo: () => true,
      isHostCurrent: () => true,
      spool: { dropTransfer: async () => {} } as never,
    } as never,
    {
      type: "image.upload.begin",
      transferId: transfer.id,
      fingerprint: f.fingerprint,
      sizeBytes: 4096,
      format: "unified",
    },
  );
  return { transferId: transfer.id, replies };
}

beforeEach(async () => {
  process.env.IMAGE_GC_GRACE_DAYS = "0";
  sent.length = 0;
  fakeS3.calls.length = 0;
  // Each test's owner stands alone: earlier owners' open publishes and
  // candidates never crowd the backfill's page.
  await db.inspect.sandboxImageTransfer.updateMany({
    where: { state: "OPEN" },
    data: { state: "CANCELLED", endReason: "test_reset" },
  });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { status: "AVAILABLE" },
    data: { status: "MISSING" },
  });
});

describe("GC and the publish backfill agree on archived templates (churn loop)", () => {
  it("an archived template's deleted image that a host still has AVAILABLE is not uploaded again", async () => {
    const f = await fixture({ archived: true, state: "DELETED" });
    expect(await publishBackfill(send)).toBe(0);
    expect(sentFor(f)).toEqual([]);
  });

  it("control: a live template's deleted image on a host is uploaded again", async () => {
    const f = await fixture({ archived: false, state: "DELETED" });
    expect(await publishBackfill(send)).toBe(1);
    expect(sentFor(f)).toEqual([{ hostId: f.host.id, fingerprint: f.fingerprint }]);
  });

  it("GC, then backfill, then GC over several ticks deletes the archived image once and stays stable", async () => {
    const f = await fixture({ archived: true, state: "STORED" });
    for (let tick = 0; tick < 4; tick++) {
      await gcPass();
      await publishBackfill(send);
    }
    expect((await artifactOf(f)).state).toBe("DELETED");
    expect(fakeS3.calls.filter((c) => c.includes(f.fingerprint.slice(7)))).toHaveLength(1);
    expect(sentFor(f)).toEqual([]);
    expect(
      await db.inspect.sandboxImageTransfer.count({
        where: { userId: f.ownerId, purpose: "PUBLISH" },
      }),
    ).toBe(0);
  });

  it("a retired revision of a live template is not uploaded either (both lifecycle flags count)", async () => {
    const f = await fixture({ archived: false, state: "DELETED" });
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: f.revision.id },
      data: { retiredAt: new Date() },
    });
    expect(await publishBackfill(send)).toBe(0);
  });
});

describe("upload begin on a reused artifact row starts a fresh lifecycle", () => {
  it("clears the deleted object's grace marks, so an upload that ends unreferenced gets the full grace", async () => {
    process.env.IMAGE_GC_GRACE_DAYS = "7";
    const f = await fixture({ archived: false, state: "DELETED" });
    const { transferId, replies } = await beginPublish(f);
    expect(replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
    expect(await artifactOf(f)).toMatchObject({
      state: "UPLOADING",
      unreferencedSince: null,
      deleteAfter: null,
    });
    // The template is archived while the publish runs; the upload completes.
    await db.inspect.sandboxTemplate.update({
      where: { id: f.revision.templateId },
      data: { archivedAt: new Date() },
    });
    await db.inspect.sandboxImageArtifact.update({
      where: { id: f.artifact.id },
      data: { state: "STORED", objectKey: "test/k", verifiedAt: new Date(), storedAt: new Date() },
    });
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transferId },
      data: { state: "COMPLETE", endReason: "uploaded" },
    });
    const now = new Date();
    expect(await gcPass(now)).toEqual({ marked: 1, deleted: 0 });
    const marked = await artifactOf(f);
    expect(marked.state).toBe("STORED");
    expect(marked.unreferencedSince).toEqual(now);
    expect(marked.deleteAfter?.getTime()).toBe(now.getTime() + 7 * 86_400_000);
    expect(fakeS3.calls).toEqual([]);
    // And the backfill never uploads it again once GC deletes it.
    process.env.IMAGE_GC_GRACE_DAYS = "0";
    expect(await gcPass(new Date(now.getTime() + 8 * 86_400_000))).toMatchObject({ deleted: 1 });
    expect(await publishBackfill(send)).toBe(0);
  });
  it("a re-upload that lands while a GC pass is under way is not deleted on the deadline that pass read", async () => {
    const run = randomUUID();
    // GC reads one page, then deletes `first` before reaching `second`; the
    // re-upload of `second` happens inside that delete, after the page read.
    const first = await fixture({ archived: true, state: "STORED", id: `gcrace-${run}-a` });
    await db.inspect.sandboxImageArtifact.update({
      where: { id: first.artifact.id },
      data: { unreferencedSince: PAST, deleteAfter: PAST },
    });
    const second = await fixture({ archived: false, state: "FAILED", id: `gcrace-${run}-b` });
    fakeS3.onDelete = async () => {
      const { transferId, replies } = await beginPublish(second);
      expect(replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
      await db.inspect.sandboxTemplate.update({
        where: { id: second.revision.templateId },
        data: { archivedAt: new Date() },
      });
      await db.inspect.sandboxImageArtifact.update({
        where: { id: second.artifact.id },
        data: { state: "STORED", objectKey: "test/new", verifiedAt: new Date() },
      });
      await db.inspect.sandboxImageTransfer.update({
        where: { id: transferId },
        data: { state: "COMPLETE", endReason: "uploaded" },
      });
    };
    process.env.IMAGE_GC_GRACE_DAYS = "7";
    await gcPass();
    expect(fakeS3.onDelete).toBeNull();
    expect(fakeS3.calls).toEqual([`delete:${first.artifact.objectKey}`]);
    expect(await artifactOf(second)).toMatchObject({
      state: "STORED",
      objectKey: "test/new",
      deleteAfter: null,
    });
    // The next pass gives the new object its own grace.
    const now = new Date();
    await gcPass(now);
    expect((await artifactOf(second)).deleteAfter?.getTime()).toBe(now.getTime() + 7 * 86_400_000);
  });
});
