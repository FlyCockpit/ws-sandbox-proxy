vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-settings-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import prisma from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedLaunchHost, seedTemplateRevision } from "../testing/resource-fixtures";
import {
  getAccountImagePolicy,
  listHostImageCache,
  pruneTemplateNow,
  setAccountImagePolicy,
  updateTemplateImageSettings,
} from "./settings";

const db = await pgTestDatabase();
afterAll(() => db.close());

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: { id, name: "O", email: `${id}@example.test`, twoFactorEnabled: true },
  });
  return { id, owner: { kind: "session" as const, ownerId: id } };
}

const fp = (n: number) => `sha256:${String(n).padStart(64, "0")}`;

describe("session image settings against real PostgreSQL", () => {
  it("prune now keeps tagged, in-use and the newest captureKeep per capture tag; owner-scoped", async () => {
    const a = await user();
    const first = await seedTemplateRevision(db.inspect, {
      data: { userId: a.id, slug: "base", label: "Base", incusFingerprint: fp(1) },
    });
    const templateId = first.templateId;
    const base = {
      userId: a.id,
      templateId,
      architecture: "x86_64",
      manifestDigest: "d".repeat(64),
    };
    // Captures under "nightly": revisions 2..5; "latest" tag points at revision 2.
    const nightly = [];
    for (let revision = 2; revision <= 5; revision++)
      nightly.push(
        await db.inspect.sandboxTemplateRevision.create({
          data: {
            ...base,
            revision,
            incusFingerprint: fp(revision),
            sourceKind: "CAPTURE",
            captureTag: "nightly",
          },
        }),
      );
    await db.inspect.sandboxTemplateTag.create({
      data: { userId: a.id, templateId, revisionId: nightly[0]!.id, tag: "pinned" },
    });
    await db.inspect.sandboxTemplate.update({
      where: { id: templateId },
      data: { captureKeep: 1 },
    });

    // Another account cannot prune (or even see) the template.
    const b = await user();
    await expect(pruneTemplateNow(b.owner, { templateId })).rejects.toMatchObject({
      data: { code: "sandbox.template_not_found" },
    });

    expect(await pruneTemplateNow(a.owner, { templateId })).toEqual({ retired: 2 });
    const rows = await db.inspect.sandboxTemplateRevision.findMany({
      where: { templateId },
      orderBy: { revision: "asc" },
      select: { revision: true, retiredAt: true, retiredReason: true },
    });
    expect(rows.map((r) => [r.revision, r.retiredReason])).toEqual([
      [1, null], // the newest (only) untagged manual revision
      [2, null], // tagged
      [3, "manual"],
      [4, "manual"],
      [5, null], // newest of "nightly"
    ]);
    // Idempotent.
    expect(await pruneTemplateNow(a.owner, { templateId })).toEqual({ retired: 0 });
  });

  it("updates template image settings and rejects an archived or foreign template", async () => {
    const a = await user();
    const revision = await seedTemplateRevision(db.inspect, {
      data: { userId: a.id, slug: "s", label: "S", incusFingerprint: fp(9) },
    });
    const updated = await updateTemplateImageSettings(a.owner, {
      templateId: revision.templateId,
      imagePlacement: "OWNED_NODES_ONLY",
      captureKeep: 7,
      pruneAfterDays: 30,
      captureScrubPaths: ["/srv/cache/*"],
    });
    expect(updated).toMatchObject({
      imagePlacement: "OWNED_NODES_ONLY",
      captureKeep: 7,
      pruneAfterDays: 30,
      captureScrubPaths: ["/srv/cache/*"],
    });
    // Omitted fields stay; null clears auto-prune.
    expect(
      await updateTemplateImageSettings(a.owner, {
        templateId: revision.templateId,
        pruneAfterDays: null,
      }),
    ).toMatchObject({ captureKeep: 7, pruneAfterDays: null });
    const b = await user();
    await expect(
      updateTemplateImageSettings(b.owner, { templateId: revision.templateId, captureKeep: 1 }),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_not_found" } });
    await db.inspect.sandboxTemplate.update({
      where: { id: revision.templateId },
      data: { archivedAt: new Date() },
    });
    await expect(
      updateTemplateImageSettings(a.owner, { templateId: revision.templateId, captureKeep: 1 }),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_not_found" } });
  });

  it("account policy: default, upsert, quotas and S3 usage", async () => {
    const a = await user();
    expect(await getAccountImagePolicy(a.owner, undefined)).toMatchObject({
      imagePlacement: "ANY_NODE",
      usage: { storedBytes: "0", downloadsLastHour: 0 },
    });
    await setAccountImagePolicy(a.owner, { imagePlacement: "OWNED_NODES_ONLY" });
    await db.inspect.accountImagePolicy.update({
      where: { userId: a.id },
      data: { adminStoredGiBMax: 5 },
    });
    await db.inspect.sandboxImageArtifact.create({
      data: {
        userId: a.id,
        fingerprint: fp(3),
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "S3",
        state: "UPLOADING",
        objectKey: "k",
      },
    });
    const policy = await getAccountImagePolicy(a.owner, undefined);
    expect(policy).toMatchObject({
      imagePlacement: "OWNED_NODES_ONLY",
      usage: { storedBytes: "4096" },
    });
    expect(policy.quotas.maxStoredGiB).toBe(5);
  });

  it("host image cache: owner only, own entries paged, foreign bytes aggregate only", async () => {
    const a = await user();
    const other = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: a.id,
        slug: "h",
        label: "h",
        status: "CONNECTED",
        daemonFeatures: { image: { acceptForeign: true } },
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
        imageCacheUsedBytes: 3n * 4096n,
        imageCacheForeignBytes: 4096n,
      },
    });
    const entry = (imageOwnerId: string, n: number) =>
      db.inspect.sandboxHostImageCache.create({
        data: {
          hostId: host.id,
          hostOwnerId: a.id,
          imageOwnerId,
          fingerprint: fp(n),
          compressedBytes: 4096n,
          origin: "fetched",
          connectionEpoch: 1,
          reportedAt: new Date(Date.now() - n * 1000),
        },
      });
    await entry(a.id, 1);
    await entry(a.id, 2);
    await entry(other.id, 3);
    // fp(1) is one of a's revisions; fp(2) only one of the other account's,
    // which must not name a's cache entry.
    await seedTemplateRevision(db.inspect, {
      data: { userId: a.id, slug: "web", label: "Web", incusFingerprint: fp(1) },
    });
    await seedTemplateRevision(db.inspect, {
      data: { userId: other.id, slug: "secret-name", label: "S", incusFingerprint: fp(2) },
    });
    const first = await listHostImageCache(a.owner, { hostId: host.id, limit: 1 });
    expect(first.items[0]?.revision).toEqual({ slug: "web", revision: 1 });
    expect(first.summary).toMatchObject({
      enabled: true,
      foreignBytes: "4096",
      acceptForeign: true,
    });
    expect(first.items.map((i) => i.fingerprint)).toEqual([fp(1)]);
    const second = await listHostImageCache(a.owner, {
      hostId: host.id,
      limit: 1,
      cursor: first.nextCursor ?? undefined,
    });
    expect(second.items.map((i) => i.fingerprint)).toEqual([fp(2)]);
    expect(second.items[0]?.revision).toBeNull();
    expect(JSON.stringify(second)).not.toContain("secret-name");
    expect(second.nextCursor).toBeNull();
    // The image owner of a foreign entry is never a host-owner read.
    await expect(
      listHostImageCache(other.owner, { hostId: host.id, limit: 10 }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("host image cache names each image from its newest revision with one bounded read per fingerprint", async () => {
    const a = await user();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: a.id,
        slug: "h",
        label: "h",
        status: "CONNECTED",
        imageCacheEpoch: 1,
        imageCacheCapBytes: 1n << 34n,
      },
    });
    await db.inspect.sandboxHostImageCache.create({
      data: {
        hostId: host.id,
        hostOwnerId: a.id,
        imageOwnerId: a.id,
        fingerprint: fp(7),
        compressedBytes: 4096n,
        origin: "fetched",
        connectionEpoch: 1,
        reportedAt: new Date(),
      },
    });
    // One fingerprint reused by a long revision history.
    const first = await seedTemplateRevision(db.inspect, {
      data: { userId: a.id, slug: "web", label: "Web", incusFingerprint: fp(7) },
    });
    for (let revision = 2; revision <= 30; revision++)
      await db.inspect.sandboxTemplateRevision.create({
        data: {
          userId: a.id,
          templateId: first.templateId,
          revision,
          incusFingerprint: fp(7),
          architecture: "x86_64",
          manifestDigest: "d".repeat(64),
          createdAt: new Date(Date.now() + revision * 1000),
        },
      });
    const findMany = vi.spyOn(prisma.sandboxTemplateRevision, "findMany");
    const findFirst = vi.spyOn(prisma.sandboxTemplateRevision, "findFirst");
    try {
      const page = await listHostImageCache(a.owner, { hostId: host.id, limit: 10 });
      expect(page.items.map((item) => item.revision)).toEqual([{ slug: "web", revision: 30 }]);
      // Never a findMany (whose `distinct` is applied in memory, unbounded in SQL);
      // exactly one LIMIT 1 findFirst per distinct fingerprint on the page.
      expect(findMany).not.toHaveBeenCalled();
      expect(findFirst).toHaveBeenCalledTimes(1);
    } finally {
      findMany.mockRestore();
      findFirst.mockRestore();
    }
  });
});
