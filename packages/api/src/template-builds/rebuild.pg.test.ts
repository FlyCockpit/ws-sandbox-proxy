vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-rebuild-fixture",
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
vi.mock("../sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("../sandbox/image-store/config")>()),
  imageDistributionMode: () => "peer",
}));

/**
 * Template builds B10 pg tests:
 * concurrent misses start one rebuild, the rebuild is a system build charged
 * to the template owner, a context-ful recipe is never rebuilt, and a waiting
 * create follows the rebuilt tag (or ends when the rebuild fails).
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../lib/service-scopes";
import { runCapacityQueuePass } from "../sandbox/capacity-queue";
import { leaseNow } from "../sandbox/lease";
import { createSandbox } from "../sandbox/services/sandboxes";
import { createSdkKey } from "../sandbox/services/sdk-keys";
import { advanceTemplateBuild } from "./orchestrator";
import { acceptTemplateBuild, requestTemplateBuildCancel } from "./service";
import { buildOwnerFixture, completeBuild, fakeDaemon } from "./testing/build-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
const daemon = fakeDaemon(db);

const RECIPE = {
  version: 1,
  from: { template: "base" },
  steps: [
    { type: "env", values: { FOO: "bar" } },
    { type: "run", script: "echo $FOO > out" },
  ],
};

type Owner = Awaited<ReturnType<typeof buildOwnerFixture>>;
const row = (id: string) => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id } });
const advance = (f: { id: string }, buildId: string) =>
  advanceTemplateBuild({ id: buildId, userId: f.id });

const complete = (f: Owner, buildId: string) => completeBuild(db, daemon, f, buildId);

/** An owner whose `built:latest` came from a successful context-free build,
 * a pool holding the builder host, and the built image gone everywhere. */
async function missingBuiltImage() {
  const f = await buildOwnerFixture(db);
  const { build } = await acceptTemplateBuild(f.session, {
    idempotencyKey: randomUUID(),
    template: { slug: "built" },
    recipe: RECIPE,
    sandboxHostId: f.host.id,
    timeoutMinutes: 30,
  });
  const revisionId = await complete(f, build.id);
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: "pool", label: "Pool" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { userId: f.id, hostOwnerId: f.id, poolId: pool.id, sandboxHostId: f.host.id },
  });
  await lose(revisionId);
  return { f, sourceBuildId: build.id, revisionId, pool };
}

/** The image is gone: no host copy, nothing stored. */
async function lose(revisionId: string) {
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId },
    data: { status: "MISSING" },
  });
  const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
    where: { id: revisionId },
  });
  await db.inspect.sandboxImageArtifact.updateMany({
    where: { userId: revision.userId, fingerprint: revision.incusFingerprint },
    data: { state: "DELETED" },
  });
}

const rebuilds = (revisionId: string) =>
  db.inspect.sandboxTemplateBuild.findMany({ where: { triggeredByRevisionId: revisionId } });
const waitCreate = (poolId: string) => ({
  template: "built",
  poolId,
  idempotencyKey: randomUUID(),
  waitForCapacityMs: 3_600_000,
});

describe("rebuild on miss: dedupe (§3.9)", () => {
  it("concurrent misses start exactly one rebuild; the second create joins it", async () => {
    const { f, revisionId, pool } = await missingBuiltImage();
    // A parks after inserting the rebuild row (owner placement still held);
    // B's create then blocks on owner placement until A commits.
    const inserted = db.pauseAt("a", { after: "sandboxTemplateBuild.create" });
    const first = db.run("a", () => createSandbox(f.session, waitCreate(pool.id)));
    await inserted.waitReached();
    const second = db.run("b", () => createSandbox(f.session, waitCreate(pool.id)));
    await db.waitUntilBlocked("b", { by: "a" });
    inserted.release();
    const [a, b] = await Promise.all([first, second]);
    for (const sandbox of [a, b]) {
      expect(sandbox.state).toBe("WAITING_FOR_CAPACITY");
      const wait = await db.inspect.sandboxCapacityWait.findUniqueOrThrow({
        where: { sandboxId: sandbox.id },
      });
      expect(wait).toMatchObject({
        lastBlocker: "image_rebuilding",
        templateRevisionId: revisionId,
      });
    }
    expect(await rebuilds(revisionId)).toHaveLength(1);
    // A create without a wait joins too: refused `rebuilding`, no new row.
    await expect(
      createSandbox(f.session, {
        template: "built",
        poolId: pool.id,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", reason: "rebuilding" },
    });
    // The queue re-evaluates the waits without starting another rebuild.
    await runCapacityQueuePass(leaseNow);
    expect(await rebuilds(revisionId)).toHaveLength(1);
    // The dedupe index refuses a second active system build of the same key.
    const [rebuild] = await rebuilds(revisionId);
    const { id: _id, ...copy } = rebuild!;
    await expect(
      db.inspect.sandboxTemplateBuild.create({
        data: { ...copy, idempotencyKey: `tb:rebuild:dup:${randomUUID()}` } as never,
      }),
    ).rejects.toMatchObject({ code: "P2002" });
  });

  it("a pinned revision is never rebuilt: image_unavailable, never a wait", async () => {
    const { f, revisionId, pool } = await missingBuiltImage();
    for (const extra of [{}, { waitForCapacityMs: 3_600_000 }]) {
      const refusal = await createSandbox(f.session, {
        template: `revision/${revisionId}`,
        poolId: pool.id,
        idempotencyKey: randomUUID(),
        ...extra,
      }).catch((error: unknown) => error);
      expect(refusal).toMatchObject({ data: { code: "sandbox.template_image_unavailable" } });
      expect((refusal as { data: object }).data).not.toHaveProperty("reason");
    }
    expect(await rebuilds(revisionId)).toHaveLength(0);
    expect(await db.inspect.sandboxCapacityWait.count({ where: { userId: f.id } })).toBe(0);
  });
});

describe("rebuild on miss: the template owner's quota (§3.9)", () => {
  it("an SDK key's miss starts a system build charged to the owner; an exhausted quota refuses quietly", async () => {
    const { f, sourceBuildId, revisionId, pool } = await missingBuiltImage();
    const key = await createSdkKey(f.session, {
      name: "all-owned",
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      poolIds: [],
      scopes: [...SERVICE_SCOPES],
    });
    const principal = await authenticateSdkKeySecret(key.secret);
    if (!principal) throw new Error("fixture key inactive");
    const source = await row(sourceBuildId);
    const used = source.chargedMinutes ?? source.reservedMinutes;
    // 29 minutes left: the 30-minute rebuild does not fit.
    await db.inspect.accountImagePolicy.create({
      data: { userId: f.id, adminBuildMinutesPerMonthMax: used + 29 },
    });
    await expect(createSandbox(principal, waitCreate(pool.id))).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", reason: "rebuild_quota" },
    });
    await expect(
      createSandbox(principal, {
        template: "built",
        poolId: pool.id,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", reason: "rebuild_quota" },
    });
    expect(await rebuilds(revisionId)).toHaveLength(0);
    expect(await db.inspect.sandboxCapacityWait.count({ where: { userId: f.id } })).toBe(0);
    // Concurrency is the owner's too.
    await db.inspect.accountImagePolicy.update({
      where: { userId: f.id },
      data: { adminBuildMinutesPerMonthMax: used + 30, adminConcurrentBuildsMax: 0 },
    });
    await expect(createSandbox(principal, waitCreate(pool.id))).rejects.toMatchObject({
      data: { reason: "rebuild_quota" },
    });
    await db.inspect.accountImagePolicy.update({
      where: { userId: f.id },
      data: { adminConcurrentBuildsMax: null },
    });
    const waiting = await createSandbox(principal, waitCreate(pool.id));
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
    const [rebuild] = await rebuilds(revisionId);
    expect(rebuild).toMatchObject({
      userId: f.id,
      principalKind: "system",
      authorizingKeyId: null,
      principalKey: "sys",
      triggeredByRevisionId: revisionId,
      templateId: source.templateId,
      tag: "latest",
      buildDigest: source.buildDigest,
      recipeDigest: source.recipeDigest,
      contextSha256: null,
      state: "QUEUED",
      timeoutMinutes: 30,
      reservedMinutes: 30,
      minutesSettled: false,
      chargeMonth: source.chargeMonth,
    });
    expect(rebuild!.idempotencyKey.startsWith("tb:")).toBe(true);
    // The owner's month is now full: the owner's own next build is refused.
    await expect(
      acceptTemplateBuild(f.session, {
        idempotencyKey: randomUUID(),
        template: { slug: "other" },
        recipe: RECIPE,
        sandboxHostId: f.host.id,
        timeoutMinutes: 1,
      }),
    ).rejects.toMatchObject({ data: { code: "template.build_minutes_exhausted" } });
  });
});

describe("rebuild on miss: COPY recipes (§3.9)", () => {
  it("a context-ful recipe is never auto-rebuilt: rebuild_required, no row, no wait", async () => {
    const { f, sourceBuildId, revisionId, pool } = await missingBuiltImage();
    // The source build carried a context (a COPY recipe): none is stored.
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: sourceBuildId },
      data: { contextSha256: "c".repeat(64), contextBytes: 10n },
    });
    await expect(createSandbox(f.session, waitCreate(pool.id))).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", hint: "rebuild_required" },
    });
    await expect(
      createSandbox(f.session, {
        template: "built",
        poolId: pool.id,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", hint: "rebuild_required" },
    });
    await expect(
      createSandbox(f.session, {
        template: "built",
        sandboxHostId: f.host.id,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ data: { hint: "rebuild_required" } });
    expect(await rebuilds(revisionId)).toHaveLength(0);
    expect(
      await db.inspect.sandboxTemplateBuild.count({
        where: { userId: f.id, principalKind: "system" },
      }),
    ).toBe(0);
    expect(await db.inspect.sandboxCapacityWait.count({ where: { userId: f.id } })).toBe(0);
  });
});

describe("rebuild on miss: the waiting create (§3.9)", () => {
  it("follows the rebuilt tag once the rebuild succeeds, and places", async () => {
    const { f, revisionId, pool } = await missingBuiltImage();
    const waiting = await createSandbox(f.session, waitCreate(pool.id));
    const [rebuild] = await rebuilds(revisionId);
    const rebuiltId = await complete(f, rebuild!.id);
    expect(rebuiltId).not.toBe(revisionId);
    const tag = await db.inspect.sandboxTemplateTag.findFirstOrThrow({
      where: { templateId: rebuild!.templateId, tag: "latest" },
    });
    expect(tag.revisionId).toBe(rebuiltId);
    await runCapacityQueuePass(leaseNow);
    const wait = await db.inspect.sandboxCapacityWait.findUniqueOrThrow({
      where: { sandboxId: waiting.id },
    });
    expect(wait).toMatchObject({ state: "PLACED", templateRevisionId: rebuiltId });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } });
    expect(sandbox).toMatchObject({ templateRevisionId: rebuiltId, sandboxHostId: f.host.id });
  });

  it("ends image_unavailable when the rebuild is cancelled; a new create may retry", async () => {
    const { f, revisionId, pool } = await missingBuiltImage();
    const waiting = await createSandbox(f.session, waitCreate(pool.id));
    const [rebuild] = await rebuilds(revisionId);
    await requestTemplateBuildCancel(f.session, rebuild!.id);
    await advance(f, rebuild!.id);
    expect((await row(rebuild!.id)).state).toBe("CANCELLED");
    await runCapacityQueuePass(leaseNow);
    const wait = await db.inspect.sandboxCapacityWait.findUniqueOrThrow({
      where: { sandboxId: waiting.id },
    });
    expect(wait).toMatchObject({ state: "FAILED", endReason: "image_unavailable" });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } })).toMatchObject(
      { state: "DELETED", lastErrorCode: "image_unavailable" },
    );
    expect(await rebuilds(revisionId)).toHaveLength(1);
    // A fresh create is a new user action: it starts a new rebuild.
    await createSandbox(f.session, waitCreate(pool.id));
    expect(await rebuilds(revisionId)).toHaveLength(2);
  });
});
