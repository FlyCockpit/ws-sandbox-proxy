vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-service-fixture",
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
 * Template-build acceptance and cancel against PostgreSQL:
 * mutation authority is revalidated under the key lock inside the mutation
 * transaction, and cache hits / active joins key on the resolved VM size.
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../lib/service-scopes";
import { createSdkKey, revokeSdkKey } from "../sandbox/services/sdk-keys";
import { acceptTemplateBuild, requestTemplateBuildCancel } from "./service";
import { buildOwnerFixture, completeBuild, fakeDaemon } from "./testing/build-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
const daemon = fakeDaemon(db);

type Owner = Awaited<ReturnType<typeof buildOwnerFixture>>;
const recipe = (value: string) => ({
  version: 1,
  from: { template: "base" },
  steps: [
    { type: "env", values: { FOO: value } },
    { type: "run", script: "echo $FOO > out" },
  ],
});
const request = (f: Owner, value: string, over: Record<string, unknown> = {}) => ({
  idempotencyKey: randomUUID(),
  template: { slug: "built" },
  recipe: recipe(value),
  sandboxHostId: f.host.id,
  timeoutMinutes: 30,
  ...over,
});
const latest = async (f: Owner) =>
  (
    await db.inspect.sandboxTemplateTag.findFirstOrThrow({
      where: { userId: f.id, tag: "latest", Template: { slug: "built" } },
    })
  ).revisionId;

/** An authenticated key principal, as the entry authorization leaves it. */
async function keyPrincipal(f: Owner) {
  const key = await createSdkKey(f.session, {
    name: "builder",
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    poolIds: [],
    scopes: [...SERVICE_SCOPES],
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("fixture key inactive");
  return principal;
}

describe("mutation authority serializes with key revocation (§3.6, §3.8)", () => {
  it("a revocation committed after entry authorization refuses the cache hit: the tag does not move", async () => {
    const f = await buildOwnerFixture(db);
    const first = await acceptTemplateBuild(f.session, request(f, "one"));
    const one = await completeBuild(db, daemon, f, first.build.id);
    const second = await acceptTemplateBuild(f.session, request(f, "two"));
    const two = await completeBuild(db, daemon, f, second.build.id);
    expect(await latest(f)).toBe(two);
    // The key passed entry authorization; the owner revokes it before the
    // acceptance transaction runs. The request is a cache hit of `one`.
    const principal = await keyPrincipal(f);
    await revokeSdkKey(f.session, { id: principal.keyId });
    await expect(acceptTemplateBuild(principal, request(f, "one"))).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    expect(await latest(f)).toBe(two);
    expect(one).not.toBe(two);
    expect(await db.inspect.sandboxTemplateBuild.count({ where: { userId: f.id } })).toBe(2);
  });

  it("a revocation committed after entry authorization refuses the cancel", async () => {
    const f = await buildOwnerFixture(db);
    const principal = await keyPrincipal(f);
    const { build } = await acceptTemplateBuild(principal, request(f, "x", { noCache: true }));
    await revokeSdkKey(f.session, { id: principal.keyId });
    await expect(requestTemplateBuildCancel(principal, build.id)).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    const row = await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: build.id },
    });
    expect(row).toMatchObject({ state: "QUEUED", cancelRequestedAt: null });
  });
});

describe("reuse keys on the resolved VM size (§3.2 cache, §3.6 join)", () => {
  it("a cache hit needs the same resolved size; a different override builds", async () => {
    const f = await buildOwnerFixture(db);
    const first = await acceptTemplateBuild(f.session, request(f, "sized"));
    const revision = await completeBuild(db, daemon, f, first.build.id);
    const same = await acceptTemplateBuild(f.session, request(f, "sized"));
    expect(same).toMatchObject({ cacheHit: true, build: { cacheHitRevisionId: revision } });
    const bigger = await acceptTemplateBuild(
      f.session,
      request(f, "sized", { resources: { cpuCount: 2 } }),
    );
    expect(bigger).toMatchObject({ cacheHit: false, joined: false, build: { state: "QUEUED" } });
    const row = await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: bigger.build.id },
    });
    expect(row.cpuCount).toBe(2);
  });

  it("an active build is joined only with the same resolved size", async () => {
    const f = await buildOwnerFixture(db);
    const first = await acceptTemplateBuild(f.session, request(f, "join"));
    const other = await acceptTemplateBuild(
      f.session,
      request(f, "join", { resources: { memoryMiB: 2048 } }),
    );
    expect(other.joined).toBe(false);
    expect(other.build.id).not.toBe(first.build.id);
    const again = await acceptTemplateBuild(
      f.session,
      request(f, "join", { resources: { memoryMiB: 2048 } }),
    );
    expect(again).toMatchObject({ joined: true, build: { id: other.build.id } });
  });
});

describe("sized builds (disk minimum vs default)", () => {
  it("an unsized build uses the base's minimum + 2 GiB; its revision's floor is the build disk, its default the base's", async () => {
    const f = await buildOwnerFixture(db);
    // A small base floor with the community 32 GiB default.
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: f.base.id },
      data: { minDiskGiB: 8, defaultDiskGiB: 32 },
    });
    const accepted = await acceptTemplateBuild(f.session, request(f, "small"));
    expect(
      await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({
        where: { id: accepted.build.id },
        select: { diskGiB: true, defaultDiskGiB: true },
      }),
    ).toEqual({ diskGiB: 10, defaultDiskGiB: 32 });
    const revision = await completeBuild(db, daemon, f, accepted.build.id);
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
        where: { id: revision },
        select: { minDiskGiB: true, defaultDiskGiB: true },
      }),
    ).toEqual({ minDiskGiB: 10, defaultDiskGiB: 32 });
  });

  it("an explicit build disk and default are kept; below the base's floor or a default below the build disk is refused", async () => {
    const f = await buildOwnerFixture(db);
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: f.base.id },
      data: { minDiskGiB: 8, defaultDiskGiB: 32 },
    });
    const sized = await acceptTemplateBuild(
      f.session,
      request(f, "sized-disk", { resources: { diskGiB: 12 }, defaultDiskGiB: 64 }),
    );
    expect(
      await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({
        where: { id: sized.build.id },
        select: { diskGiB: true, defaultDiskGiB: true },
      }),
    ).toEqual({ diskGiB: 12, defaultDiskGiB: 64 });
    // Only the default differs: a different result, not a join.
    const otherDefault = await acceptTemplateBuild(
      f.session,
      request(f, "sized-disk", { resources: { diskGiB: 12 }, defaultDiskGiB: 48 }),
    );
    expect(otherDefault.joined).toBe(false);
    for (const over of [
      { resources: { diskGiB: 6 } },
      { resources: { diskGiB: 12 }, defaultDiskGiB: 10 },
    ]) {
      await expect(
        acceptTemplateBuild(f.session, request(f, "refused", over)),
      ).rejects.toMatchObject({ data: { code: "sandbox.disk_below_image" } });
    }
  });
});
