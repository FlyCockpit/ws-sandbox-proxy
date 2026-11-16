vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "community-base-fixture",
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
/** The image distribution mode (peer unless a test stores to S3). */
const imageMode = vi.hoisted(() => ({ value: "peer" as "peer" | "s3" }));
vi.mock("../../sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("../../sandbox/image-store/config")>()),
  imageDistributionMode: () => imageMode.value,
}));

/**
 * Community base templates end to end on a real database (community-base
 * §6, §8, §11): the dedicated UPSTREAM insert, the bootstrap build VM with
 * its upstream plan, capture into a pending revision, the verify VM in
 * CAPTURING (its own role, cleanup rule and key namespace), publish on pass,
 * retire on failure, cancel and manual retire, and UPSTREAM containment.
 */
import { readFileSync } from "node:fs";
import { Prisma } from "@wssp/db/client";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { checkAcceptedDispatchAuthority } from "../../lib/sdk-key-access";
import { recordCaptureResult } from "../../sandbox/image-store/capture-result";
import { finalizeCapture } from "../../sandbox/image-store/captures";
import { createSandbox } from "../../sandbox/services/sandboxes";
import { retireTemplateRevision } from "../../sandbox/services/templates";
import { resolveTemplateRevision } from "../../sandbox/template-resolution";
import { buildActionKey } from "../decide";
import { advanceTemplateBuild, runTemplateBuildCleanup } from "../orchestrator";
import { requestTemplateBuildCancel } from "../service";
import { buildOwnerFixture, currentOperation, fakeDaemon } from "../testing/build-fixtures";
import { CommunityIndexClient } from "./index-client";
import { createCommunityTemplate, retryCommunityTemplate } from "./service";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => {
  imageMode.value = "peer";
});
const daemon = fakeDaemon(db);
const fixture = readFileSync(new URL("./fixtures/images.json", import.meta.url), "utf8");
const index = () => new CommunityIndexClient(async () => new Response(fixture));
const PIN = "sha256:370bafec5a904285398c108f6c75bd8e644abb645ffe81c1524b153cfb617aca";
const BUILT_FP = `sha256:${"e".repeat(64)}`;
const row = (id: string) => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id } });

async function owner() {
  const f = await buildOwnerFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { imageCacheCapBytes: 1n << 34n, imageCacheUsedBytes: 0n, imageCacheForeignBytes: 0n },
  });
  return f;
}

/** Create the community template and drive its build until the host's
 * capture result is recorded (CAPTURING, capture CAPTURED). */
async function toCaptured(f: Awaited<ReturnType<typeof owner>>) {
  const created = await createCommunityTemplate(
    f.session,
    {
      source: "ubuntu-26.04",
      idempotencyKey: `c-${Math.random()}`,
      target: { sandboxHostId: f.host.id },
    },
    new Date(),
    index(),
  );
  const buildId = created.build!.id;
  const advance = () => advanceTemplateBuild({ id: buildId, userId: f.id });
  await advance(); // build VM create
  const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { buildId } });
  await daemon.ready(buildId);
  await advance(); // READY → RUNNING
  for (let op = await currentOperation(db, buildId); op?.kind === "RUN_COMMAND"; ) {
    await daemon.command(op.id, 0);
    await advance();
    op = await currentOperation(db, buildId);
  }
  await advance(); // lease → stop
  const stop = await currentOperation(db, buildId);
  await daemon.stopped(stop!.id, vm.id);
  await advance(); // capture claimed
  const capture = (await row(buildId)).captureOperationId!;
  await db.inspect.$transaction((tx) =>
    recordCaptureResult(tx, {
      operationId: capture,
      hostId: f.host.id,
      epoch: f.host.connectionEpoch,
      result: { fingerprint: BUILT_FP, sizeBytes: 4096, architecture: "x86_64" },
    }),
  );
  return { created, buildId, vm, capture, advance };
}

/** Create the community template and drive its build to the verify phase. */
async function toVerify(f: Awaited<ReturnType<typeof owner>>) {
  const { created, buildId, vm, capture, advance } = await toCaptured(f);
  const finalized = await finalizeCapture(capture);
  expect(finalized.kind).toBe("finalized");
  const revisionId = (finalized as { revisionId: string }).revisionId;
  return { created, buildId, vm, revisionId, advance };
}

async function verifyVmReady(buildId: string) {
  const vvm = await db.inspect.sandbox.findUniqueOrThrow({ where: { verifyBuildId: buildId } });
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: vvm.id, kind: "CREATE_SANDBOX" },
  });
  await daemon.succeed(create.id);
  await db.inspect.sandbox.update({ where: { id: vvm.id }, data: { state: "READY" } });
  return vvm;
}

describe("community create (S8, criterion 1)", () => {
  it("writes one template, one untagged UPSTREAM pin and one COMMUNITY_PREP build; idempotent", async () => {
    const f = await owner();
    const input = {
      source: "ubuntu-26.04",
      idempotencyKey: "same",
      target: { sandboxHostId: f.host.id },
    };
    const first = await createCommunityTemplate(f.session, input, new Date(), index());
    const again = await createCommunityTemplate(f.session, input, new Date(), index());
    expect(again.build?.id).toBe(first.build?.id);
    const other = await createCommunityTemplate(
      f.session,
      { ...input, idempotencyKey: "other" },
      new Date(),
      index(),
    );
    expect(other).toMatchObject({ existing: true, template: { id: first.template.id } });
    const revisions = await db.inspect.sandboxTemplateRevision.findMany({
      where: { templateId: first.template.id },
    });
    expect(revisions).toHaveLength(1);
    expect(revisions[0]).toMatchObject({
      sourceKind: "UPSTREAM",
      incusFingerprint: PIN,
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
    });
    expect(
      await db.inspect.sandboxTemplateTag.count({ where: { templateId: first.template.id } }),
    ).toBe(0);
    const build = await row(first.build!.id);
    expect(build).toMatchObject({
      origin: "COMMUNITY_PREP",
      verifyRequired: true,
      noCache: true,
      timeoutMinutes: 40,
      reservedMinutes: 40,
      baseRevisionId: revisions[0]!.id,
      waitForCapacityMs: null,
    });
    expect(
      await db.inspect.sandboxTemplateBuild.count({ where: { templateId: first.template.id } }),
    ).toBe(1);
  });

  it("a replay of the same key with another host or label is an idempotency conflict (create and retry)", async () => {
    const f = await owner();
    const input = {
      source: "ubuntu-26.04",
      idempotencyKey: "same-key",
      target: { sandboxHostId: f.host.id },
    };
    const first = await createCommunityTemplate(f.session, input, new Date(), index());
    const conflict = { data: { code: "sandbox.idempotency_conflict" } };
    await expect(
      createCommunityTemplate(
        f.session,
        { ...input, target: { sandboxHostId: "another-host" } },
        new Date(),
        index(),
      ),
    ).rejects.toMatchObject(conflict);
    await expect(
      createCommunityTemplate(f.session, { ...input, label: "Renamed" }, new Date(), index()),
    ).rejects.toMatchObject(conflict);
    // The exact replay still returns the acceptance.
    expect((await createCommunityTemplate(f.session, input, new Date(), index())).build?.id).toBe(
      first.build?.id,
    );
    // Retry: cancel the first build, retry once, then replay its key elsewhere.
    await requestTemplateBuildCancel(f.session, first.build!.id);
    await advanceTemplateBuild({ id: first.build!.id, userId: f.id });
    const retry = { templateId: first.template.id, idempotencyKey: "retry-key" };
    const retried = await retryCommunityTemplate(f.session, retry, new Date(), index());
    expect(retried.existing).toBe(false);
    await expect(
      retryCommunityTemplate(
        f.session,
        { ...retry, target: { sandboxHostId: "another-host" } },
        new Date(),
        index(),
      ),
    ).rejects.toMatchObject(conflict);
    expect((await retryCommunityTemplate(f.session, retry, new Date(), index())).build?.id).toBe(
      retried.build?.id,
    );
  });
});

describe("bootstrap build VM (S7, I12)", () => {
  it("dispatches the upstream plan with bootstrap, guestSudo off, and nobody else can boot the pin", async () => {
    const f = await owner();
    const created = await createCommunityTemplate(
      f.session,
      { source: "ubuntu-26.04", idempotencyKey: "boot", target: { sandboxHostId: f.host.id } },
      new Date(),
      index(),
    );
    const buildId = created.build!.id;
    await advanceTemplateBuild({ id: buildId, userId: f.id });
    const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { buildId } });
    expect(vm).toMatchObject({ purpose: "TEMPLATE_BUILD", guestSudo: false, guestRoot: false });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: vm.id, eventType: "sandbox.create_requested" },
    });
    expect(event.payload).toMatchObject({
      build: { buildId, bootstrap: true },
      image: {
        fingerprint: PIN,
        format: "split",
        source: "upstream",
        upstream: {
          metaPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/incus.tar.xz",
          diskPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/disk.qcow2",
          metaSize: 1208,
          diskSize: 495803904,
        },
      },
    });
    // A workload create of the pin is refused at resolution, by id.
    const upstream = await db.inspect.sandboxTemplateRevision.findFirstOrThrow({
      where: { templateId: created.template.id, sourceKind: "UPSTREAM" },
    });
    await expect(
      db.prisma.$transaction((tx) =>
        resolveTemplateRevision(tx, f.session, `revision/${upstream.id}`),
      ),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_not_found" } });
    await expect(
      createSandbox(f.session, {
        template: `revision/${upstream.id}`,
        sandboxHostId: f.host.id,
        idempotencyKey: "wl-up",
      } as never),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_not_found" } });
    // The first-create window: the slug maps to `rebuilding` after the re-proof.
    await expect(
      createSandbox(f.session, {
        template: created.template.slug,
        sandboxHostId: f.host.id,
        idempotencyKey: "wl-slug",
      } as never),
    ).rejects.toMatchObject({
      data: { code: "sandbox.template_image_unavailable", reason: "rebuilding" },
    });
  });
});

describe("verify in CAPTURING (S9, criteria 3, 4)", () => {
  it("pass: pending until the smoke passes, then latest moves, wssp recipe marked, verify VM vkilled", async () => {
    const f = await owner();
    const { buildId, vm, revisionId, advance } = await toVerify(f);
    const pending = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(pending).toMatchObject({ pendingVerifyBuildId: buildId, sourceKind: "BUILD" });
    expect(await row(buildId)).toMatchObject({ state: "CAPTURING", phase: "verifying" });
    expect(await db.inspect.sandboxTemplateTag.count({ where: { revisionId } })).toBe(0);
    // Not launchable while pending.
    await expect(
      db.prisma.$transaction((tx) =>
        resolveTemplateRevision(tx, f.session, `revision/${revisionId}`),
      ),
    ).rejects.toMatchObject({ data: { code: "sandbox.template_not_found" } });
    // The build VM must die now; there is no verify VM yet.
    await runTemplateBuildCleanup();
    await daemon.killed(vm.id);

    await advance(); // vcreate
    const vvm = await db.inspect.sandbox.findUniqueOrThrow({ where: { verifyBuildId: buildId } });
    expect(vvm).toMatchObject({
      purpose: "TEMPLATE_VERIFY",
      buildId: null,
      templateRevisionId: revisionId,
      guestSudo: false,
    });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: vvm.id, eventType: "sandbox.create_requested" },
    });
    expect((event.payload as Record<string, unknown>).build).toBeUndefined();
    // Deny-all egress: an allowlist request with no grants.
    expect(vvm.egressRequest).toMatchObject({ mode: "allowlist", domains: [], cidrs: [] });
    await verifyVmReady(buildId);
    // U2: a live verify VM is not a cleanup candidate while its build verifies.
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: vvm.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);

    await advance(); // vrun
    const smoke = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: vvm.id, kind: "RUN_COMMAND" },
    });
    expect(smoke.idempotencyKey).toBe(buildActionKey(buildId, "vrun", 0, 0));
    await daemon.command(smoke.id, 0, "wssp-smoke-ok\n");
    await advance(); // verify_finish(pass)
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "SUCCEEDED", revisionId });
    const published = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(published).toMatchObject({
      pendingVerifyBuildId: null,
      builtWithRoot: true,
      builtWithWsspRecipe: true,
      capturedWithGuestRoot: false,
    });
    expect(
      await db.inspect.sandboxTemplateTag.findFirst({
        where: { templateId: published.templateId, tag: "latest" },
      }),
    ).toMatchObject({ revisionId });
    // Pass path (U9): the verify VM is cleanup-killed in its own key namespace before DONE.
    await runTemplateBuildCleanup();
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: vvm.id, kind: "KILL_SANDBOX" },
    });
    expect(kill.idempotencyKey).toBe(buildActionKey(buildId, "vkill", 0, 0));
    expect((await row(buildId)).cleanupState).toBe("PENDING");
    await daemon.killed(vvm.id);
    await runTemplateBuildCleanup();
    expect((await row(buildId)).cleanupState).toBe("DONE");
  });

  it("fail: the revision retires verify_failed, latest is unchanged", async () => {
    const f = await owner();
    const { buildId, vm, revisionId, advance } = await toVerify(f);
    await runTemplateBuildCleanup();
    await daemon.killed(vm.id);
    await advance();
    const vvm = await verifyVmReady(buildId);
    await advance();
    const smoke = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: vvm.id, kind: "RUN_COMMAND" },
    });
    await daemon.command(smoke.id, 11, "smoke: passwordless escalation succeeded\n");
    await advance();
    expect(await row(buildId)).toMatchObject({
      state: "FAILED",
      errorCode: "build_verify_failed",
      errorDetail: "smoke_failed",
    });
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }),
    ).toMatchObject({ retiredReason: "verify_failed" });
    expect(await db.inspect.sandboxTemplateTag.count({ where: { revisionId } })).toBe(0);
  });

  it("cancel during verify: the verify VM is vkilled, the revision retires, the build ends CANCELLED", async () => {
    const f = await owner();
    const { buildId, vm, revisionId, advance } = await toVerify(f);
    await runTemplateBuildCleanup();
    await daemon.killed(vm.id);
    await advance();
    const vvm = await verifyVmReady(buildId);
    await requestTemplateBuildCancel(f.session, buildId);
    await advance();
    expect((await row(buildId)).state).toBe("CANCELLING");
    await runTemplateBuildCleanup();
    expect(
      (
        await db.inspect.sandboxOperation.findFirstOrThrow({
          where: { sandboxId: vvm.id, kind: "KILL_SANDBOX" },
        })
      ).idempotencyKey,
    ).toBe(buildActionKey(buildId, "vkill", 0, 0));
    await daemon.killed(vvm.id);
    await advance();
    expect((await row(buildId)).state).toBe("CANCELLED");
    expect(
      (await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }))
        .retiredAt,
    ).not.toBeNull();
  });

  it("cancel while the S3 upload stores: no exception for a community build, so the VM dies, the upload loses authority and the capture fails without waiting for storage", async () => {
    imageMode.value = "s3";
    const f = await owner();
    const { buildId, vm, capture, advance } = await toCaptured(f);
    const killsOfVm = () =>
      db.inspect.sandboxOperation.count({ where: { sandboxId: vm.id, kind: "KILL_SANDBOX" } });
    const authority = () =>
      checkAcceptedDispatchAuthority(
        {
          ownerId: f.id,
          principal: { kind: "build", buildId, keyId: null },
          operationKind: "CAPTURE_TEMPLATE",
          context: {
            operationId: capture,
            sandboxId: vm.id,
            sandboxHostId: f.host.id,
            templateRevisionId: vm.templateRevisionId,
            originPoolId: vm.originPoolId,
          },
        },
        db.prisma,
      );
    // Before the cancel the upload stores on the build VM's authority.
    expect(await finalizeCapture(capture)).toMatchObject({ kind: "waiting" });
    await runTemplateBuildCleanup();
    expect(await killsOfVm()).toBe(0);
    expect(await authority()).toBe("active");

    // The result was recorded before the cancel, but a community build has
    // not verified, so the cancel wins (S9): nothing is kept for its upload.
    await requestTemplateBuildCancel(f.session, buildId);
    await advance();
    expect((await row(buildId)).state).toBe("CANCELLING");
    expect(
      (
        await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
          where: { operationId: capture },
        })
      ).buildCancelledAt,
    ).toBeNull();
    await runTemplateBuildCleanup();
    expect(await killsOfVm()).toBe(1);
    expect(await authority()).toBe("inactive");
    // Never stored, yet the finalizer fails it at once instead of waiting.
    expect(await finalizeCapture(capture)).toMatchObject({ kind: "failed" });
    expect(
      await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
        where: { operationId: capture },
      }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_failed" });
    await daemon.killed(vm.id);
    await advance();
    expect((await row(buildId)).state).toBe("CANCELLED");
  });

  it("a verify that stalls past its deadline fails and retires its pending revision", async () => {
    const f = await owner();
    const { buildId, vm, revisionId, advance } = await toVerify(f);
    await runTemplateBuildCleanup();
    await daemon.killed(vm.id);
    await advance(); // vcreate; the verify VM never becomes READY
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { verifyDeadlineAt: new Date(Date.now() - 1000), pendingAction: Prisma.DbNull },
    });
    await advance();
    expect(await row(buildId)).toMatchObject({
      state: "FAILED",
      errorCode: "build_verify_failed",
      errorDetail: "verify_deadline",
    });
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }),
    ).toMatchObject({ retiredReason: "verify_failed", pendingVerifyBuildId: buildId });
    expect(
      (await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }))
        .retiredAt,
    ).not.toBeNull();
  });

  it("a manual retire during verify wins (D-L)", async () => {
    const f = await owner();
    const { buildId, vm, revisionId, advance } = await toVerify(f);
    await runTemplateBuildCleanup();
    await daemon.killed(vm.id);
    await retireTemplateRevision(f.session, { id: revisionId } as never);
    await advance();
    expect(await row(buildId)).toMatchObject({
      state: "FAILED",
      errorCode: "build_verify_failed",
      errorDetail: "revision_retired",
    });
  });
});
