vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-orchestrator-fixture",
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
/** Runs once right after the next capture acceptance commits (a race seam). */
const captureSeam = vi.hoisted(() => ({ after: null as null | (() => Promise<unknown>) }));
vi.mock("../sandbox/image-store/captures", async (original) => {
  const actual = await original<typeof import("../sandbox/image-store/captures")>();
  return {
    ...actual,
    captureSandbox: async (...args: Parameters<typeof actual.captureSandbox>) => {
      const result = await actual.captureSandbox(...args);
      const after = captureSeam.after;
      captureSeam.after = null;
      if (after) await after();
      return result;
    },
  };
});
/** The image distribution mode (peer unless a test stores to S3). */
const imageMode = vi.hoisted(() => ({ value: "peer" as "peer" | "s3" }));
vi.mock("../sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("../sandbox/image-store/config")>()),
  imageDistributionMode: () => imageMode.value,
}));

/**
 * Template builds pg tests owned by B6: pg 22 (no orphan build
 * VM: the create/cancel race and the cleanup invariant), pg 4 (cancel vs
 * finalizer, both orders), and minutes settled once and clamped.
 */
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { checkAcceptedDispatchAuthority } from "../lib/sdk-key-access";
import { assertHostDeletable } from "../sandbox/host-admission";
import { recordCaptureResult } from "../sandbox/image-store/capture-result";
import { finalizeCapture } from "../sandbox/image-store/captures";
import { originImagesToRelease } from "../sandbox/image-store/jobs";
import { droppedCaptureImageToRelease } from "../sandbox/image-store/references";
import { lockHostByEpoch } from "../sandbox/relay-fence";
import { sdkListHosts } from "../sandbox/sdk-reads";
import { SandboxIntegrityError } from "../sandbox/sensitive-errors";
import { seedSandboxInstance } from "../sandbox/testing/resource-fixtures";
import { parseStepRecords } from "./exec-plan";
import { recordBuildEgressHints } from "./hints";
import { advanceTemplateBuild, runTemplateBuildCleanup } from "./orchestrator";
import { acceptTemplateBuild, requestTemplateBuildCancel } from "./service";
import { buildOwnerFixture, currentOperation, fakeDaemon } from "./testing/build-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => {
  imageMode.value = "peer";
});
const daemon = fakeDaemon(db);

const RECIPE = {
  version: 1,
  from: { template: "base" },
  steps: [
    { type: "env", values: { FOO: "bar" } },
    { type: "workdir", path: "/home/user/app" },
    { type: "run", script: "apt-get install -y jq", user: "root" },
    { type: "run", script: "echo $FOO > out" },
  ],
};

async function accepted(f: Awaited<ReturnType<typeof buildOwnerFixture>>, timeoutMinutes = 30) {
  const { build } = await acceptTemplateBuild(f.session, {
    idempotencyKey: `accept-${Math.random()}`,
    template: { slug: "built" },
    recipe: RECIPE,
    sandboxHostId: f.host.id,
    timeoutMinutes,
    noCache: true,
  });
  return build.id;
}
const row = (id: string) => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id } });
const CAPTURED_FP = `sha256:${"c".repeat(64)}`;
const advance = (f: { id: string }, buildId: string) =>
  advanceTemplateBuild({ id: buildId, userId: f.id });

/** Drive a fresh build to READY with its first step claimed. */
async function running(f: Awaited<ReturnType<typeof buildOwnerFixture>>, timeoutMinutes = 30) {
  const buildId = await accepted(f, timeoutMinutes);
  await advance(f, buildId); // create
  const sandbox = await daemon.ready(buildId);
  await advance(f, buildId); // READY → RUNNING, step 0 (prelude) claimed
  return { buildId, sandbox };
}

/** Run every exec step to exit 0, then lease, stop (STOPPED), capture claimed. */
async function toCapture(
  f: Awaited<ReturnType<typeof buildOwnerFixture>>,
  buildId: string,
  sandboxId: string,
) {
  for (let i = 0; i < 3; i++) {
    const op = await currentOperation(db, buildId);
    expect(op?.kind).toBe("RUN_COMMAND");
    await daemon.command(op!.id, 0);
    await advance(f, buildId);
  }
  // Last step done: lease re-anchor claimed; then STOPPING with the stop.
  expect((await row(buildId)).phase).toBe("lease");
  await advance(f, buildId);
  const stop = await currentOperation(db, buildId);
  expect(stop?.kind).toBe("STOP_SANDBOX");
  await daemon.stopped(stop!.id, sandboxId);
  await advance(f, buildId); // STOPPED → CAPTURING, capture claimed
  const build = await row(buildId);
  expect(build.state).toBe("CAPTURING");
  expect(build.captureOperationId).not.toBeNull();
  return build;
}

describe("no orphan build VM (pg 22, N18)", () => {
  it("cancel committed between the create's authorization and its placement: the create is refused, no VM", async () => {
    const f = await buildOwnerFixture(db);
    const buildId = await accepted(f);
    const ownerLock = {
      before: "sql:SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(?, 31))",
    };
    // First owner-placement lock: the orchestrator's own tx A. Let it pass,
    // then park the create at ITS owner-placement lock (after authorization).
    const claim = db.pauseAt("orch", ownerLock);
    const run = db.run("orch", () => advance(f, buildId));
    await claim.waitReached();
    const place = db.pauseAt("orch", ownerLock);
    claim.release();
    await place.waitReached();
    expect((await row(buildId)).state).toBe("PLACING");
    await requestTemplateBuildCancel(f.session, buildId);
    place.release();
    await run;
    expect(await db.inspect.sandbox.count({ where: { buildId } })).toBe(0);
    const build = await row(buildId);
    expect(build.state).toBe("CANCELLING");
    expect(build.pendingAction).toBeNull();
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({
      state: "CANCELLED",
      chargedMinutes: 0,
      minutesSettled: true,
    });
    await runTemplateBuildCleanup();
    expect((await row(buildId)).cleanupState).toBe("DONE");
  });

  it("cancel after the create committed: the cleanup invariant kills the VM, DONE only after the kill", async () => {
    const f = await buildOwnerFixture(db);
    const buildId = await accepted(f);
    await advance(f, buildId);
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { buildId } });
    expect(sandbox).toMatchObject({ purpose: "TEMPLATE_BUILD", buildId });
    await requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    expect((await row(buildId)).state).toBe("CANCELLED");
    await runTemplateBuildCleanup();
    const kills = await db.inspect.sandboxOperation.findMany({
      where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
    });
    expect(kills.map((k) => k.idempotencyKey)).toEqual([`tb:${buildId}:kill:0:0`]);
    // A second pass does not issue another kill while the first is in flight.
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(1);
    expect((await row(buildId)).cleanupState).toBe("PENDING");
    // No operation was ever cancelled (r2 N2).
    expect(
      await db.inspect.outboxEvent.count({
        where: { userId: f.id, eventType: { contains: "cancel" } },
      }),
    ).toBe(0);
    await daemon.killed(sandbox.id);
    await runTemplateBuildCleanup();
    expect((await row(buildId)).cleanupState).toBe("DONE");
  });

  it("a VM inserted with the id of a CANCELLED build (simulated crash) is killed by the next pass", async () => {
    const f = await buildOwnerFixture(db);
    const buildId = await accepted(f);
    await requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    await runTemplateBuildCleanup();
    expect((await row(buildId)).cleanupState).toBe("DONE");
    // A bug or crash left a VM behind after the build ended.
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { cleanupState: "PENDING", cleanupDoneAt: null },
    });
    const orphan = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        templateId: f.base.id,
        originPoolId: null,
        state: "READY",
        purpose: "TEMPLATE_BUILD",
        buildId,
      },
    });
    await runTemplateBuildCleanup();
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: orphan.id, kind: "KILL_SANDBOX" },
    });
    expect(kill.idempotencyKey).toBe(`tb:${buildId}:kill:0:0`);
    expect((await row(buildId)).cleanupState).toBe("PENDING");
    await daemon.killed(orphan.id);
    await runTemplateBuildCleanup();
    expect((await row(buildId)).cleanupState).toBe("DONE");
  });

  it("a live build's VM is never killed; a deadline failure is (build_timeout, step outcome ignored)", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { deadlineAt: new Date(Date.now() - 1000) },
    });
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({ state: "FAILED", errorCode: "build_timeout" });
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(1);
    // The in-flight step ends later: recorded nowhere that changes the outcome.
    const step = await currentOperation(db, buildId);
    if (step) await daemon.command(step.id, 1);
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({ state: "FAILED", errorCode: "build_timeout" });
  });
});

describe("cleanup fairness (§3.10)", () => {
  it("ended builds that stay blocked never starve a later one: the pass rotates past them", async () => {
    const f = await buildOwnerFixture(db);
    const template = await accepted(f);
    const source = await row(template);
    await db.inspect.sandboxTemplateBuild.delete({ where: { id: template } });
    const {
      id: _id,
      idempotencyKey: _key,
      createdAt: _created,
      updatedAt: _updated,
      ...data
    } = source;
    const ended = {
      ...data,
      steps: data.steps ?? [],
      buildArgs: data.buildArgs ?? {},
      recipe: data.recipe ?? {},
      egressRequest: undefined,
      pendingAction: undefined,
      egressHints: undefined,
      state: "CANCELLED" as const,
      cancelRequestedAt: new Date(),
      completedAt: new Date(),
      cleanupState: "PENDING" as const,
    };
    // A full batch of ended builds whose VM cannot be killed yet (STOPPING
    // settles first) and that sort before the last one in every order.
    const blocked: string[] = [];
    for (let i = 0; i < 32; i++) {
      const build = await db.inspect.sandboxTemplateBuild.create({
        data: { ...ended, idempotencyKey: `blocked-${i}-${Math.random()}` },
      });
      await seedSandboxInstance(db.inspect, {
        data: {
          userId: f.id,
          sandboxHostId: f.host.id,
          originHostId: f.host.id,
          templateId: f.base.id,
          originPoolId: null,
          state: "STOPPING",
          purpose: "TEMPLATE_BUILD",
          buildId: build.id,
        },
      });
      blocked.push(build.id);
    }
    const last = await db.inspect.sandboxTemplateBuild.create({
      data: { ...ended, idempotencyKey: `last-${Math.random()}` },
    });
    // Oldest-first paging re-read the same 32 blocked builds every pass.
    for (let pass = 0; pass < 10 && (await row(last.id)).cleanupState === "PENDING"; pass++)
      await runTemplateBuildCleanup();
    expect((await row(last.id)).cleanupState).toBe("DONE");
    for (const id of blocked) expect((await row(id)).cleanupState).toBe("PENDING");
  });
});

describe("capture capacity blocker (E1-A-07)", () => {
  it("a capture refused for host disk shows capture_waiting_capacity, then captures once room exists", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    for (let i = 0; i < 3; i++) {
      const op = await currentOperation(db, buildId);
      await daemon.command(op!.id, 0);
      await advance(f, buildId);
    }
    await advance(f, buildId); // lease → stop claimed
    const stop = await currentOperation(db, buildId);
    await daemon.stopped(stop!.id, sandbox.id);
    // No room for the capture's hold on the build VM's storage pool.
    const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    const pool = await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
      where: { id: vm.storagePoolId! },
    });
    await db.inspect.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: { capacityGiB: pool.diskReservedGiB },
    });
    await advance(f, buildId); // STOPPED → CAPTURING, capture refused (retryable)
    const waiting = await row(buildId);
    expect(waiting).toMatchObject({
      state: "CAPTURING",
      phase: "capture_waiting_capacity",
      captureOperationId: null,
    });
    await db.inspect.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: { capacityGiB: pool.capacityGiB },
    });
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { nextAttemptAt: new Date() },
    });
    await advance(f, buildId); // the same key replays and is accepted
    const capturing = await row(buildId);
    expect(capturing.phase).toBe("capturing");
    expect(capturing.captureOperationId).not.toBeNull();
  });
});

/** The S3 store's verified copy of the fake daemon's captured image. */
async function storeCapturedImage(userId: string) {
  await db.inspect.sandboxImageArtifact.upsert({
    where: { userId_fingerprint: { userId, fingerprint: `sha256:${"f".repeat(64)}` } },
    create: {
      userId,
      fingerprint: `sha256:${"f".repeat(64)}`,
      architecture: "x86_64",
      sizeBytes: 1024n,
      storeKind: "S3",
      state: "STORED",
      objectKey: "images/fixture",
      storedAt: new Date(),
      verifiedAt: new Date(),
    },
    update: {
      storeKind: "S3",
      state: "STORED",
      objectKey: "images/fixture",
      storedAt: new Date(),
      verifiedAt: new Date(),
    },
  });
}

/** The upload's dispatch authority for a build VM's operation of `kind`. */
async function uploadAuthority(
  f: Awaited<ReturnType<typeof buildOwnerFixture>>,
  buildId: string,
  sandboxId: string,
  operationId: string,
  operationKind = "CAPTURE_TEMPLATE",
) {
  const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  return checkAcceptedDispatchAuthority(
    {
      ownerId: f.id,
      principal: { kind: "build", buildId, keyId: null },
      operationKind,
      context: {
        operationId,
        sandboxId,
        sandboxHostId: f.host.id,
        templateRevisionId: vm.templateRevisionId,
        originPoolId: vm.originPoolId,
      },
    },
    db.prisma,
  );
}

const killsOf = (sandboxId: string) =>
  db.inspect.sandboxOperation.count({ where: { sandboxId, kind: "KILL_SANDBOX" } });

describe("S3 storage after a recorded capture (VM lifetime and authority)", () => {
  it("a capture recorded before the cancel keeps its VM and upload authority until stored, then publishes", async () => {
    imageMode.value = "s3";
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const operationId = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    await daemon.captured(operationId, f.host.id, f.host.connectionEpoch);
    // Not stored yet: the capture waits in STORING with its VM alive.
    expect(await finalizeCapture(operationId)).toMatchObject({ kind: "waiting" });
    await runTemplateBuildCleanup();
    expect(await killsOf(sandbox.id)).toBe(0);
    expect(await uploadAuthority(f, buildId, sandbox.id, operationId)).toBe("active");

    await requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({ state: "CANCELLING" });
    // The recorded result wins: the VM is kept and only this capture's own
    // operation keeps dispatch authority; any other build dispatch is refused.
    await runTemplateBuildCleanup();
    expect(await killsOf(sandbox.id)).toBe(0);
    expect(await uploadAuthority(f, buildId, sandbox.id, operationId)).toBe("active");
    expect(await uploadAuthority(f, buildId, sandbox.id, operationId, "RUN_COMMAND")).toBe(
      "inactive",
    );
    const other = await currentOperation(db, buildId);
    if (other && other.id !== operationId)
      expect(await uploadAuthority(f, buildId, sandbox.id, other.id)).toBe("inactive");

    // Stored: it publishes, the build ends SUCCEEDED and the VM is killed.
    await storeCapturedImage(f.id);
    expect(await finalizeCapture(operationId)).toMatchObject({ kind: "finalized" });
    expect(await row(buildId)).toMatchObject({ state: "SUCCEEDED" });
    expect(await uploadAuthority(f, buildId, sandbox.id, operationId)).toBe("inactive");
    await runTemplateBuildCleanup();
    expect(await killsOf(sandbox.id)).toBe(1);
  });

  it("a capture recorded after the cancel loses: the VM dies at once and the upload has no authority", async () => {
    imageMode.value = "s3";
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const operationId = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    await requestTemplateBuildCancel(f.session, buildId);
    await daemon.captured(operationId, f.host.id, f.host.connectionEpoch);
    const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId },
    });
    expect(capture).toMatchObject({ state: "CAPTURED" });
    expect(capture.buildCancelledAt).not.toBeNull();
    expect(await uploadAuthority(f, buildId, sandbox.id, operationId)).toBe("inactive");
    await advance(f, buildId);
    await runTemplateBuildCleanup();
    expect(await killsOf(sandbox.id)).toBe(1);
  });

  it("storage never outlives the build VM: the finalizer fails it at the VM's lease", async () => {
    imageMode.value = "s3";
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const operationId = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    // The re-anchored lease reserves the capture window + storage window + slack.
    const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    const lease = vm.leaseExpiresAt!;
    expect(lease.getTime()).toBeGreaterThan(Date.now() + 130 * 60_000);
    await daemon.captured(operationId, f.host.id, f.host.connectionEpoch);
    // Before the lease (and within the 2 h store bound): it keeps waiting.
    const created = (
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } })
    ).createdAt;
    expect(
      await finalizeCapture(operationId, new Date(created.getTime() + 60 * 60_000)),
    ).toMatchObject({ kind: "waiting" });
    // A host lease shortened to 30 min after the capture bounds storage there.
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { leaseExpiresAtEffective: new Date(created.getTime() + 30 * 60_000) },
    });
    expect(
      await finalizeCapture(operationId, new Date(created.getTime() + 31 * 60_000)),
    ).toMatchObject({ kind: "failed" });
    expect(
      await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_store_failed" });
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({ state: "FAILED", errorCode: "build_store_failed" });
  });
});

describe("cancel vs finalizer (pg 4, r3 N22)", () => {
  it("host CAPTURED recorded before the cancel: published, tag moved, SUCCEEDED with cancelRequestedAt kept", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const build = await toCapture(f, buildId, sandbox.id);
    await daemon.captured(build.captureOperationId!, f.host.id, f.host.connectionEpoch);
    await requestTemplateBuildCancel(f.session, buildId);
    // The orchestrator waits for the finalizer (the result wins) ...
    await advance(f, buildId);
    expect((await row(buildId)).state).toBe("CANCELLING");
    // ... and the cleanup invariant keeps the stopped VM until it is stored.
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
    expect(await finalizeCapture(build.captureOperationId!)).toMatchObject({ kind: "finalized" });
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "SUCCEEDED" });
    await runTemplateBuildCleanup();
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(1);
    expect(done.cancelRequestedAt).not.toBeNull();
    const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: done.revisionId! },
    });
    expect(revision).toMatchObject({
      sourceKind: "BUILD",
      buildId,
      defaultCwd: "/home/user/app",
      builtWithRoot: true,
      // The build VM inherits its base's taint (none here); the wssp-recipe
      // flag is written explicitly false until community-base's writer.
      capturedWithGuestRoot: false,
      builtWithWsspRecipe: false,
    });
    const tag = await db.inspect.sandboxTemplateTag.findFirstOrThrow({
      where: { templateId: done.templateId, tag: "latest" },
    });
    expect(tag.revisionId).toBe(revision.id);
  });

  it("a capture accepted before the cancel but never linked (tx B discarded) is still found by buildId; its later result loses", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const accepted = await toCapture(f, buildId, sandbox.id);
    const operationId = accepted.captureOperationId!;
    // The race: the capture committed, then the cancel cleared the claim,
    // so the outcome transaction discarded the link to the build.
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { captureOperationId: null },
    });
    await requestTemplateBuildCancel(f.session, buildId);
    // The host result arrives after the cancel committed: the cancel wins
    // (E2-A-01 ruling). It is recorded only so its image can be released.
    await daemon.captured(operationId, f.host.id, f.host.connectionEpoch);
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({
      state: "CANCELLING",
      captureOperationId: operationId,
    });
    expect(await finalizeCapture(operationId)).toMatchObject({
      kind: "failed",
      fingerprint: `sha256:${"f".repeat(64)}`,
    });
    await advance(f, buildId);
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "CANCELLED", revisionId: null });
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { buildId } })).toBe(0);
    expect(
      await db.inspect.sandboxTemplateTag.count({ where: { templateId: done.templateId } }),
    ).toBe(0);
  });

  it("race, result first: a result recorded before the cancel commits wins (the cancel waits on the capture row)", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const operationId = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    const relayCommit = db.pauseAt("relay", { before: "$transaction.commit" });
    const relay = db.run("relay", () =>
      db.prisma.$transaction((tx) =>
        recordCaptureResult(tx, {
          operationId,
          hostId: f.host.id,
          epoch: f.host.connectionEpoch,
          result: { fingerprint: CAPTURED_FP, sizeBytes: 1024, architecture: "x86_64" },
        }),
      ),
    );
    await relayCommit.waitReached();
    const cancel = db.run("cancel", () => requestTemplateBuildCancel(f.session, buildId));
    // Serialized: the cancel waits for the recording transaction's row lock.
    await db.waitUntilBlocked("cancel", { by: "relay" });
    relayCommit.release();
    expect(await relay).toBe(true);
    await cancel;
    const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId },
    });
    expect(capture).toMatchObject({ state: "CAPTURED", buildCancelledAt: null });
    expect(await finalizeCapture(operationId)).toMatchObject({ kind: "finalized" });
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "SUCCEEDED" });
    expect(done.cancelRequestedAt).not.toBeNull();
    const tag = await db.inspect.sandboxTemplateTag.findFirstOrThrow({
      where: { templateId: done.templateId, tag: "latest" },
    });
    expect(tag.revisionId).toBe(done.revisionId);
  });

  it("race, cancel first: a result arriving after the cancel commits loses (no revision, tag unchanged, image released)", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const operationId = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    const cancelCommit = db.pauseAt("cancel", { before: "$transaction.commit" });
    const cancel = db.run("cancel", () => requestTemplateBuildCancel(f.session, buildId));
    await cancelCommit.waitReached();
    const relay = db.run("relay", () =>
      db.prisma.$transaction((tx) =>
        recordCaptureResult(tx, {
          operationId,
          hostId: f.host.id,
          epoch: f.host.connectionEpoch,
          result: { fingerprint: CAPTURED_FP, sizeBytes: 1024, architecture: "x86_64" },
        }),
      ),
    );
    // Serialized: the recording waits for the cancel's mark on the capture row.
    await db.waitUntilBlocked("relay", { by: "cancel" });
    cancelCommit.release();
    await cancel;
    // Recorded (the image's fingerprint is kept for its release), never published.
    expect(await relay).toBe(true);
    const marked = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId },
    });
    expect(marked.state).toBe("CAPTURED");
    expect(marked.buildCancelledAt).not.toBeNull();
    expect(await finalizeCapture(operationId)).toMatchObject({
      kind: "failed",
      fingerprint: CAPTURED_FP,
      hostId: f.host.id,
      ownerId: f.id,
    });
    expect(
      await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } }),
    ).toMatchObject({ state: "FAILED", resourcesHeld: false, revisionId: null });
    await advance(f, buildId);
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "CANCELLED", revisionId: null });
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { buildId } })).toBe(0);
    expect(
      await db.inspect.sandboxTemplateTag.count({ where: { templateId: done.templateId } }),
    ).toBe(0);
  });

  it("the kill retires a pending capture first: no revision, hold released once, CANCELLED", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const build = await toCapture(f, buildId, sandbox.id);
    await requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    expect((await row(buildId)).state).toBe("CANCELLING");
    await runTemplateBuildCleanup(); // kill → the capture operation is superseded
    // Until the host settles it, the capture is neither published nor failed.
    expect(await finalizeCapture(build.captureOperationId!)).toMatchObject({ kind: "waiting" });
    await daemon.killed(sandbox.id);
    expect(await finalizeCapture(build.captureOperationId!)).toMatchObject({ kind: "failed" });
    expect(await finalizeCapture(build.captureOperationId!)).toMatchObject({ kind: "skipped" });
    const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId: build.captureOperationId! },
    });
    expect(capture).toMatchObject({ state: "FAILED", resourcesHeld: false, revisionId: null });
    await advance(f, buildId);
    expect(await row(buildId)).toMatchObject({ state: "CANCELLED", revisionId: null });
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { buildId } })).toBe(0);
  });

  it("E2-A-01: a cancel during an in-flight capture wins and the host's capture image is released", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const build = await toCapture(f, buildId, sandbox.id);
    const operationId = build.captureOperationId!;
    const fingerprint = `sha256:${"e".repeat(64)}`;
    const dropped = () =>
      droppedCaptureImageToRelease({ operationId, hostId: f.host.id, fingerprint });
    // In flight and still fenced: its result may yet be recorded.
    expect(await dropped()).toBeNull();
    // The host published and pinned the image; a census reported the copy.
    await db.inspect.sandboxHostImageCache.create({
      data: {
        hostId: f.host.id,
        hostOwnerId: f.id,
        imageOwnerId: f.id,
        fingerprint,
        compressedBytes: 1024n,
        origin: "captured",
        pinned: true,
        connectionEpoch: f.host.connectionEpoch,
        reportedAt: new Date(),
      },
    });
    const gcSelects = async () =>
      (await originImagesToRelease()).some(
        (c) => c.hostId === f.host.id && c.fingerprint === fingerprint,
      );
    // The unrecorded PENDING capture on this host may name exactly this copy.
    expect(await gcSelects()).toBe(false);
    await requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    await runTemplateBuildCleanup(); // kill → the in-flight capture is superseded
    // The host's successful result now arrives and the relay cannot record
    // it: the superseded capture's image is released at once.
    expect(await dropped()).toEqual({ imageOwnerId: f.id, fingerprint });
    await daemon.killed(sandbox.id);
    expect(await finalizeCapture(operationId)).toMatchObject({ kind: "failed" });
    await advance(f, buildId);
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "CANCELLED", revisionId: null });
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { buildId } })).toBe(0);
    expect(
      await db.inspect.sandboxTemplateTag.count({ where: { templateId: done.templateId } }),
    ).toBe(0);
    // And a frame lost on the way is recovered by the origin-pin GC.
    expect(await dropped()).toEqual({ imageOwnerId: f.id, fingerprint });
    expect(await gcSelects()).toBe(true);
  });
});

/** The capture operation ends UNKNOWN_OUTCOME and the finalizer retires it. */
async function captureLost(operationId: string) {
  await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: { state: "UNKNOWN_OUTCOME", completedAt: new Date() },
  });
  expect(await finalizeCapture(operationId)).toMatchObject({ kind: "failed" });
}

describe("capture attempts (§3.3 retry-with-new-attempt, ruling f)", () => {
  it("an UNKNOWN_OUTCOME capture is retried as attempt 1, which captures and SUCCEEDS", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const first = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    await captureLost(first);
    await advance(f, buildId); // FAILED/UNKNOWN_OUTCOME → claim attempt 1, accepted
    const retried = await row(buildId);
    expect(retried).toMatchObject({ state: "CAPTURING", captureAttempt: 1 });
    expect(retried.captureOperationId).not.toBeNull();
    expect(retried.captureOperationId).not.toBe(first);
    const attempts = await db.inspect.sandboxTemplateCapture.findMany({
      where: { buildId },
      orderBy: { buildAttempt: "asc" },
      select: { operationId: true, buildAttempt: true, state: true },
    });
    expect(attempts).toEqual([
      { operationId: first, buildAttempt: 0, state: "FAILED" },
      { operationId: retried.captureOperationId, buildAttempt: 1, state: "PENDING" },
    ]);
    await daemon.captured(retried.captureOperationId!, f.host.id, f.host.connectionEpoch);
    expect(await finalizeCapture(retried.captureOperationId!)).toMatchObject({
      kind: "finalized",
    });
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "SUCCEEDED" });
    expect(done.revisionId).not.toBeNull();
  });

  it("a cancel racing the retry (link discarded) still recovers the CURRENT attempt, whose later result loses", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const first = (await toCapture(f, buildId, sandbox.id)).captureOperationId!;
    await captureLost(first);
    // The retry's capture commits, then the cancel clears the claim, so the
    // outcome transaction discards the link to the new attempt.
    captureSeam.after = () => requestTemplateBuildCancel(f.session, buildId);
    await advance(f, buildId);
    expect(captureSeam.after).toBeNull();
    const raced = await row(buildId);
    expect(raced).toMatchObject({
      state: "CANCELLING",
      captureAttempt: 1,
      captureOperationId: null,
    });
    const current = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { buildId_buildAttempt: { buildId, buildAttempt: 1 } },
    });
    await daemon.captured(current.operationId, f.host.id, f.host.connectionEpoch);
    await advance(f, buildId); // links attempt 1 (never attempt 0) and waits
    expect(await row(buildId)).toMatchObject({
      state: "CANCELLING",
      captureOperationId: current.operationId,
    });
    // Its result arrived after the cancel committed: the cancel wins.
    expect(await finalizeCapture(current.operationId)).toMatchObject({ kind: "failed" });
    await advance(f, buildId);
    const done = await row(buildId);
    expect(done).toMatchObject({ state: "CANCELLED", revisionId: null });
    expect(done.cancelRequestedAt).not.toBeNull();
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { buildId } })).toBe(0);
  });
});

describe("hosts during a capture (E2-A-04)", () => {
  it("a stopped VM's capture hold is a valid reservation: the hosts list reads, deletion is a conflict", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const build = await toCapture(f, buildId, sandbox.id);
    const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId: build.captureOperationId! },
    });
    expect(capture.resourcesHeld).toBe(true);
    expect(capture.chargedMemoryMiB).toBeGreaterThan(0);
    // The stopped build VM is no longer live; only the capture holds.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        liveCount: 0,
        memoryReservedMiB: capture.chargedMemoryMiB,
        vcpuReserved: capture.chargedVcpu,
      },
    });
    const page = await sdkListHosts(f.session, {});
    expect(page.items.find((host) => host.id === f.host.id)?.capacity).toMatchObject({
      memoryReservedMiB: capture.chargedMemoryMiB,
      vcpuReserved: capture.chargedVcpu,
    });
    const { default: prisma } = await import("@wssp/db");
    const deletable = () =>
      prisma.$transaction(async (tx) => {
        await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
        await assertHostDeletable(tx, f.host.id, f.id);
      });
    await expect(deletable()).rejects.toMatchObject({
      data: { code: "sandbox.host_delete_conflict" },
    });
    // A reservation beyond the capture holds is still an integrity failure.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { vcpuReserved: capture.chargedVcpu + 1 },
    });
    await expect(deletable()).rejects.toBeInstanceOf(SandboxIntegrityError);
  });
});

describe("blocked-name hints (E2-A-03)", () => {
  it("a report attributed from steps that changed meanwhile lands on the now-latest step", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f);
    const stale = await row(buildId); // step 0 (the prelude) running
    const prelude = await currentOperation(db, buildId);
    await daemon.command(prelude!.id, 0);
    await advance(f, buildId); // step 0 succeeded, step 1 started
    expect(parseStepRecords((await row(buildId)).steps)[1]?.state).toBe("running");
    // The report's attribution read happened before step 1 started.
    const { default: prisma } = await import("@wssp/db");
    const read = vi.spyOn(prisma.sandboxTemplateBuild, "findFirst").mockResolvedValueOnce(stale);
    try {
      await expect(
        recordBuildEgressHints({
          hostId: f.host.id,
          sandboxId: sandbox.id,
          names: ["late.example.org"],
        }),
      ).resolves.toBe(true);
    } finally {
      read.mockRestore();
    }
    // Never on step 0: a follower that saw step 1 start treats step 0's hints as final.
    expect((await row(buildId)).egressHints).toEqual([
      expect.objectContaining({ n: 1, name: "late.example.org" }),
    ]);
  });
});

describe("minutes (§3.3, r2 N15)", () => {
  it("charge READY → STOPPED once, rounded up and clamped to the reservation; capture time is free", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId, sandbox } = await running(f, 10);
    // The VM was READY 45 minutes ago (stop lag past the deadline is absorbed).
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: {
        readyAt: new Date(Date.now() - 45 * 60_000),
        deadlineAt: new Date(Date.now() + 60 * 60_000),
      },
    });
    const build = await toCapture(f, buildId, sandbox.id);
    expect(build).toMatchObject({ minutesSettled: true, chargedMinutes: 10, reservedMinutes: 10 });
    await daemon.captured(build.captureOperationId!, f.host.id, f.host.connectionEpoch);
    await finalizeCapture(build.captureOperationId!);
    expect(await row(buildId)).toMatchObject({ state: "SUCCEEDED", chargedMinutes: 10 });
  });

  it("a failed step charges until the failure and keeps the output tail", async () => {
    const f = await buildOwnerFixture(db);
    const { buildId } = await running(f);
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { readyAt: new Date(Date.now() - 150_000) },
    });
    const prelude = await currentOperation(db, buildId);
    await daemon.command(prelude!.id, 0);
    await advance(f, buildId);
    const step = await currentOperation(db, buildId);
    await daemon.command(step!.id, 3, "E: Unable to locate package jq\n");
    await advance(f, buildId);
    const failed = await row(buildId);
    expect(failed).toMatchObject({
      state: "FAILED",
      errorCode: "build_step_failed",
      failureStepIndex: 2,
      failureExitCode: 3,
      minutesSettled: true,
      chargedMinutes: 3,
    });
    expect(Buffer.from(failed.failureTail!).toString()).toBe("E: Unable to locate package jq\n");
  });
});
