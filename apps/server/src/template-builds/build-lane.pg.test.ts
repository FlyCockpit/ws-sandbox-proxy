import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  buildOwnerFixture,
  currentOperation,
  fakeDaemon,
} from "../../../../packages/api/src/template-builds/testing/build-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-lane-fixture",
    TRANSFER_GLOBAL_ACTIVE: 16,
    TRANSFER_OWNER_ACTIVE: 4,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/image-store/config")>()),
  imageDistributionMode: () => "peer",
}));

/**
 * Lane C e2e: a COPY build driven through
 * AWAITING_CONTEXT → QUEUED → PLACING → RUNNING (context import + PUT_FILE,
 * then steps dispatched with runAs/buildCopy) → STOPPING → CAPTURING →
 * SUCCEEDED, with a fake daemon completing each operation the way the relay
 * records host results; the cleanup invariant then kills the VM. A second
 * build is cancelled mid-RUNNING and ends with the cleanup kill.
 */
const db = await pgTestDatabase();
const { TransferStore } = await import("../sandbox-transfers/store.js");
const { BuildContextStore } = await import("./context-store.js");
const { bindBuildContextStores } = await import("./runtime.js");
const { advanceTemplateBuild, runTemplateBuildCleanup } = await import(
  "@wssp/api/template-builds/orchestrator"
);
const { acceptTemplateBuild, requestTemplateBuildCancel } = await import(
  "@wssp/api/template-builds/service"
);
const { finalizeCapture } = await import("@wssp/api/sandbox/image-store/captures");
const { loadRevisionDefaults } = await import(
  "../../../../packages/api/src/sandbox/revision-config"
);
const { buildCommandRunOperationDispatchMessage, commandRunDispatchBuildInputFromOutboxPayload } =
  await import("@wssp/api/sandbox/dispatch-control-envelope");
const { encodeServerControlMessage } = await import("../sandbox-relay/protocol.js");
const { buildDispatchFieldsMatch } = await import("../sandbox-relay/dispatch-gates.js");

const daemon = fakeDaemon(db);
const dirs: string[] = [];
const stores: { close(): Promise<void> }[] = [];
afterAll(async () => {
  for (const store of stores) await store.close();
  for (const dir of dirs) await fs.rm(dir, { recursive: true, force: true });
  await db.close();
});

async function startStores() {
  const base = await fs.mkdtemp(join(tmpdir(), "wssp-b6-lane-"));
  dirs.push(base);
  const root = join(base, "spool");
  const contexts = new BuildContextStore(root, {
    maxBytes: CHUNK * 4,
    stagedBytesPerAccount: CHUNK * 8,
    stagedBytes: CHUNK * 32,
    idleMs: 900_000,
    globalActive: 16,
  });
  await contexts.start();
  const transfers = new TransferStore(root, {
    maxBytes: CHUNK * 4,
    diskBytes: CHUNK * 8,
    ownerActive: 4,
    globalActive: 16,
    idleMs: 900_000,
    absoluteMs: 3_600_000,
  });
  await transfers.start();
  stores.push(contexts, transfers);
  bindBuildContextStores(contexts, transfers);
  return { contexts, transfers };
}

const RECIPE = {
  version: 1,
  from: { template: "base" },
  steps: [
    { type: "arg", name: "VERSION", default: "1" },
    { type: "env", values: { FOO: "bar" } },
    { type: "workdir", path: "/home/user/app" },
    { type: "run", script: "apt-get install -y jq", user: "root" },
    { type: "copy", src: ["app/"], dest: "./", owner: "user" },
    { type: "run", script: "make VERSION=$VERSION" },
  ],
};

/** The command dispatch frame the relay would send for a step's outbox row. */
async function stepFrame(operationId: string, sandboxId: string) {
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandboxId, payload: { path: ["operationId"], equals: operationId } },
  });
  const payload = event.payload as Record<string, unknown>;
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  // The outbox processor's defence: build fields match this build VM.
  expect(
    buildDispatchFieldsMatch("command.run", payload, { ...sandbox, revisionSourceKind: "MANUAL" }),
  ).toBe(true);
  const frame = buildCommandRunOperationDispatchMessage(
    commandRunDispatchBuildInputFromOutboxPayload(payload, sandboxId, {
      sandboxOwnerId: sandbox.userId,
      attempt: 1,
      bodyHash: "f".repeat(64),
      stdinSequence: 0,
    }),
  );
  // The 1.0 encoder accepts it (strict placement of build fields).
  return JSON.parse(encodeServerControlMessage(frame, "1.0")) as Record<string, unknown>;
}

describe("lane C e2e: a COPY build end to end, then a cancel mid-RUNNING", () => {
  it("QUEUED → PLACING → RUNNING (runAs/buildCopy) → CAPTURING → SUCCEEDED, then the cleanup kill", async () => {
    const { contexts } = await startStores();
    const f = await buildOwnerFixture(db);
    const content = Buffer.from("app/main.py\0print('hi')\n");
    const sha = createHash("sha256").update(content).digest("hex");
    const accepted = await acceptTemplateBuild(f.session, {
      idempotencyKey: "lane-1",
      template: { slug: "app" },
      recipe: RECIPE,
      sandboxHostId: f.host.id,
      contextSha256: sha,
      contextBytes: content.byteLength,
    });
    expect(accepted).toMatchObject({ joined: false, needsContext: true });
    const buildId = accepted.build.id;
    const advance = () => advanceTemplateBuild({ id: buildId, userId: f.id });
    const row = () => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: buildId } });
    expect((await row()).state).toBe("AWAITING_CONTEXT");
    // The client stages the context before any VM exists.
    await contexts.open(f.session, buildId);
    await contexts.write(f.session, buildId, 0, content);
    await contexts.seal(f.session, buildId);

    // QUEUED → PLACING: the create carries the build binding.
    await advance();
    expect(await row()).toMatchObject({ state: "PLACING", phase: "placing" });
    const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { buildId } });
    expect(vm).toMatchObject({ purpose: "TEMPLATE_BUILD" });
    // A session build stores no key on its work (keyed builds store the real one).
    expect(
      (await db.inspect.sandboxOperation.findFirstOrThrow({ where: { sandboxId: vm.id } }))
        .authorizingKeyId,
    ).toBeNull();
    const createEvent = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: vm.id, eventType: "sandbox.create_requested" },
    });
    const createPayload = createEvent.payload as Record<string, unknown>;
    expect(createPayload.build).toEqual({ buildId });
    expect(
      buildDispatchFieldsMatch("sandbox.create", createPayload, {
        ...vm,
        revisionSourceKind: "MANUAL",
      }),
    ).toBe(true);
    expect(createEvent.payload).toMatchObject({ authorizingPrincipal: { kind: "build", buildId } });

    // READY → RUNNING: the sealed context is imported, then committed (PUT_FILE).
    await daemon.ready(buildId);
    await advance();
    expect(await row()).toMatchObject({ state: "RUNNING", phase: "context_import" });
    const context = await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { buildId } });
    expect(context.state).toBe("ADOPTED");
    await advance();
    const put = await currentOperation(db, buildId);
    expect(put?.kind).toBe("PUT_FILE");
    expect(put?.idempotencyKey).toBe(`tb:${buildId}:context:0:0`);
    await daemon.succeed(put!.id);
    await advance();

    // Steps: the WORKDIR prelude (root), RUN root, COPY (fixed helper), RUN user.
    const frames: Record<string, unknown>[] = [];
    for (let n = 0; n < 4; n++) {
      const op = await currentOperation(db, buildId);
      const at = await row();
      expect(op?.kind, JSON.stringify({ n, phase: at.phase, pending: at.pendingAction })).toBe(
        "RUN_COMMAND",
      );
      expect(op?.idempotencyKey).toBe(`tb:${buildId}:run:${n}:0`);
      frames.push(await stepFrame(op!.id, vm.id));
      await daemon.command(op!.id, 0);
      await advance();
    }
    expect(frames[0]).toMatchObject({ runAs: "root" });
    expect(frames[1]).toMatchObject({
      runAs: "root",
      script: "apt-get install -y jq",
      cwd: "/home/user/app",
    });
    expect(frames[2]).toMatchObject({
      buildCopy: {
        contextPath: `/var/tmp/wssp-build/${buildId}/context.tar`,
        sha256: sha,
        src: ["app"],
        dest: "/home/user/app/",
        owner: "user",
      },
    });
    expect(frames[2]).not.toHaveProperty("script");
    expect(frames[2]).not.toHaveProperty("runAs");
    expect(frames[3]).not.toHaveProperty("runAs");
    expect(frames[3]).toMatchObject({ script: "make VERSION=$VERSION" });
    expect(frames[3]?.env).toEqual(
      expect.arrayContaining([
        ["FOO", "bar"],
        ["VERSION", "1"],
      ]),
    );

    // Lease re-anchor, then STOPPING.
    expect((await row()).phase).toBe("lease");
    await advance();
    expect((await row()).state).toBe("STOPPING");
    const stop = await currentOperation(db, buildId);
    expect(stop?.idempotencyKey).toBe(`tb:${buildId}:stop:0:0`);
    await daemon.stopped(stop!.id, vm.id);
    await advance();
    const capturing = await row();
    expect(capturing).toMatchObject({ state: "CAPTURING", minutesSettled: true });
    expect(capturing.captureDeadlineAt).not.toBeNull();
    const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId: capturing.captureOperationId! },
    });
    expect(capture).toMatchObject({ buildId, tag: "latest", templateId: capturing.templateId });

    // The host's result, then the finalizer's build branch.
    await daemon.captured(capture.operationId, f.host.id, f.host.connectionEpoch);
    expect(await finalizeCapture(capture.operationId)).toMatchObject({ kind: "finalized" });
    const done = await row();
    expect(done).toMatchObject({ state: "SUCCEEDED", cleanupState: "PENDING" });
    const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: done.revisionId! },
    });
    expect(revision).toMatchObject({
      sourceKind: "BUILD",
      buildId,
      parentRevisionId: f.base.id,
      recipeDigest: done.recipeDigest,
      defaultCwd: "/home/user/app",
      builtWithRoot: true,
      builtOnForeignHost: false,
      captureTag: "latest",
    });
    const defaults = Object.fromEntries(await loadRevisionDefaults(db.inspect, revision.id, f.id));
    expect(defaults).toEqual({ FOO: "bar" }); // ARG never persists

    // The cleanup invariant kills the build VM; DONE once it is gone.
    await runTemplateBuildCleanup();
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: vm.id, kind: "KILL_SANDBOX" },
    });
    expect(kill.idempotencyKey).toBe(`tb:${buildId}:kill:0:0`);
    expect((await row()).cleanupState).toBe("PENDING");
    await daemon.killed(vm.id);
    await runTemplateBuildCleanup();
    expect((await row()).cleanupState).toBe("DONE");

    // The same recipe again is a cache hit: no VM, no minutes, tag kept.
    const again = await acceptTemplateBuild(f.session, {
      idempotencyKey: "lane-1-again",
      template: { slug: "app" },
      recipe: RECIPE,
      sandboxHostId: f.host.id,
      contextSha256: sha,
      contextBytes: content.byteLength,
    });
    expect(again).toMatchObject({ cacheHit: true, needsContext: false });
    expect(again.build).toMatchObject({ state: "SUCCEEDED", cacheHitRevisionId: revision.id });
  });

  it("cancel mid-RUNNING: CANCELLED, the cleanup invariant kills the VM, no operation is cancelled", async () => {
    await startStores();
    const f = await buildOwnerFixture(db);
    const { build } = await acceptTemplateBuild(f.session, {
      idempotencyKey: "lane-2",
      template: { slug: "plain" },
      recipe: {
        version: 1,
        from: { template: "base" },
        steps: [{ type: "run", script: "sleep 600" }],
      },
      sandboxHostId: f.host.id,
    });
    const advance = () => advanceTemplateBuild({ id: build.id, userId: f.id });
    await advance();
    const vm = await daemon.ready(build.id);
    await advance();
    const step = await currentOperation(db, build.id);
    expect(step?.state).toBe("QUEUED");
    await requestTemplateBuildCancel(f.session, build.id);
    // Idempotent; terminal builds refuse (template.build_not_cancellable).
    await requestTemplateBuildCancel(f.session, build.id);
    await advance();
    expect(
      await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: build.id } }),
    ).toMatchObject({
      state: "CANCELLED",
      minutesSettled: true,
    });
    await runTemplateBuildCleanup();
    const kills = await db.inspect.sandboxOperation.findMany({
      where: { sandboxId: vm.id, kind: "KILL_SANDBOX" },
    });
    expect(kills.map((kill) => kill.idempotencyKey)).toEqual([`tb:${build.id}:kill:0:0`]);
    // The step is superseded by the kill, never cancelled on its own.
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: vm.id, eventType: { contains: "cancel" } },
      }),
    ).toBe(0);
    await daemon.killed(vm.id);
    await runTemplateBuildCleanup();
    expect(
      (await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: build.id } }))
        .cleanupState,
    ).toBe("DONE");
  });
});
