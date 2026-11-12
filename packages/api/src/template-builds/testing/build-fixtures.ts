import { randomUUID } from "node:crypto";
import type { Prisma } from "@wssp/db";
import type { PgTestDatabase } from "@wssp/db/testing/pg";
import { sessionPrincipal } from "../../sandbox/contracts";
import { recordCaptureResult } from "../../sandbox/image-store/capture-result";
import { finalizeCapture } from "../../sandbox/image-store/captures";
import { seedLaunchHost, seedTemplateRevision } from "../../sandbox/testing/resource-fixtures";
import { advanceTemplateBuild, runTemplateBuildCleanup } from "../orchestrator";

/**
 * Template-build pg fixtures (never used by application IO): an owner with
 * one connected builder host and a base template, plus a fake daemon that
 * completes operations the way the relay records host results.
 */
const BUILDER_IMAGE_FEATURES = {
  fetch: true,
  serve: true,
  publish: true,
  capture: true,
  build: true,
  acceptForeign: false,
  leaseFromReady: false,
  formats: ["unified"],
  captureStorageMarkers: [],
};

export async function buildOwnerFixture(db: PgTestDatabase) {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Builder",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "builder",
      label: "Builder",
      status: "CONNECTED",
      egressEnforcement: true,
      daemonLeasePolicy: true,
    },
  });
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: {
      daemonFeatures: { egressPolicy: true, terminal: true, image: BUILDER_IMAGE_FEATURES },
      imageCacheEpoch: host.connectionEpoch,
    },
  });
  const base = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const session = sessionPrincipal(id);
  return { id, host, base, session };
}

/** The relay's host-result writes, reduced to what the orchestrator reads. */
export function fakeDaemon(db: PgTestDatabase) {
  const inspect = db.inspect;
  const finish = (
    operationId: string,
    data: Partial<Prisma.SandboxOperationUncheckedUpdateInput> = {},
  ) =>
    inspect.sandboxOperation.update({
      where: { id: operationId },
      data: { state: "SUCCEEDED", completedAt: new Date(), ...data },
    });
  return {
    /** Create accepted and the guest is READY. */
    async ready(buildId: string) {
      const sandbox = await inspect.sandbox.findUniqueOrThrow({ where: { buildId } });
      const create = await inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
      });
      await finish(create.id);
      await inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
      return sandbox;
    },
    /** The latest command on the build VM exits with `exitCode`. */
    async command(operationId: string, exitCode: number, output?: string) {
      await finish(operationId, { result: { exitCode, pid: 1, outputBytes: output?.length ?? 0 } });
      if (output !== undefined) {
        const bytes = Buffer.from(output);
        // A complete stream: the header accounts for every committed byte, as
        // the relay's writer does (a cursor at the end stays valid on a re-read).
        const end = BigInt(bytes.byteLength);
        await inspect.sandboxCommandOutput.create({
          data: { id: operationId, attempt: 1, receivedEnd: end, totalBytes: end },
        });
        await inspect.sandboxCommandOutputSegment.create({
          data: {
            outputId: operationId,
            tail: false,
            startOffset: 0n,
            endOffset: end,
            bytes,
            stderrMask: Buffer.alloc(Math.ceil(bytes.byteLength / 8)),
          },
        });
      }
    },
    async succeed(operationId: string) {
      await finish(operationId);
    },
    async stopped(operationId: string, sandboxId: string) {
      await finish(operationId);
      await inspect.sandbox.update({ where: { id: sandboxId }, data: { state: "STOPPED" } });
    },
    /** The host's CAPTURED result for a capture operation. */
    async captured(operationId: string, hostId: string, epoch: number) {
      await inspect.$transaction((tx) =>
        recordCaptureResult(tx, {
          operationId,
          hostId,
          epoch,
          result: {
            fingerprint: `sha256:${"f".repeat(64)}`,
            sizeBytes: 1024,
            architecture: "x86_64",
          },
        }),
      );
    },
    /** A kill completes: the VM is gone. */
    async killed(sandboxId: string) {
      const kill = await inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "KILL_SANDBOX" },
        orderBy: { createdAt: "desc" },
      });
      await finish(kill.id);
      await inspect.sandbox.update({ where: { id: sandboxId }, data: { state: "DELETED" } });
      // The host settles every operation the kill superseded.
      await inspect.sandboxOperation.updateMany({
        where: { sandboxId, state: "CANCEL_REQUESTED" },
        data: { state: "CANCELLED", completedAt: new Date() },
      });
      return kill;
    },
  };
}

/** The build's current operation (create, PUT_FILE, step, lease, stop). */
export async function currentOperation(db: PgTestDatabase, buildId: string) {
  const build = await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: buildId } });
  if (!build.currentOperationId) return null;
  return db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: build.currentOperationId } });
}

/** Drive an accepted build to SUCCEEDED (fake daemon), returning its revision. */
export async function completeBuild(
  db: PgTestDatabase,
  daemon: ReturnType<typeof fakeDaemon>,
  owner: { id: string; host: { id: string; connectionEpoch: number } },
  buildId: string,
) {
  const row = () => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: buildId } });
  const advance = () => advanceTemplateBuild({ id: buildId, userId: owner.id });
  const fail = (what: string): never => {
    throw new Error(`completeBuild: expected ${what}`);
  };
  await advance(); // create
  const sandbox = await daemon.ready(buildId);
  await advance(); // READY → RUNNING, prelude claimed
  for (let op = await currentOperation(db, buildId); op?.kind === "RUN_COMMAND"; ) {
    await daemon.command(op.id, 0);
    await advance();
    op = await currentOperation(db, buildId);
  }
  if ((await row()).phase !== "lease") fail("the lease phase");
  await advance(); // lease re-anchor → stop
  const stop = await currentOperation(db, buildId);
  if (stop?.kind !== "STOP_SANDBOX") return fail("a STOP_SANDBOX");
  await daemon.stopped(stop.id, sandbox.id);
  await advance(); // capture claimed
  const capture = (await row()).captureOperationId ?? fail("a capture operation");
  await daemon.captured(capture, owner.host.id, owner.host.connectionEpoch);
  if ((await finalizeCapture(capture)).kind !== "finalized") fail("a finalized capture");
  const done = await row();
  if (done.state !== "SUCCEEDED") fail("SUCCEEDED");
  await runTemplateBuildCleanup(); // the cleanup invariant kills the build VM
  await daemon.killed(sandbox.id);
  return done.revisionId ?? fail("a revision");
}
