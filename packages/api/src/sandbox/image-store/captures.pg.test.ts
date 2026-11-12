vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "captures-fixture",
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
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { toOperationDto } from "../sdk-reads";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../testing/resource-fixtures";
import {
  captureHold,
  captureSandbox,
  finalizeCapture,
  recordCaptureResult,
  sweepCaptures,
} from "./captures";

const db = await pgTestDatabase();
afterAll(() => db.close());

const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: false,
    leaseFromReady: true,
    captureStorageMarkers: [],
  },
};

async function fixture() {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: { id: ownerId, name: "O", email: `${ownerId}@example.test`, twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "cap",
      label: "cap",
      status: "CONNECTED",
      egressEnforcement: true,
      daemonFeatures: FEATURES,
      imageCacheEpoch: 1,
      imageCacheCapBytes: 1n << 34n,
      imageCacheUsedBytes: 0n,
      imageCacheForeignBytes: 0n,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"1".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "STOPPED",
      // Smaller than the base revision's 32 GiB default (E1-A-04).
      diskGiB: 16,
    },
  });
  await db.inspect.sandboxTemplate.update({
    where: { id: revision.templateId },
    data: { captureKeep: 1 },
  });
  const owner = { kind: "session" as const, ownerId };
  const counters = async () => {
    const h = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
    const p = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
      where: { sandboxHostId: host.id },
    });
    return { memory: h.memoryReservedMiB, vcpu: h.vcpuReserved, disk: p.diskReservedGiB };
  };
  return { ownerId, owner, host, revision, sandbox, counters };
}

const fp = (n: number) => `sha256:${String(n).padStart(64, "0")}`;

async function capture(f: Awaited<ReturnType<typeof fixture>>, tag = "nightly") {
  const { operationId } = await captureSandbox(f.owner, {
    id: f.sandbox.id,
    idempotencyKey: randomUUID(),
    tag,
  });
  return operationId;
}

async function hostResult(f: Awaited<ReturnType<typeof fixture>>, operationId: string, n: number) {
  return db.inspect.$transaction((tx) =>
    recordCaptureResult(tx, {
      operationId,
      hostId: f.host.id,
      epoch: 1,
      result: { fingerprint: fp(n), sizeBytes: 4096, architecture: "x86_64" },
    }),
  );
}

describe("capture lifecycle against real PostgreSQL", () => {
  it("acceptance → host result → finalizer: revision, availability, artifact, tag, retention, hold released exactly once", async () => {
    const f = await fixture();
    const before = await f.counters();
    const hold = captureHold(f.sandbox.diskGiB);
    const first = await capture(f);
    expect(await f.counters()).toEqual({
      memory: before.memory + hold.memoryMiB,
      vcpu: before.vcpu + hold.vcpu,
      disk: before.disk + hold.diskGiB,
    });
    const row = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId: first },
    });
    expect(row).toMatchObject({ state: "PENDING", resourcesHeld: true, stoppedCapture: true });
    // A second capture of the same sandbox (or host) is busy.
    await expect(capture(f)).rejects.toMatchObject({ data: { code: "sandbox.capture_busy" } });
    // Reconnect is refused while the stopped root is being copied (M2).
    expect(await finalizeCapture(first)).toEqual({ kind: "waiting" });

    // The outbox dispatched it and the host accepted it before the result.
    await db.inspect.sandboxOperation.update({ where: { id: first }, data: { state: "ACCEPTED" } });
    expect(await hostResult(f, first, 1)).toBe(true);
    const running = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: first } });
    expect(running).toMatchObject({ state: "RUNNING", progressPhase: "finalizing" });
    // OD-1: the source could reach guest root, so the revision is tainted.
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { guestRoot: true } });
    const outcome = await finalizeCapture(first);
    expect(outcome.kind).toBe("finalized");
    const revisionId = outcome.kind === "finalized" ? outcome.revisionId : "";
    const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(revision).toMatchObject({
      sourceKind: "CAPTURE",
      parentRevisionId: f.revision.id,
      capturedFromSandboxId: f.sandbox.id,
      captureTag: "nightly",
      incusFingerprint: fp(1),
      revision: 2,
      // The image is the captured VM's 16 GiB root, not the parent's default.
      diskGiB: 16,
      capturedWithGuestRoot: true,
      builtWithWsspRecipe: false,
    });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
        where: { revisionId, hostId: f.host.id },
      }),
    ).toMatchObject({ status: "AVAILABLE", verifiedConnectionEpoch: 1, sizeBytes: 4096n });
    expect(
      await db.inspect.sandboxImageArtifact.findFirstOrThrow({
        where: { userId: f.ownerId, fingerprint: fp(1) },
      }),
    ).toMatchObject({ storeKind: "PEER", state: "LOCAL" });
    expect(
      await db.inspect.sandboxTemplateTag.findFirstOrThrow({
        where: { templateId: f.revision.templateId, tag: "nightly" },
      }),
    ).toMatchObject({ revisionId });
    const done = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: first },
      include: { Capture: { select: { revisionId: true } } },
    });
    expect(done.state).toBe("SUCCEEDED");
    expect(toOperationDto(done).capturedRevisionId).toBe(revisionId);
    expect(await f.counters()).toEqual(before);
    // Finalizing again changes nothing: the hold is released exactly once.
    expect(await finalizeCapture(first)).toEqual({ kind: "skipped" });
    expect(await f.counters()).toEqual(before);

    // A second capture under the same tag retires the first (captureKeep 1).
    const second = await capture(f);
    await hostResult(f, second, 2);
    const next = await finalizeCapture(second);
    expect(next.kind).toBe("finalized");
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }),
    ).toMatchObject({ retiredReason: "retention" });
    expect(await f.counters()).toEqual(before);
  });

  it("a finalizer failure (template archived) fails the capture, releases the hold and reports the fingerprint for image.release", async () => {
    const f = await fixture();
    const before = await f.counters();
    const op = await capture(f);
    await hostResult(f, op, 3);
    await db.inspect.sandboxTemplate.update({
      where: { id: f.revision.templateId },
      data: { archivedAt: new Date() },
    });
    const outcomes = await sweepCaptures();
    expect(outcomes.find((o) => o.operationId === op)?.outcome).toEqual({
      kind: "failed",
      fingerprint: fp(3),
      hostId: f.host.id,
      ownerId: f.ownerId,
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op } }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_failed" });
    expect(await f.counters()).toEqual(before);
  });

  it("a host that fails the capture before a result releases the hold once", async () => {
    const f = await fixture();
    const before = await f.counters();
    const op = await capture(f);
    await db.inspect.sandboxOperation.update({
      where: { id: op },
      data: { state: "FAILED", errorCode: "capture_failed" },
    });
    expect(await finalizeCapture(op)).toEqual({
      kind: "failed",
      fingerprint: null,
      hostId: f.host.id,
      ownerId: f.ownerId,
    });
    expect(await finalizeCapture(op)).toEqual({ kind: "skipped" });
    expect(await f.counters()).toEqual(before);
  });
});
