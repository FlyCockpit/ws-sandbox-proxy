import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { z } from "zod";
import { helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "association-test-signing-key",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

import { createSandbox } from "../../../../packages/api/src/sandbox/services/sandboxes";
import {
  seedLaunchHost,
  seedMintSession,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { applyOperationResult } from "./operation-handlers.js";
import { parseDaemonControlFrame } from "./protocol.js";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "host", label: "Host", status: "CONNECTED", egressEnforcement: true },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await createSandbox(
    { kind: "session", ownerId: userId },
    { template: `revision/${revision.id}`, sandboxHostId: host.id, idempotencyKey: randomUUID() },
  );
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: operation.id },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: host.connectionEpoch,
    },
  });
  const proof = {
    templateRevisionId: revision.id,
    artifact: revision.incusFingerprint,
    architecture: revision.architecture,
    connectionEpoch: host.connectionEpoch,
  };
  const input = {
    sender: { userId, hostId: host.id, connectionEpoch: host.connectionEpoch },
    operationId: operation.id,
    sandboxId: sandbox.id,
    generation: sandbox.generation,
    attempt: 1,
    state: "failed" as const,
    error: { code: "not_found" as const, message: "Image missing." },
    result: { imageMissing: proof },
  };
  return { userId, host, revision, sandbox, operation, proof, input };
}
it.each(["exact", "artifact", "architecture", "revision", "epoch", "untyped"])(
  "3E image absence %s report only invalidates the exact fresh-create binding",
  async (variant) => {
    const f = await fixture();
    const proof = { ...f.proof };
    if (variant === "artifact") proof.artifact = `sha256:${"b".repeat(64)}`;
    if (variant === "architecture") proof.architecture = "aarch64";
    if (variant === "revision") proof.templateRevisionId = "hidden";
    if (variant === "epoch") proof.connectionEpoch += 1;
    expect(
      await applyOperationResult({
        ...f.input,
        result: variant === "untyped" ? {} : { imageMissing: proof },
      }),
    ).toEqual({ written: true });
    expect(
      await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
        where: { revisionId_hostId: { revisionId: f.revision.id, hostId: f.host.id } },
      }),
    ).toMatchObject({ status: variant === "exact" ? "MISSING" : "AVAILABLE" });
    if (variant === "exact")
      await expect(
        createSandbox(
          { kind: "session", ownerId: f.userId },
          {
            template: `revision/${f.revision.id}`,
            sandboxHostId: f.host.id,
            idempotencyKey: randomUUID(),
          },
        ),
      ).rejects.toMatchObject({
        code: "CONFLICT",
        data: { code: "sandbox.template_image_missing" },
      });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toMatchObject({
      state: "FAILED",
      errorCode: variant === "exact" ? "sandbox.template_image_missing" : "not_found",
      errorDetail:
        variant === "exact"
          ? "The exact template image is missing on this host."
          : "Resource not found.",
    });
    // E1-A-07: a proven image-missing create held a root it never made; the
    // failure releases it with the live hold (an unproven failure keeps it).
    // E2-A-05: holding nothing, the proven one ends DELETED and detached, the
    // same disposition as an ended capacity wait; the unproven stays ERROR.
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
    expect(sandbox).toMatchObject({
      state: variant === "exact" ? "DELETED" : "ERROR",
      lastErrorCode: variant === "exact" ? "sandbox.template_image_missing" : "not_found",
      liveResourcesHeld: false,
      diskReservationHeld: variant !== "exact",
      sandboxHostId: variant === "exact" ? null : f.host.id,
    });
    const pool = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
      where: { sandboxHostId: f.host.id },
    });
    expect(pool.diskReservedGiB).toBe(variant === "exact" ? 0 : sandbox.rootChargeGiB);
  },
);
it("3E availability invalidation and result settlement roll back together", async () => {
  const f = await fixture();
  const gate = db.pauseAt("result", { before: "sandboxTemplateAvailability.updateMany" });
  const result = db.run("result", () => applyOperationResult(f.input));
  await gate.waitReached();
  gate.fail(new Error("injected availability write failure"));
  await expect(result).rejects.toThrow("An internal error occurred.");
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
  ).toMatchObject({ state: "DISPATCHED" });
  expect(
    await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
      where: { revisionId_hostId: { revisionId: f.revision.id, hostId: f.host.id } },
    }),
  ).toMatchObject({ status: "AVAILABLE" });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(1);
  expect(await applyOperationResult(f.input)).toEqual({ written: true });
});
it("3E stale result epoch cannot settle or invalidate current availability", async () => {
  const f = await fixture();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: { increment: 1 } },
  });
  expect(await applyOperationResult(f.input)).toEqual({ written: false });
  expect(
    await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
      where: { revisionId_hostId: { revisionId: f.revision.id, hostId: f.host.id } },
    }),
  ).toMatchObject({ status: "AVAILABLE" });
});

it("3E exact readiness and stop evidence update only the current boot's timing", async () => {
  const f = await fixture();
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: f.sandbox.id },
  });
  const payload = event.payload as import("@wssp/db").Prisma.JsonObject;
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      error: undefined,
      result: { state: "ready", lease: payload.lease },
    }),
  ).toEqual({ written: true });
  const first = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id },
  });
  expect(first).toMatchObject({
    startedAt: expect.any(Date),
    readyAt: expect.any(Date),
    endedAt: null,
  });
  // Master already writes both instance and placement timing at this exact
  // READY result. Pin the instance writer and replay behavior explicitly.
  const ready = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
  expect(ready).toMatchObject({ startedAt: first.startedAt, readyAt: first.readyAt });
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      error: undefined,
      result: { state: "ready", lease: payload.lease },
    }),
  ).toEqual({ written: false });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).toMatchObject(
    {
      startedAt: ready.startedAt,
      readyAt: ready.readyAt,
    },
  );
  const { stopSandbox, reconnectSandbox } = await import(
    "../../../../packages/api/src/sandbox/services/sandboxes"
  );
  const receipt = await stopSandbox(
    { kind: "session", ownerId: f.userId },
    { id: f.sandbox.id, idempotencyKey: randomUUID() },
  );
  const stopping = await db.inspect.sandboxOperation.update({
    where: { id: receipt.operationId },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: f.host.connectionEpoch,
    },
  });
  const result = {
    sender: f.input.sender,
    operationId: stopping.id,
    sandboxId: f.sandbox.id,
    generation: stopping.generation,
    attempt: 1,
    state: "succeeded" as const,
    result: { state: "stopped" },
  };
  expect(await applyOperationResult(result)).toEqual({ written: true });
  const ended = await db.inspect.sandboxPlacement.findUniqueOrThrow({ where: { id: first.id } });
  expect(ended).toMatchObject({ endedAt: expect.any(Date), endReason: "stopped" });
  expect(await applyOperationResult(result)).toEqual({ written: false });
  expect(
    (await db.inspect.sandboxPlacement.findUniqueOrThrow({ where: { id: first.id } })).endedAt,
  ).toEqual(ended.endedAt);
  await reconnectSandbox(
    { kind: "session", ownerId: f.userId },
    { id: f.sandbox.id, mode: "cold", idempotencyKey: randomUUID() },
  );
  const current = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: f.sandbox.id },
    include: { CurrentPlacement: true },
  });
  expect(current).toMatchObject({ startedAt: null, readyAt: null });
  expect(current.CurrentPlacement).toMatchObject({
    startedAt: null,
    readyAt: null,
    endedAt: null,
    templateRevisionId: f.revision.id,
  });
  expect(current.currentPlacementId).not.toBe(first.id);
});

it("3E result locks S/current placement before acquiring operation rows", async () => {
  const f = await fixture();
  const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id },
  });
  const held = db.pauseAt("placement-holder", { before: "$transaction.commit" });
  const holder = db.run("placement-holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_placement WHERE id = ${placement.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const result = db.run("result", () => applyOperationResult(f.input));
  try {
    expect((await db.waitUntilBlocked("result", { by: "placement-holder" })).query).toContain(
      "sandbox_placement",
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.operation.id} FOR UPDATE NOWAIT`;
    });
  } finally {
    held.release();
  }
  await holder;
  expect(await result).toEqual({ written: true });
});

it("Incus JSON and CLI image absence traverses the real daemon and settles only the exact revision availability", async () => {
  const dir = await mkdtemp(join(tmpdir(), "wssp-incus-result-pg-"));
  const modes = ["json", "cli", "denied", "unknown"] as const;
  const fixtures = new Map<string, Awaited<ReturnType<typeof fixture>>>();
  const dispatches: Record<string, unknown> = {};
  try {
    for (const mode of modes) {
      const f = await fixture();
      fixtures.set(mode, f);
      // Same owner/host, different revision: it must survive the missing proof.
      await seedTemplateRevision(db.inspect, {
        data: {
          userId: f.userId,
          sandboxHostId: f.host.id,
          slug: "other",
          label: "Other",
          incusFingerprint: f.revision.incusFingerprint,
        },
      });
      const other = await seedLaunchHost(db.inspect, {
        data: {
          userId: f.userId,
          slug: "other",
          label: "Other",
          status: "CONNECTED",
          egressEnforcement: true,
        },
      });
      // Same exact revision, different host: it must survive too.
      await db.inspect.sandboxTemplateAvailability.create({
        data: {
          hostOwnerId: f.userId,
          userId: f.userId,
          revisionId: f.revision.id,
          hostId: other.id,
          status: "AVAILABLE",
          verifiedConnectionEpoch: other.connectionEpoch,
          localFingerprint: f.revision.incusFingerprint,
          architecture: f.revision.architecture,
          manifestDigest: f.revision.manifestDigest,
        },
      });
      const event = await db.inspect.outboxEvent.findFirstOrThrow({
        where: { aggregateId: f.sandbox.id },
      });
      const payload = event.payload as import("@wssp/db").Prisma.JsonObject;
      // The outbox processor projects these public launch fields onto the wire.
      dispatches[mode] = {
        sandboxOwnerId: f.userId,
        operationId: f.operation.id,
        sandboxId: f.sandbox.id,
        idempotencyKey: f.operation.idempotencyKey,
        kind: "sandbox.create",
        generation: f.sandbox.generation,
        attempt: 1,
        templateRevisionId: payload.templateRevisionId,
        verificationConnectionEpoch: f.host.connectionEpoch,
        templateDigest: payload.templateDigest,
        incusFingerprint: payload.incusFingerprint,
        architecture: payload.architecture,
        guestUid: payload.guestUid,
        guestGid: payload.guestGid,
        guestHome: payload.guestHome,
        guestShell: payload.guestShell,
        incusName: payload.incusName,
        lease: payload.lease,
        egressPolicy: payload.egressPolicy,
        egressPolicyHash: payload.egressPolicyHash,
      };
    }
    const path = join(dir, "dispatch.json");
    await writeFile(path, JSON.stringify(dispatches));
    const output = await promisify(execFile)(
      "cargo",
      [
        "test",
        "-p",
        "wssp",
        "--lib",
        "--locked",
        "sandbox_relay::supervisor::revision_image_tests::incus_exact_image_missing_pipeline",
        "--",
        "--exact",
      ],
      {
        cwd: resolve(import.meta.dirname, "../../../.."),
        env: { ...process.env, WSSP_TEST_IMAGE_DISPATCH: path },
        timeout: 300_000,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    expect(output.stdout).toContain("1 passed");
    const results = z
      .array(
        z.object({
          mode: z.enum(modes),
          availability: z.enum(["missing", "rejected"]),
          frame: z.unknown(),
        }),
      )
      .parse(JSON.parse(await readFile(join(dir, "dispatch.results.json"), "utf8")));
    expect(results).toHaveLength(4);
    for (const { mode, availability, frame } of results) {
      const f = fixtures.get(mode)!;
      const message = parseDaemonControlFrame(JSON.stringify(frame));
      if (message.type !== "operation.result") throw new Error("expected operation result");
      const missing = mode === "json" || mode === "cli";
      expect(availability).toBe(missing ? "missing" : "rejected");
      expect(await applyOperationResult({ ...message, sender: f.input.sender })).toEqual({
        written: true,
      });
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
      ).toMatchObject({
        state: "FAILED",
        errorCode: missing
          ? "sandbox.template_image_missing"
          : mode === "denied"
            ? "access_denied"
            : "internal",
      });
      const rows = await db.inspect.sandboxTemplateAvailability.findMany({
        where: { userId: f.userId },
        take: 10,
      });
      expect(rows).toHaveLength(3);
      for (const row of rows) {
        expect(row.status).toBe(
          missing && row.revisionId === f.revision.id && row.hostId === f.host.id
            ? "MISSING"
            : "AVAILABLE",
        );
      }
      if (missing) {
        // Deliver the real Rust adapter's error on the image-verification wire.
        // The production session manager must produce the association verdict.
        const { bindHostImageVerifier } = await import(
          "../../../../packages/api/src/sandbox/host-image-verifier"
        );
        const { associateTemplateAvailability } = await import(
          "../../../../packages/api/src/sandbox/services/templates"
        );
        const target = rows.find((row) => row.hostId !== f.host.id)!;
        const { SandboxRelaySessionManager } = await import("./session-manager.js");
        const { createHostToken } = await import(
          "../../../../packages/api/src/sandbox/services/hosts"
        );
        const token = await createHostToken(
          await seedMintSession(db.inspect, { kind: "session" as const, ownerId: f.userId }),
          { hostId: target.hostId, name: "association-daemon" },
        );
        const manager = new SandboxRelaySessionManager();
        const socket = {
          readyState: 1,
          bufferedAmount: 0,
          send(data: string | ArrayBuffer | Uint8Array) {
            if (typeof data !== "string") return;
            const request = JSON.parse(data);
            if (request.type === "image.verify.request") {
              manager.handleTextFrame(
                socket,
                JSON.stringify({
                  type: "image.verify.result",
                  requestId: request.requestId,
                  error: message.error,
                }),
              );
            }
          },
          close() {
            this.readyState = 3;
          },
        };
        manager.acceptAuthenticatedSocket({
          socket,
          identity: {
            hostId: target.hostId,
            userId: f.userId,
            tokenId: token.token.id,
            credentialKind: "hostToken",
            expiresAt: null,
          },
        });
        manager.handleTextFrame(socket, JSON.stringify(helloFixture(target.hostId, false)));
        await manager.drain(socket);
        manager.handleTextFrame(
          socket,
          JSON.stringify({ type: "sandbox.inventory", page: 0, complete: true, entries: [] }),
        );
        manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
        await manager.drain(socket);
        bindHostImageVerifier((input) => manager.verifyHostImage(input));
        try {
          await expect(
            associateTemplateAvailability(
              { kind: "session", ownerId: f.userId },
              {
                templateId: f.revision.templateId,
                revisionId: f.revision.id,
                hostId: target.hostId,
              },
            ),
          ).rejects.toMatchObject({ data: { code: "sandbox.template_image_missing" } });
          expect(
            await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
              where: { id: target.id },
            }),
          ).toMatchObject({ status: "MISSING" });
        } finally {
          bindHostImageVerifier(null);
          await manager.dispose();
        }
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 300_000);

it.each(["readiness", "unknown"] as const)(
  "%s outcome never invalidates availability even with an image proof",
  async (kind) => {
    const f = await fixture();
    await applyOperationResult({
      ...f.input,
      ...(kind === "readiness"
        ? { error: { code: "guest_unavailable" as const, message: "Readiness failed." } }
        : { state: "unknown_outcome" as const }),
    });
    expect(
      await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
        where: { revisionId_hostId: { revisionId: f.revision.id, hostId: f.host.id } },
      }),
    ).toMatchObject({ status: "AVAILABLE" });
  },
);

it("retired revisions block fresh creates while existing instance operations keep their pinned disk identity", async () => {
  const f = await fixture();
  const owner = { kind: "session" as const, ownerId: f.userId };
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: f.sandbox.id },
  });
  const payload = event.payload as import("@wssp/db").Prisma.JsonObject;
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      error: undefined,
      result: { state: "ready", lease: payload.lease },
    }),
  ).toEqual({ written: true });
  const { retireTemplateRevision } = await import(
    "../../../../packages/api/src/sandbox/services/templates"
  );
  await retireTemplateRevision(owner, { id: f.revision.id });
  await expect(
    createSandbox(owner, {
      template: `revision/${f.revision.id}`,
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  const { runCommand, readFile, setSandboxTimeout, stopSandbox, reconnectSandbox } = await import(
    "../../../../packages/api/src/sandbox/services/sandboxes"
  );
  const target = () => ({ id: f.sandbox.id, idempotencyKey: randomUUID() });
  const commands = await runCommand(owner, { ...target(), argv: ["true"], timeoutMs: 30000 });
  const file = await readFile(owner, { ...target(), path: "/tmp/example" });
  const leaseKey = randomUUID();
  await setSandboxTimeout(owner, { id: f.sandbox.id, idempotencyKey: leaseKey, timeoutMs: 300000 });
  const lease = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id, idempotencyKey: leaseKey },
  });
  const stop = await stopSandbox(owner, target());
  const stopping = await db.inspect.sandboxOperation.update({
    where: { id: stop.operationId },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: f.host.connectionEpoch,
    },
  });
  expect(
    await applyOperationResult({
      sender: f.input.sender,
      operationId: stopping.id,
      sandboxId: f.sandbox.id,
      generation: stopping.generation,
      attempt: 1,
      state: "succeeded",
      result: { state: "stopped" },
    }),
  ).toEqual({ written: true });
  const reconnect = await reconnectSandbox(owner, { ...target(), mode: "cold" });
  for (const operation of [commands, file, { operationId: lease.id }, stop, reconnect]) {
    const outbox = await db.inspect.outboxEvent.findFirstOrThrow({
      where: {
        aggregateId: f.sandbox.id,
        payload: { path: ["operationId"], equals: operation.operationId },
      },
    });
    expect(outbox.payload).toMatchObject({
      templateDigest: f.revision.incusFingerprint,
      architecture: f.revision.architecture,
    });
  }
});

it.each([
  ["unknown_outcome", "timeout", false],
  ["unknown_outcome", "internal", false],
  ["unknown_outcome", "unknown_outcome", false],
  ["unknown_outcome", "disconnected", false],
  ["failed", "egress_resolution_failed", false],
  ["failed", "timeout", false],
  ["failed", "timeout", true],
  ["unknown_outcome", "unknown_outcome", true],
] as const)(
  "qualification: create %s/%s (expired stop lease: %s) transfers holds to durable teardown and releases only on absence",
  async (state, code, expiredStop) => {
    const f = await fixture();
    if (expiredStop) {
      await db.inspect.sandbox.update({
        where: { id: f.sandbox.id },
        data: { leaseExpiresAt: new Date(Date.now() - 1000), leaseExpireAction: "STOP" },
      });
    }
    await applyOperationResult({
      ...f.input,
      state,
      error: { code, message: "Unconfirmed create." },
    });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
    expect(sandbox).toMatchObject({
      state: "STOPPING",
      generation: f.sandbox.generation + 1,
      liveResourcesHeld: true,
      diskReservationHeld: true,
    });
    const pool = await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
      where: { id: sandbox.storagePoolId ?? "missing" },
    });
    expect(pool.diskReservedGiB).toBeGreaterThan(0);
    expect(pool.diskReservedGiB).toBe(sandbox.rootChargeGiB);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
    ).toMatchObject({ state: "FAILED", errorCode: code });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX", generation: sandbox.generation },
    });
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: sandbox.id, payload: { path: ["operationId"], equals: kill.id } },
      }),
    ).toBe(1);
    await db.inspect.sandboxOperation.update({
      where: { id: kill.id },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: f.host.connectionEpoch,
      },
    });
    await applyOperationResult({
      sender: f.input.sender,
      operationId: kill.id,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
      attempt: 1,
      state: "succeeded",
      result: { state: "deleted" },
    });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).toMatchObject(
      { state: "DELETED", liveResourcesHeld: false, diskReservationHeld: false },
    );
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 });
    expect(
      await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: pool.id } }),
    ).toMatchObject({ diskReservedGiB: 0 });
    // Replayed proof cannot release either ledger twice.
    expect(
      await applyOperationResult({
        sender: f.input.sender,
        operationId: kill.id,
        sandboxId: sandbox.id,
        generation: sandbox.generation,
        attempt: 1,
        state: "succeeded",
        result: { state: "deleted" },
      }),
    ).toEqual({ written: false });
    expect(
      await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: pool.id } }),
    ).toMatchObject({ diskReservedGiB: 0 });
  },
);

it("qualification: create timeout result and cleanup enqueue roll back together", async () => {
  const f = await fixture();
  const gate = db.pauseAt("timeout-result", { before: "outboxEvent.create" });
  const result = db
    .run("timeout-result", () =>
      applyOperationResult({
        ...f.input,
        state: "unknown_outcome",
        error: { code: "timeout", message: "Unconfirmed create." },
      }),
    )
    .catch((error: unknown) => error);
  await gate.waitReached();
  gate.fail(new Error("injected cleanup enqueue failure"));
  expect(await result).toBeInstanceOf(Error);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
  ).toMatchObject({ state: "DISPATCHED" });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).toMatchObject(
    {
      state: f.sandbox.state,
      generation: f.sandbox.generation,
      liveResourcesHeld: true,
      diskReservationHeld: true,
    },
  );
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
    }),
  ).toBe(0);
});
