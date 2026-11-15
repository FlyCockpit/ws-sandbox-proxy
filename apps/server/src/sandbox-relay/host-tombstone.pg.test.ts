import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
// No sockets: the relay "sends" succeed; every durable transition is real SQL.
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
  },
}));

const db = await pgTestDatabase();
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { createSandbox, killSandbox, getSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
const { applyOperationResult } = await import("./operation-handlers.js");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

afterAll(() => db.close());

const FP = `sha256:${"c".repeat(64)}`;
const clock = () => new Date();

async function seedHost() {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  return { owner: { kind: "session" as const, ownerId }, hostId: host.id, templateId: template.id };
}

async function reportSucceeded(operationId: string, state: "ready" | "deleted") {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: op.sandboxId, payload: { path: ["operationId"], equals: op.id } },
  });
  const payload = event.payload as Record<string, unknown>;
  return applyOperationResult(
    {
      sender: { userId: op.userId, hostId: op.dispatchedHostId!, connectionEpoch: 1 },
      operationId: op.id,
      sandboxId: op.sandboxId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state: "succeeded",
      result: { state, lease: payload.lease },
    },
    clock,
  );
}

async function readySandbox(seed: Awaited<ReturnType<typeof seedHost>>) {
  const sandbox = await createSandbox(
    seed.owner,
    createSandboxInput.parse({
      template: "revision/" + seed.templateId,
      sandboxHostId: seed.hostId,
      idempotencyKey: `create-${randomUUID()}`,
    }),
  );
  await processSandboxOutboxBatch(clock);
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: {
      NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
      sandboxId: sandbox.id,
      kind: "CREATE_SANDBOX",
    },
  });
  expect(create.state).toBe("DISPATCHED");
  expect(await reportSucceeded(create.id, "ready")).toEqual({ written: true });
  return sandbox.id;
}

async function dispatchedKill(seed: Awaited<ReturnType<typeof seedHost>>, sandboxId: string) {
  await killSandbox(seed.owner, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
  await processSandboxOutboxBatch(clock);
  const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: {
      NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
      sandboxId,
      kind: "KILL_SANDBOX",
    },
  });
  expect(kill.state).toBe("DISPATCHED");
  return kill.id;
}

describe("C21-HOSTFINALIZE (real PostgreSQL): tombstoned host finalization", () => {
  it("the last placement release finalizes the host row in the same transaction as the DELETED detach", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    await expect(deleteHost(seed.owner, { id: seed.hostId })).resolves.toEqual({
      ok: true,
      pending: true,
    });
    const killId = await dispatchedKill(seed, sandboxId);

    // Fail the transaction at the host-row DELETE, after the release and the
    // detach already ran in it: everything must roll back together.
    const parked = db.pauseAt("relay", { before: "sandboxHost.deleteMany" });
    const failing = db.run("relay", () => reportSucceeded(killId, "deleted"));
    await parked.waitReached();
    parked.fail(new Error("injected failure at host finalization"));
    await expect(failing).rejects.toThrow("An internal error occurred.");
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toMatchObject({
      liveCount: 1,
    });
    expect(await db.inspect.sandbox.findUnique({ where: { id: sandboxId } })).toMatchObject({
      sandboxHostId: seed.hostId,
      liveResourcesHeld: true,
    });
    expect((await db.inspect.sandboxOperation.findUnique({ where: { id: killId } }))?.state).toBe(
      "DISPATCHED",
    );

    // The same result, uninterrupted: release, detach and host finalization commit as one.
    expect(await reportSucceeded(killId, "deleted")).toEqual({ written: true });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toBeNull();
    expect(await db.inspect.sandbox.findUnique({ where: { id: sandboxId } })).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(
      await db.inspect.sandboxTemplateRevision.findUnique({ where: { id: seed.templateId } }),
    ).toMatchObject({ retiredAt: null });
    expect(
      await db.inspect.sandboxTemplateAvailability.count({ where: { hostId: seed.hostId } }),
    ).toBe(0);
    expect((await db.inspect.sandboxOperation.findUnique({ where: { id: killId } }))?.state).toBe(
      "SUCCEEDED",
    );
  });

  it("C23 host finalization revokes a pending host-scoped read in the same commit", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    await deleteHost(seed.owner, { id: seed.hostId });
    const killId = await dispatchedKill(seed, sandboxId);
    const { authorityTicket } = await import("@wssp/db/authority");
    // Sampled where a host-scoped sandbox read is admitted (serviceReadTicket):
    // the host grant still stands.
    const pendingRead = authorityTicket({ ownerId: seed.owner.ownerId, hostId: seed.hostId });
    expect(pendingRead()).toBe(true);
    // The kill result's transaction detaches the sandbox and deletes the host.
    expect(await reportSucceeded(killId, "deleted")).toEqual({ written: true });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toBeNull();
    // The read paused across that commit now fails closed instead of
    // disclosing data authorized by the deleted grant.
    expect(pendingRead()).toBe(false);
  });

  it("C23 a read admitted between finalization and commit stays fenced (deferred path)", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    await deleteHost(seed.owner, { id: seed.hostId });
    const killId = await dispatchedKill(seed, sandboxId);
    const { authorityTicket } = await import("@wssp/db/authority");
    // Park after the finalizer's statements, before COMMIT: the host row and
    // its allowlist grants are still committed-visible to other transactions,
    // yet no read admitted in this window may validate a ticket against them.
    const parkedDelete = db.pauseAt("relay", { after: "sandboxHost.deleteMany" });
    const parkedCommit = db.pauseAt("relay", { before: "$transaction.commit" });
    const done = db.run("relay", () => reportSucceeded(killId, "deleted"));
    await parkedDelete.waitReached();
    parkedDelete.release();
    await parkedCommit.waitReached();
    // Vacuity guard: the deletion really is still uncommitted at this point.
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).not.toBeNull();
    // Finalization is complete but uncommitted. A statement-scoped authority
    // change (the old shape) would already validate a fresh ticket here.
    const gapTicket = authorityTicket({ ownerId: seed.owner.ownerId, hostId: seed.hostId });
    expect(gapTicket()).toBe(false);
    parkedCommit.release();
    await expect(done).resolves.toEqual({ written: true });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toBeNull();
    // Once the change is durable, a freshly sampled ticket validates again.
    expect(authorityTicket({ ownerId: seed.owner.ownerId, hostId: seed.hostId })()).toBe(true);
  });

  it("C23 explicit deleteHost finalization stays fenced through its own commit", async () => {
    // A bare host (no placements, no templates) finalizes inside deleteHost's
    // own transaction rather than a later relay transaction.
    const ownerId = `user-${randomUUID()}`;
    await db.inspect.user.create({
      data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
    });
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: ownerId,
        slug: "bare",
        label: "Bare",
        status: "CONNECTED",
        connectionEpoch: 1,
      },
    });
    const { authorityTicket } = await import("@wssp/db/authority");
    const parkedDelete = db.pauseAt("explicit", { after: "sandboxHost.deleteMany" });
    const parkedCommit = db.pauseAt("explicit", { before: "$transaction.commit" });
    const done = db.run("explicit", () =>
      deleteHost({ kind: "session", ownerId }, { id: host.id }),
    );
    await parkedDelete.waitReached();
    parkedDelete.release();
    await parkedCommit.waitReached();
    // Vacuity guard: the deletion really is still uncommitted at this point.
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: host.id } })).not.toBeNull();
    expect(authorityTicket({ ownerId, hostId: host.id })()).toBe(false);
    parkedCommit.release();
    await expect(done).resolves.toEqual({ ok: true, pending: false });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: host.id } })).toBeNull();
    expect(authorityTicket({ ownerId, hostId: host.id })()).toBe(true);
  });

  it("C23 an allowlisted getSandbox paused mid-authorization fails closed once the deletion commits", async () => {
    const seed = await seedHost();
    // A retained sandbox: deleted and detached, still readable through the
    // key's host grant (originHostId survives the detach).
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: seed.owner.ownerId,
        templateId: seed.templateId,
        originPoolId: null,
        state: "DELETED",
        originHostId: seed.hostId,
        sandboxHostId: seed.hostId,
      },
    });
    await db.inspect.sandbox.update({
      where: { id: sandbox.id },
      data: { sandboxHostId: null },
    });
    // The allowlisted reader uses its current host and revision grants; the host
    // deletion cascades that grant row away.
    const key = await db.inspect.sdkKey.create({
      data: {
        userId: seed.owner.ownerId,
        name: "reader",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        resourceMode: "ALLOWLIST",
        scopes: ["sandboxes:read"],
        HostAllowlist: { create: { sandboxHostId: seed.hostId } },
        RevisionAllowlist: { create: { templateRevisionId: seed.templateId } },
      },
    });
    const sdk = {
      kind: "sdkKey" as const,
      credentialKind: "API" as const,
      ownSandboxesOnly: false,
      keyId: key.id,
      ownerId: seed.owner.ownerId,
      expiresAt: null,
      resourceMode: "ALLOWLIST" as const,
      scopes: new Set(["sandboxes:read" as const]),
      allowedHostIds: new Set([seed.hostId]),
      allowedRevisionIds: new Set([seed.templateId]),
      allowedPoolIds: new Set<string>(),
    };
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
      data: { authorizingKeyId: key.id },
    });
    // The creating key can read this retained placement.
    expect(await getSandbox(sdk, { id: sandbox.id })).toMatchObject({ id: sandbox.id });

    // Park the second read right after authorization's host lookup found the
    // still-committed host row.
    const parkedRead = db.pauseAt("reader", { after: "sandboxOperation.findFirst" });
    const read = db.run("reader", () => getSandbox(sdk, { id: sandbox.id }));
    await parkedRead.waitReached();

    // The host deletion — and its allowlist cascade — commits while the reader
    // is parked inside authorization.
    await deleteHost(seed.owner, { id: seed.hostId });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toBeNull();

    parkedRead.release();
    // Authorization fences the host scope from before its host lookup to its
    // end check; without that fence this resumes against the post-deletion
    // revision and resolves 200 with metadata whose grant no longer exists.
    await expect(read).rejects.toMatchObject({ status: 403 });
  });

  it("a non-last placement release leaves the tombstoned host row in place", async () => {
    const seed = await seedHost();
    const first = await readySandbox(seed);
    await readySandbox(seed);
    await deleteHost(seed.owner, { id: seed.hostId });
    const killId = await dispatchedKill(seed, first);

    expect(await reportSucceeded(killId, "deleted")).toEqual({ written: true });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toMatchObject({
      liveCount: 1,
      deletionRequestedAt: expect.any(Date),
    });
  });
});

for (const table of ["host_token", "host_device_credential", "sdk_key_host_allowlist"] as const) {
  for (const order of ["child-first", "finalizer-first"] as const) {
    it(`3A finalizer ${table} ${order} explicitly prelocks sorted suffix`, async () => {
      const f = await seedHost();
      let childId: string;
      if (table === "host_token")
        childId = (
          await db.inspect.hostToken.create({
            data: {
              userId: f.owner.ownerId,
              sandboxHostId: f.hostId,
              name: "test",
              lookupPrefix: randomUUID(),
              secretDigest: randomUUID(),
            },
          })
        ).id;
      else if (table === "host_device_credential")
        childId = (
          await db.inspect.hostDeviceCredential.create({
            data: {
              userId: f.owner.ownerId,
              sandboxHostId: f.hostId,
              lookupPrefix: randomUUID(),
              secretDigest: randomUUID(),
            },
          })
        ).id;
      else {
        const key = await db.inspect.sdkKey.create({
          data: {
            userId: f.owner.ownerId,
            name: "test",
            lookupPrefix: randomUUID(),
            secretDigest: randomUUID(),
            scopes: ["hosts:read"],
          },
        });
        childId = (
          await db.inspect.sdkKeyHostAllowlist.create({
            data: { sdkKeyId: key.id, sandboxHostId: f.hostId },
          })
        ).id;
      }
      const child = () =>
        db.run("child", () =>
          db.prisma.$transaction(async (tx) => {
            if (table === "host_token")
              await tx.$queryRaw`SELECT id FROM host_token WHERE id = ${childId} FOR UPDATE`;
            else if (table === "host_device_credential")
              await tx.$queryRaw`SELECT id FROM host_device_credential WHERE id = ${childId} FOR UPDATE`;
            else
              await tx.$queryRaw`SELECT id FROM sdk_key_host_allowlist WHERE id = ${childId} FOR UPDATE`;
          }),
        );
      const heldChild = db.pauseAt("child", { before: "$transaction.commit" });
      const heldFinalizer = db.pauseAt("finalizer", { before: "sandboxHost.deleteMany" });
      let writing: Promise<unknown>;
      let deleting: ReturnType<typeof deleteHost>;
      if (order === "child-first") {
        writing = child();
        await heldChild.waitReached();
        deleting = db.run("finalizer", () => deleteHost(f.owner, { id: f.hostId }));
        try {
          const blocked = await db.waitUntilBlocked("finalizer", { by: "child" });
          expect(blocked.query).toContain(`FROM ${table}`);
          expect(blocked.query).toMatch(/ORDER BY id LIMIT 100 FOR UPDATE/);
        } finally {
          heldChild.release();
        }
        await writing;
        await heldFinalizer.waitReached();
        heldFinalizer.release();
      } else {
        deleting = db.run("finalizer", () => deleteHost(f.owner, { id: f.hostId }));
        await heldFinalizer.waitReached();
        writing = child();
        try {
          expect((await db.waitUntilBlocked("child", { by: "finalizer" })).query).toContain(table);
        } finally {
          heldFinalizer.release();
          heldChild.release();
        }
      }
      expect(await deleting).toEqual({ ok: true, pending: false });
      await writing;
      expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.hostId } })).toBeNull();
      if (table === "host_token")
        expect(
          (await db.inspect.hostToken.findUniqueOrThrow({ where: { id: childId } })).sandboxHostId,
        ).toBeNull();
      else if (table === "host_device_credential")
        expect(
          await db.inspect.hostDeviceCredential.findUnique({ where: { id: childId } }),
        ).toBeNull();
      else
        expect(
          await db.inspect.sdkKeyHostAllowlist.findUnique({ where: { id: childId } }),
        ).toBeNull();
    });
  }
}

it("3A finalizer prelocks credential history in keyset pages of 100", async () => {
  const f = await seedHost();
  await db.inspect.hostToken.createMany({
    data: Array.from({ length: 205 }, (_, i) => ({
      id: `history-${String(i).padStart(4, "0")}`,
      userId: f.owner.ownerId,
      sandboxHostId: f.hostId,
      name: "history",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
    })),
  });
  const page = db.pauseAt("finalizer", {
    after: /^sql:SELECT id FROM host_token.*ORDER BY id LIMIT 100 FOR UPDATE$/,
  });
  const deleting = db.run("finalizer", () => deleteHost(f.owner, { id: f.hostId }));
  await page.waitReached();
  // First page acquired ids 0..99, independent of trigger traversal order.
  const late = db.pauseAt("late-child", { before: "$transaction.commit" });
  const laterChild = db.run("late-child", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM host_token WHERE id = ${"history-0204"} FOR UPDATE`;
    }),
  );
  await late.waitReached();
  page.release();
  try {
    expect((await db.waitUntilBlocked("finalizer", { by: "late-child" })).query).toMatch(
      /LIMIT 100 FOR UPDATE/,
    );
  } finally {
    late.release();
  }
  await laterChild;
  expect(await deleting).toEqual({ ok: true, pending: false });
});
