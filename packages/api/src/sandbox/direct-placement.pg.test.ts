import { seedMintSession } from "./testing/resource-fixtures";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "direct-placement-fixture",
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
import { afterAll, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { loadExecutionConfig } from "./execution-config";
import { bindHostImageVerifier, HostImageMissing } from "./host-image-verifier";
import { writeRevisionDefaults } from "./revision-config";
import { createSandbox, reconnectSandbox } from "./services/sandboxes";
import { createSdkKey } from "./services/sdk-keys";
import { associateTemplateAvailability } from "./services/templates";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      egressEnforcement: true,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: id });
  const input = { template: "base", sandboxHostId: host.id, idempotencyKey: randomUUID() };
  return { id, owner, host, revision, input };
}
it.each([
  "sandbox.create",
  "sandboxHost.updateMany",
  "sandboxExecutionConfig.create",
  "sandboxOperation.create",
  "sandboxPlacement.create",
  "outboxEvent.create",
  "sandbox.update",
])(
  "3E rollback insert S → reserve → config/O/placement/outbox/pointer after %s is atomic",
  async (step) => {
    const f = await fixture();
    const gate = db.pauseAt("create", { after: step });
    const create = db.run("create", () => createSandbox(f.owner, f.input));
    const outcome = create.then(
      () => null,
      (error: unknown) => error,
    );
    await gate.waitReached();
    gate.fail(new Error("injected write refusal"));
    expect(await outcome).not.toBeNull();
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxOperation.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxExecutionConfig.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxPlacement.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  },
);
it("3E create snapshots template < sandbox defaults and pins exact revision/config/operation in one transaction", async () => {
  const f = await fixture();
  await db.inspect.sandboxRevisionConfig.deleteMany({ where: { revisionId: f.revision.id } });
  await writeRevisionDefaults(db.inspect, f.id, f.revision.id, {
    APP: "template-secret",
    TEMPLATE_ONLY: "template-value",
  });
  const result = await createSandbox(f.owner, { ...f.input, envs: { APP: "sandbox-secret" } });
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: result.id },
    include: { CurrentPlacement: true, ExecutionConfig: true },
  });
  expect(sandbox).toMatchObject({
    templateId: f.revision.templateId,
    templateRevisionId: f.revision.id,
    originalSelector: "base",
    originPoolId: null,
    liveResourcesHeld: true,
  });
  expect(sandbox.CurrentPlacement).toMatchObject({
    sandboxId: sandbox.id,
    userId: f.id,
    templateRevisionId: f.revision.id,
    configId: sandbox.ExecutionConfig!.id,
  });
  const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: sandbox.CurrentPlacement!.operationId },
  });
  expect(operation).toMatchObject({ sandboxId: sandbox.id, kind: "CREATE_SANDBOX" });
  expect((await loadExecutionConfig(db.inspect, sandbox.id, f.id))!.env).toEqual([
    ["APP", "sandbox-secret"],
    ["TEMPLATE_ONLY", "template-value"],
  ]);
  const outbox = await db.inspect.outboxEvent.findFirstOrThrow({ where: { userId: f.id } });
  expect(JSON.stringify([result, outbox.payload])).not.toMatch(
    /template-secret|sandbox-secret|template-value/,
  );
  await db.inspect.sandboxTemplateTag.deleteMany({ where: { templateId: f.revision.templateId } });
  expect((await createSandbox(f.owner, { ...f.input, envs: { APP: "sandbox-secret" } })).id).toBe(
    sandbox.id,
  );
});
it("3E tag/retirement/availability and admission evidence all refuse before allocation", async () => {
  for (const field of [
    "availability",
    "availability-epoch",
    "epoch",
    "inventory",
    "heartbeat",
    "retired",
    "tag",
  ] as const) {
    const f = await fixture();
    if (field === "availability")
      await db.inspect.sandboxTemplateAvailability.updateMany({
        where: { revisionId: f.revision.id },
        data: { status: "MISSING" },
      });
    if (field === "availability-epoch")
      await db.inspect.sandboxTemplateAvailability.updateMany({
        where: { revisionId: f.revision.id },
        data: { verifiedConnectionEpoch: 0 },
      });
    if (field === "epoch")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { admissionEpoch: 0 },
      });
    if (field === "inventory")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { inventoryAcknowledgedEpoch: null },
      });
    if (field === "heartbeat")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { lastHeartbeatAt: new Date(0) },
      });
    if (field === "retired")
      await db.inspect.sandboxTemplateRevision.update({
        where: { id: f.revision.id },
        data: { retiredAt: new Date() },
      });
    if (field === "tag")
      await db.inspect.sandboxTemplateTag.deleteMany({
        where: { templateId: f.revision.templateId },
      });
    await expect(createSandbox(f.owner, f.input)).rejects.toBeDefined();
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  }
});
it("3E original-disk cold reconnect ignores missing cached image availability", async () => {
  const f = await fixture();
  const created = await createSandbox(f.owner, f.input);
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: created.id },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { userId: f.id },
    data: { processedAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { state: "STOPPED", liveResourcesHeld: false },
  });
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { liveCount: 0 } });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: f.revision.id },
    data: { status: "MISSING" },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  const result = await reconnectSandbox(f.owner, {
    id: created.id,
    mode: "cold",
    idempotencyKey: randomUUID(),
  });
  expect(result.operationId).toBeTruthy();
  expect(
    (
      await db.inspect.sandboxPlacement.findMany({
        where: { sandboxId: created.id },
        orderBy: { generation: "asc" },
        take: 3,
      })
    ).map((p) => p.templateRevisionId),
  ).toEqual([f.revision.id, f.revision.id]);
});

it.each(["create", "reconnect"] as const)(
  "3E explicit-host last slot and original-disk cold reconnect contend on H with %s holding its reservation",
  async (winner) => {
    const f = await fixture();
    const first = await createSandbox(f.owner, f.input);
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: first.id },
      data: { state: "SUCCEEDED" },
    });
    await db.inspect.outboxEvent.updateMany({
      where: { aggregateId: first.id },
      data: { processedAt: new Date() },
    });
    await db.inspect.sandbox.update({
      where: { id: first.id },
      data: { state: "STOPPED", liveResourcesHeld: false },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        liveCount: 0,
        memoryReservedMiB: 0,
        vcpuReserved: 0,
        daemonMemoryBudgetMiB: 1536,
      },
    });
    const create = () => createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    const reconnect = () =>
      reconnectSandbox(f.owner, { id: first.id, mode: "cold", idempotencyKey: randomUUID() });
    // The winner has incremented its reservation and still owns H. Prove the
    // other transaction actually waits for that host before either can commit.
    const gate = db.pauseAt("winner", { after: "sandboxHost.updateMany" });
    const leading = db.run("winner", winner === "create" ? create : reconnect);
    await gate.waitReached();
    const trailing = db.run("contender", winner === "create" ? reconnect : create);
    const settled = Promise.allSettled([leading, trailing]);
    try {
      expect((await db.waitUntilBlocked("contender", { by: "winner" })).query).toMatch(
        /\bFROM\s+"?sandbox_host"?[\s\S]*\bFOR\s+(?:NO KEY\s+)?UPDATE\b/i,
      );
    } finally {
      gate.release();
    }
    const outcomes = await settled;
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(1);
    expect(
      await db.inspect.sandbox.count({ where: { userId: f.id, liveResourcesHeld: true } }),
    ).toBe(1);
  },
);

it("3E new owner relationships and current pointer enforce composite identity in PostgreSQL", async () => {
  const a = await fixture();
  const b = await fixture();
  const one = await createSandbox(a.owner, a.input);
  const two = await createSandbox(b.owner, b.input);
  const p1 = await db.inspect.sandboxPlacement.findFirstOrThrow({ where: { sandboxId: one.id } });
  const p2 = await db.inspect.sandboxPlacement.findFirstOrThrow({ where: { sandboxId: two.id } });
  await db.inspect.sandbox.update({ where: { id: two.id }, data: { currentPlacementId: null } });
  await expect(
    db.inspect.sandbox.update({ where: { id: one.id }, data: { currentPlacementId: p2.id } }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandboxPlacement.update({ where: { id: p1.id }, data: { configId: p2.configId } }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandboxExecutionConfig.update({
      where: { id: p1.configId },
      data: { userId: b.id },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandboxTemplateAvailability.create({
      data: {
        hostOwnerId: a.id,
        userId: a.id,
        revisionId: a.revision.id,
        hostId: b.host.id,
        localFingerprint: a.revision.incusFingerprint,
        architecture: a.revision.architecture,
        manifestDigest: a.revision.manifestDigest,
        status: "PENDING",
      },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await db.inspect.sandboxHost.update({
    where: { id: a.host.id },
    data: {},
  });
  const sameOwner = await createSandbox(a.owner, { ...a.input, idempotencyKey: randomUUID() });
  const samePlacement = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: sameOwner.id },
  });
  await db.inspect.sandbox.update({
    where: { id: sameOwner.id },
    data: { currentPlacementId: null },
  });
  await expect(
    db.inspect.sandbox.update({
      where: { id: one.id },
      data: { currentPlacementId: samePlacement.id },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandboxPlacement.update({
      where: { id: p1.id },
      data: { configId: samePlacement.configId },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
});
it("3E create holds placement serialization through tag movement; replay never resolves the moved tag", async () => {
  const f = await fixture();
  const { setTemplateTag } = await import("./services/templates");
  const {
    id: _id,
    createdAt: _createdAt,
    ...source
  } = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: f.revision.id } });
  const newer = await db.inspect.sandboxTemplateRevision.create({
    data: { ...source, revision: 2, incusFingerprint: `sha256:${"b".repeat(64)}` },
  });
  await writeRevisionDefaults(db.inspect, f.id, newer.id, {});
  const gate = db.pauseAt("create", { after: "sandbox.create" });
  const creating = db.run("create", () => createSandbox(f.owner, f.input));
  await gate.waitReached();
  const moving = db.run("tag", () =>
    setTemplateTag(f.owner, {
      templateId: f.revision.templateId,
      revisionId: newer.id,
      tag: "latest",
    }),
  );
  expect((await db.waitUntilBlocked("tag", { by: "create" })).query).toContain(
    "pg_advisory_xact_lock",
  );
  gate.release();
  const sandbox = await creating;
  await moving;
  expect(sandbox.templateRevisionId).toBe(f.revision.id);
  expect((await createSandbox(f.owner, f.input)).id).toBe(sandbox.id);
  expect(
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).templateRevisionId,
  ).toBe(f.revision.id);
});
it("3E retirement committed before allocation refuses without tentative rows", async () => {
  const f = await fixture();
  const { retireTemplateRevision } = await import("./services/templates");
  const gate = db.pauseAt("retire", { after: "sandboxTemplateRevision.update" });
  const retiring = db.run("retire", () => retireTemplateRevision(f.owner, { id: f.revision.id }));
  await gate.waitReached();
  const creating = db
    .run("create", () => createSandbox(f.owner, f.input))
    .catch((error: unknown) => error);
  expect((await db.waitUntilBlocked("create", { by: "retire" })).query).toContain(
    "pg_advisory_xact_lock",
  );
  gate.release();
  await retiring;
  expect(await creating).toMatchObject({ code: "NOT_FOUND" });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});
it("3E a hello epoch change committed while allocation waits on H defeats old availability", async () => {
  const f = await fixture();
  const held = db.pauseAt("hello", { before: "$transaction.commit" });
  const hello = db.run("hello", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.sandboxHost.update({
        where: { id: f.host.id },
        data: {
          connectionEpoch: { increment: 1 },
          inventoryAcknowledgedEpoch: null,
          admissionEpoch: null,
          journalKeyAcknowledgedEpoch: null,
        },
      });
    }),
  );
  await held.waitReached();
  const creating = db
    .run("create", () => createSandbox(f.owner, f.input))
    .catch((error: unknown) => error);
  expect((await db.waitUntilBlocked("create", { by: "hello" })).query).toContain("sandbox_host");
  held.release();
  await hello;
  expect(await creating).toMatchObject({ code: "CONFLICT" });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});

it("3E execution-config composite owner/sandbox FK is independent of placement references", async () => {
  const a = await fixture();
  const b = await fixture();
  const booted = await createSandbox(a.owner, a.input);
  const config = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
    where: { sandboxId: booted.id },
  });
  const tentative = await db.inspect.sandbox.create({
    data: {
      hostOwnerId: a.id,
      userId: a.id,
      templateId: a.revision.templateId,
      templateRevisionId: a.revision.id,
      originalSelector: "base",
      sandboxHostId: a.host.id,
      originHostId: a.host.id,
    },
  });
  const data = {
    ...config,
    id: randomUUID(),
    sandboxId: tentative.id,
    templateDefaults: {},
    sandboxOverrides: {},
    mergedDefaults: {},
  };
  await expect(
    db.inspect.sandboxExecutionConfig.create({ data: { ...data, userId: b.id } }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(db.inspect.sandboxExecutionConfig.create({ data })).resolves.toMatchObject({
    sandboxId: tentative.id,
    userId: a.id,
  });
});
it("3E a committed availability change while allocation waits on H refuses before S insertion", async () => {
  const f = await fixture();
  const gate = db.pauseAt("availability", { before: "$transaction.commit" });
  const observing = db.run("availability", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
      await tx.sandboxTemplateAvailability.updateMany({
        where: { revisionId: f.revision.id, hostId: f.host.id },
        data: { status: "MISSING" },
      });
    }),
  );
  await gate.waitReached();
  const creating = db
    .run("create", () => createSandbox(f.owner, f.input))
    .catch((error: unknown) => error);
  expect((await db.waitUntilBlocked("create", { by: "availability" })).query).toContain(
    "sandbox_host",
  );
  gate.release();
  await observing;
  expect(await creating).toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.template_image_missing" },
  });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});

it.each(["placement", "execution_config"] as const)(
  "3E cold reconnect locks its pinned %s before inserting the new operation",
  async (resource) => {
    const f = await fixture();
    const created = await createSandbox(f.owner, f.input);
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: created.id },
      data: { state: "SUCCEEDED" },
    });
    await db.inspect.outboxEvent.updateMany({
      where: { userId: f.id },
      data: { processedAt: new Date() },
    });
    await db.inspect.sandbox.update({
      where: { id: created.id },
      data: { state: "STOPPED", liveResourcesHeld: false },
    });
    await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { liveCount: 0 } });
    const gate = db.pauseAt("private-parent", { before: "$transaction.commit" });
    const held = db.run("private-parent", () =>
      db.prisma.$transaction(async (tx) => {
        if (resource === "placement")
          await tx.$queryRaw`SELECT id FROM sandbox_placement WHERE "sandboxId" = ${created.id} FOR UPDATE`;
        else
          await tx.$queryRaw`SELECT id FROM sandbox_execution_config WHERE "sandboxId" = ${created.id} FOR UPDATE`;
      }),
    );
    await gate.waitReached();
    const reconnecting = db.run("cold-reconnect", () =>
      reconnectSandbox(f.owner, {
        id: created.id,
        mode: "cold",
        idempotencyKey: randomUUID(),
      }),
    );
    const observed = await db.waitUntilBlocked("cold-reconnect", { by: "private-parent" });
    expect(observed.query).toContain(`sandbox_${resource}`);
    const pid = db.backendPid("cold-reconnect");
    const locks = await db.inspect.$queryRaw<{ acquired: boolean }[]>`
      SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid = ${pid}
        AND relation = 'sandbox_mutation_operation'::regclass
        AND mode = 'RowExclusiveLock') AS acquired`;
    expect(locks).toEqual([{ acquired: false }]);
    gate.release();
    await held;
    expect((await reconnecting).operationId).toBeTruthy();
  },
);

it.each(["session", "ALL_OWNED"] as const)(
  "explicit-host %s foreign and absent refusals are identical 404s without locking a foreign H",
  async (kind) => {
    const f = await fixture();
    const foreign = await fixture();
    const owner =
      kind === "session"
        ? f.owner
        : await authenticateSdkKeySecret(
            (
              await createSdkKey(f.owner, {
                name: "create",
                resourceMode: "ALL_OWNED",
                scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
                hostIds: [],
                templateRevisionIds: [],
              })
            ).secret,
          );
    if (!owner) throw new Error("fixture key inactive");
    const held = db.pauseAt("foreign-host", { before: "$transaction.commit" });
    const holder = db.run("foreign-host", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${foreign.host.id} FOR UPDATE`;
      }),
    );
    await held.waitReached();
    const errors: unknown[] = [];
    try {
      for (const hostId of [foreign.host.id, randomUUID()]) {
        const creating = db
          .run("create-unowned", () =>
            createSandbox(owner, {
              ...f.input,
              sandboxHostId: hostId,
              idempotencyKey: randomUUID(),
            }),
          )
          .then(
            () => null,
            (error: unknown) => error,
          );
        // If create seeks foreign H, the PG lock observer wins this race. A
        // correct refusal finishes while the other owner's row stays locked.
        const outcome = await Promise.race([
          creating,
          db
            .waitUntilBlocked("create-unowned", { by: "foreign-host" })
            .then((lock) => ({ blockedOn: lock.query })),
        ]);
        expect(outcome).toMatchObject({
          code: "NOT_FOUND",
          status: 404,
          data: { code: "sandbox.host_not_found" },
          message: "Host not found.",
        });
        const error = outcome as { code: string; message: string; data: unknown };
        errors.push({ code: error.code, message: error.message, data: error.data });
      }
      expect(errors[0]).toEqual(errors[1]);
      expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    } finally {
      held.release();
      await holder;
    }
  },
);

it("explicit-host owned H is locked before inserting tentative S", async () => {
  const f = await fixture();
  const gate = db.pauseAt("create-owned", { before: "sandbox.create" });
  const creating = db.run("create-owned", () => createSandbox(f.owner, f.input));
  await gate.waitReached();
  const probing = db.run("host-probe", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
    }),
  );
  try {
    expect((await db.waitUntilBlocked("host-probe", { by: "create-owned" })).query).toContain(
      "sandbox_host",
    );
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  } finally {
    gate.release();
  }
  await creating;
  await probing;
});

it("missing exact association persists MISSING and subsequent creates return the same conflict", async () => {
  const f = await fixture();
  await db.inspect.sandboxTemplateAvailability.deleteMany({ where: { revisionId: f.revision.id } });
  bindHostImageVerifier(async () => {
    throw new HostImageMissing("private diagnostic");
  });
  try {
    const failure = { code: "CONFLICT", data: { code: "sandbox.template_image_missing" } };
    await expect(
      associateTemplateAvailability(f.owner, {
        templateId: f.revision.templateId,
        revisionId: f.revision.id,
        hostId: f.host.id,
      }),
    ).rejects.toMatchObject(failure);
    expect(
      await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
        where: { revisionId_hostId: { revisionId: f.revision.id, hostId: f.host.id } },
      }),
    ).toMatchObject({ status: "MISSING", verifiedConnectionEpoch: f.host.connectionEpoch });
    await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject(failure);
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  } finally {
    bindHostImageVerifier(null);
  }
});
