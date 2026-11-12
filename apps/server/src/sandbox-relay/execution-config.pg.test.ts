import { sandboxDiskSelect } from "../../../../packages/api/src/sandbox/disk-offload/disk-view";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const db = await pgTestDatabase();
const { createSandbox, runCommand } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { loadExecutionConfig } = await import("@wssp/api/sandbox/execution-config");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const { toSandboxDto } = await import("@wssp/api/sandbox/sdk-reads");
afterAll(() => db.close());
const SENTINEL = "synthetic-private-config-3d";
async function seed(keyed = true) {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
      ...(keyed
        ? {
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          }
        : { journalKeyVersion: null, journalKeyId: null, journalKeyAcknowledgedEpoch: null }),
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  const owner = { kind: "session" as const, ownerId };
  const input = {
    template: "revision/" + template.id,
    sandboxHostId: host.id,
    idempotencyKey: randomUUID(),
    envs: { APP: SENTINEL },
  };
  return { owner, host, input };
}

it("3D private snapshot stamps the sandbox owner; cross-owner reads and service writes confer nothing", async () => {
  const f = await seed();
  const other = await seed();
  await expect(createSandbox(other.owner, f.input)).rejects.toMatchObject({ code: "NOT_FOUND" });
  const sandbox = await createSandbox(f.owner, f.input);
  const row = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
    where: { sandboxId: sandbox.id },
  });
  expect(row).toMatchObject({
    userId: f.owner.ownerId,
    templateDefaults: {},
    sandboxOverrides: f.input.envs,
    mergedDefaults: f.input.envs,
  });
  expect(await loadExecutionConfig(db.prisma, sandbox.id, other.owner.ownerId)).toBeNull();
  expect(await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId)).toMatchObject({
    env: [["APP", SENTINEL]],
  });
  const outbox = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id },
  });
  expect(outbox.payload).toMatchObject({
    privateConfig: { configId: row.id, bindingMac: row.bindingMac },
  });
  const disk = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: sandbox.id },
    select: sandboxDiskSelect,
  });
  for (const publicValue of [sandbox, toSandboxDto({ ...sandbox, ...disk }), outbox.payload])
    expect(JSON.stringify(publicValue)).not.toContain(SENTINEL);
  expect(await createSandbox(f.owner, { ...f.input, envs: { APP: SENTINEL } })).toMatchObject({
    id: sandbox.id,
  });
  await expect(
    createSandbox(f.owner, { ...f.input, envs: { APP: "changed" } }),
  ).rejects.toMatchObject({ code: "CONFLICT" });
});

it("3D config has additive owner/sandbox FKs and cascades with sandbox history cleanup", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const row = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
    where: { sandboxId: sandbox.id },
  });
  // Clear the unique sandbox slot so each missing FK is tested independently.
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { currentPlacementId: null },
  });
  await db.inspect.sandboxPlacement.deleteMany({ where: { sandboxId: sandbox.id } });
  await db.inspect.sandboxExecutionConfig.delete({ where: { id: row.id } });
  for (const missing of [{ userId: "missing-owner" }, { sandboxId: "missing-sandbox" }]) {
    await expect(
      db.inspect.sandboxExecutionConfig.create({
        data: {
          ...row,
          templateDefaults: {},
          sandboxOverrides: f.input.envs,
          mergedDefaults: f.input.envs,
          id: randomUUID(),
          ...missing,
        },
      }),
    ).rejects.toMatchObject({ code: "P2003" });
  }
  await db.inspect.sandboxExecutionConfig.create({
    data: {
      ...row,
      templateDefaults: {},
      sandboxOverrides: f.input.envs,
      mergedDefaults: f.input.envs,
    },
  });
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "STOPPED" } });
  expect(await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId)).not.toBeNull();
  await db.inspect.sandboxOperation.deleteMany({ where: { sandboxId: sandbox.id } });
  await db.inspect.sandbox.delete({ where: { id: sandbox.id } });
  expect(await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId)).toBeNull();
});

it.each(["sandboxExecutionConfig.create", "outboxEvent.create", "$transaction.commit"])(
  "3D %s failure rolls back config, sandbox, operation, outbox and reservation without exposing the producer",
  async (point) => {
    const f = await seed();
    const gate = db.pauseAt("create", { before: point });
    const result = db
      .run("create", () => createSandbox(f.owner, f.input))
      .catch((error: unknown) => error);
    await gate.waitReached();
    gate.fail(
      new Error(`Prisma invocation DETAIL ${SENTINEL} ${Buffer.from(SENTINEL).toString("base64")}`),
    );
    const error = await result;
    expect(JSON.stringify(error)).not.toContain(SENTINEL);
    expect(String(error)).not.toContain(SENTINEL);
    const where = { userId: f.owner.ownerId };
    expect(await db.inspect.sandbox.count({ where })).toBe(0);
    expect(await db.inspect.sandboxOperation.count({ where })).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where })).toBe(0);
    expect(await db.inspect.sandboxExecutionConfig.count({ where })).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  },
);

it("3E requires negotiated key support before reservation, including empty snapshots", async () => {
  const f = await seed(false);
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({ code: "CONFLICT" });
  expect(await db.inspect.sandbox.count({ where: { userId: f.owner.ownerId } })).toBe(0);
  await expect(createSandbox(f.owner, { ...f.input, envs: {} })).rejects.toMatchObject({
    code: "CONFLICT",
  });
});

it("3D H precedes snapshot and FK writes under real contention", async () => {
  const f = await seed();
  const held = db.pauseAt("holder", { before: "$transaction.commit" });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const created = db.run("create", () => createSandbox(f.owner, f.input));
  try {
    expect((await db.waitUntilBlocked("create", { by: "holder" })).query).toMatch(
      /sandbox_host.*FOR UPDATE/,
    );
    expect(
      await db.inspect.sandboxExecutionConfig.count({
        where: { userId: f.owner.ownerId },
      }),
    ).toBe(0);
  } finally {
    held.release();
  }
  await holder;
  await created;
});

it("3D validates stored snapshots and refuses an oversized defaults+command union before enqueue", async () => {
  const f = await seed();
  const envs = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`K${i}`, "value"]));
  const sandbox = await createSandbox(f.owner, { ...f.input, envs });
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
  const before = await db.inspect.sandboxOperation.count({ where: { sandboxId: sandbox.id } });
  await expect(
    runCommand(f.owner, {
      id: sandbox.id,
      idempotencyKey: randomUUID(),
      argv: ["/bin/true"],
      timeoutMs: 1000,
      envs: { EXTRA: SENTINEL },
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(await db.inspect.sandboxOperation.count({ where: { sandboxId: sandbox.id } })).toBe(
    before,
  );
  await db.inspect.sandboxExecutionConfig.update({
    where: { sandboxId: sandbox.id },
    data: { mergedDefaults: { APP: SENTINEL } },
  });
  await expect(loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId)).rejects.toThrow(
    "Invalid private execution config.",
  );
});

it("3D env-bearing config and outbox rows have no secret-bearing CHECK constraints", async () => {
  const rows = await db.inspect.$queryRaw<
    Array<{ name: string }>
  >`SELECT conname AS name FROM pg_constraint WHERE contype = 'c' AND conrelid IN ('sandbox_execution_config'::regclass, 'sandbox_dispatch_outbox'::regclass)`;
  expect(rows).toEqual([]);
});

it("3D both owner filters reject a mismatched direct row; service never accepts an owner field", async () => {
  const f = await seed();
  const other = await seed();
  const poisoned = { ...f.input, userId: other.owner.ownerId };
  const sandbox = await createSandbox(f.owner, poisoned);
  expect(
    await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
      where: { sandboxId: sandbox.id },
    }),
  ).toMatchObject({ userId: f.owner.ownerId });
  await expect(
    db.inspect.sandboxExecutionConfig.update({
      where: { sandboxId: sandbox.id },
      data: { userId: other.owner.ownerId },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  expect(await loadExecutionConfig(db.prisma, sandbox.id, other.owner.ownerId)).toBeNull();
  expect(await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId)).not.toBeNull();
});

it("3D command config reads wait on S after H, before operation/outbox writes", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
  const held = db.pauseAt("s-holder", { before: "$transaction.commit" });
  const holder = db.run("s-holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const config = db.pauseAt("command", { before: "sandboxExecutionConfig.findFirst" });
  const command = db.run("command", () =>
    runCommand(f.owner, {
      id: sandbox.id,
      argv: ["true"],
      timeoutMs: 1000,
      idempotencyKey: randomUUID(),
    }),
  );
  try {
    expect((await db.waitUntilBlocked("command", { by: "s-holder" })).query).toMatch(
      /sandbox.*FOR NO KEY UPDATE/,
    );
  } finally {
    held.release();
  }
  await holder;
  await config.waitReached();
  const host = db.run("host-writer", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
    }),
  );
  try {
    expect((await db.waitUntilBlocked("host-writer", { by: "command" })).query).toMatch(
      /sandbox_host.*FOR UPDATE/,
    );
  } finally {
    config.release();
  }
  await command;
  await host;
});
