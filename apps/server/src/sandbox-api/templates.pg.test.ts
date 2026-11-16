import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: vi.fn(async () => {}),
}));

import { randomUUID } from "node:crypto";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * C46: the templates page's procedures and the SDK-key mint rules against real
 * PostgreSQL — owner scoping, status filtering, the host summary and use count
 * in the owner projection, archive refused while a non-DELETED sandbox uses
 * the template (with a stable code), an archived revision still readable for
 * the sandbox that references it, and the server-side SDK-key mint rules.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c46-pg-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { sandboxTemplatesRouter } = await import(
  "../../../../packages/api/src/routers/sandbox-templates"
);
const { sdkKeysRouter } = await import("../../../../packages/api/src/routers/sdk-keys");
const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
const { bindHostImageVerifier, HostImageRejected, HostImageMissing } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
afterAll(() => db.close());

const FP = `sha256:${"e".repeat(64)}`;
const FP2 = `sha256:${"f".repeat(64)}`;

async function owner() {
  const id = `tpl-${randomUUID()}`;
  const user = await db.inspect.user.create({
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
      connectionEpoch: 1,
      lastHeartbeatAt: new Date(),
    },
  });
  const other = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "spare", label: "Spare", status: "CONNECTED", connectionEpoch: 1 },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session,
    },
  } as Context;
  return {
    id,
    host,
    other,
    templates: createRouterClient(sandboxTemplatesRouter, { context }),
    keys: createRouterClient(sdkKeysRouter, { context }),
    sandboxes: createRouterClient(sandboxesRouter, { context }),
  };
}

function template(ownerId: string, hostId: string, slug: string, incusFingerprint = FP) {
  return seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: hostId,
      slug,
      label: slug,
      imageRef: `local:${slug}`,
      incusFingerprint,
    },
  });
}

it("registration creates a logical template, immutable first revision and exact host availability; refusal persists nothing", async () => {
  const f = await owner();
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  const logical = await f.templates.createTemplate({
    hostId: f.host.id,
    slug: "base",
    label: "Base",
    imageRef: "images:base",
    envs: { APP: "private-template-default" },
  });
  expect(logical).toMatchObject({ slug: "base", label: "Base", archivedAt: null });
  expect(JSON.stringify(logical)).not.toContain("private-template-default");
  const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
    where: { id: logical.firstRevisionId },
  });
  expect(revision).toMatchObject({ templateId: logical.id, revision: 1, incusFingerprint: FP });
  expect(
    await db.inspect.sandboxTemplateAvailability.findFirst({ where: { revisionId: revision.id } }),
  ).toMatchObject({
    hostId: f.host.id,
    status: "AVAILABLE",
    verifiedConnectionEpoch: f.host.connectionEpoch,
  });
  const publicPage = await f.templates.listRevisions({ templateId: logical.id, limit: 10 });
  expect(JSON.stringify(publicPage)).not.toMatch(
    /private-template-default|checksum|defaultEnvs|Config/,
  );
  bindHostImageVerifier(async () => {
    throw new HostImageRejected("private-host-reason");
  });
  await expect(
    f.templates.createTemplate({
      hostId: f.host.id,
      slug: "refused",
      label: "Refused",
      imageRef: "images:no",
    }),
  ).rejects.toMatchObject({ data: { code: "sandbox.template_image_rejected" } });
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id } })).toBe(1);
});
it("logical owner lists are disjoint and archive filters do not reinterpret retained revision identity", async () => {
  const a = await owner();
  const b = await owner();
  const first = await template(a.id, a.host.id, "base");
  const second = await template(a.id, a.host.id, "old", FP2);
  await template(b.id, b.host.id, "foreign");
  await a.templates.retireTemplate({ id: second.templateId });
  expect(
    (await a.templates.listTemplates({ limit: 10, status: "active" })).items.map((row) => row.id),
  ).toEqual([first.templateId]);
  expect(
    (await a.templates.listTemplates({ limit: 10, status: "retired" })).items.map((row) => row.id),
  ).toEqual([second.templateId]);
  await expect(b.templates.getTemplate({ id: first.templateId })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect((await a.templates.getTemplateRevision({ id: second.id })).id).toBe(second.id);
});
it("archiving a logical template preserves every pinned launch and private config", async () => {
  const f = await owner();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { egressEnforcement: true },
  });
  const revision = await template(f.id, f.host.id, "base");
  const created = await f.sandboxes.createSandbox({
    template: `revision/${revision.id}`,
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await f.templates.retireTemplate({ id: revision.templateId });
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: created.id } });
  expect(sandbox.templateRevisionId).toBe(revision.id);
  expect(await db.inspect.sandboxExecutionConfig.count({ where: { sandboxId: sandbox.id } })).toBe(
    1,
  );
  await expect(
    f.sandboxes.createSandbox({
      template: `revision/${revision.id}`,
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it("mint requires exact active revision associations on selected owned hosts; missing/rejected and logical IDs confer no grant", async () => {
  const f = await owner();
  const revision = await template(f.id, f.host.id, "base");
  const input = {
    name: "key",
    scopes: ["sandboxes:read"] as ["sandboxes:read"],
    resourceMode: "ALLOWLIST" as const,
    hostIds: [f.host.id],
    templateRevisionIds: [revision.id],
  };
  await expect(
    f.keys.create({ ...input, templateRevisionIds: [revision.templateId] }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  for (const status of ["MISSING", "REJECTED"] as const) {
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: revision.id },
      data: { status },
    });
    await expect(f.keys.create(input)).rejects.toMatchObject({
      data: { code: "sdk_key.template_not_on_selected_host" },
    });
  }
  for (const status of ["PENDING", "AVAILABLE"] as const) {
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: revision.id },
      data: { status },
    });
    const key = await f.keys.create(input);
    expect(key.key.revisionAllowlist.map((row) => row.id)).toEqual([revision.id]);
  }
  await expect(
    f.keys.create({ ...input, templateIds: [revision.id] } as never),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
});

it.each(["createTemplate", "appendRevision", "associateAvailability"] as const)(
  "oRPC %s propagates the template budget refusal before work and succeeds under budget",
  async (kind) => {
    const f = await owner();
    const revision = await template(f.id, f.host.id, "base");
    const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
    const budget = vi.mocked(consumeSandboxWriteBudget);
    bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
    const call = () =>
      kind === "createTemplate"
        ? f.templates.createTemplate({
            hostId: f.host.id,
            slug: "new",
            label: "New",
            imageRef: "images:base",
          })
        : kind === "appendRevision"
          ? f.templates.appendRevision({
              templateId: revision.templateId,
              hostId: f.host.id,
              imageRef: "images:base",
            })
          : f.templates.associateAvailability({
              templateId: revision.templateId,
              revisionId: revision.id,
              hostId: f.host.id,
            });
    budget.mockRejectedValueOnce(
      new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 60 } }),
    );
    await expect(call()).rejects.toMatchObject({
      code: "TOO_MANY_REQUESTS",
      status: 429,
      data: { retryAfterSeconds: 60 },
    });
    expect(await db.inspect.sandboxTemplateRevision.count({ where: { userId: f.id } })).toBe(1);
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(0);
    await expect(call()).resolves.toBeDefined();
    expect(budget).toHaveBeenLastCalledWith(f.id, "template");
  },
);

it.each(["createTemplate", "appendRevision", "associateAvailability"] as const)(
  "%s availability uses database time sampled after the host lock despite app clock skew",
  async (kind) => {
    const f = await owner();
    const revision = await template(f.id, f.host.id, "base");
    bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
    const held = db.pauseAt("clock-host", { before: "$transaction.commit" });
    const holder = db.run("clock-host", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
      }),
    );
    await held.waitReached();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2000-01-01T00:00:00Z"));
    const writing = db.run("availability-writer", async () => {
      if (kind === "createTemplate")
        return (
          await f.templates.createTemplate({
            hostId: f.host.id,
            slug: "new",
            label: "New",
            imageRef: "images:base",
          })
        ).firstRevisionId;
      if (kind === "appendRevision")
        return (
          await f.templates.appendRevision({
            templateId: revision.templateId,
            hostId: f.host.id,
            imageRef: "images:base",
          })
        ).id;
      await f.templates.associateAvailability({
        templateId: revision.templateId,
        revisionId: revision.id,
        hostId: f.host.id,
      });
      return revision.id;
    });
    try {
      expect(
        (await db.waitUntilBlocked("availability-writer", { by: "clock-host" })).query,
      ).toContain("sandbox_host");
      const [released] = await db.inspect.$queryRaw<
        { now: Date }[]
      >`SELECT clock_timestamp() AS now`;
      held.release();
      const revisionId = await writing;
      const availability = await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
        where: { revisionId_hostId: { revisionId, hostId: f.host.id } },
      });
      const [after] = await db.inspect.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
      expect(availability.observedAt!.getTime()).toBeGreaterThanOrEqual(released!.now.getTime());
      expect(availability.observedAt!.getTime()).toBeLessThanOrEqual(after!.now.getTime());
    } finally {
      held.release();
      vi.useRealTimers();
      await holder;
    }
  },
);

it("an older association MISSING cannot overwrite a newer same-epoch census verdict", async () => {
  const { AvailabilityCensus } = await import("../sandbox-relay/availability-census.js");
  const f = await owner();
  const revision = await template(f.id, f.host.id, "base");
  let entered!: () => void;
  const verifying = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  bindHostImageVerifier(async () => {
    entered();
    await gate;
    throw new HostImageMissing("old absence observation");
  });
  const pending = f.templates.associateAvailability({
    templateId: revision.templateId,
    revisionId: revision.id,
    hostId: f.host.id,
  });
  const outcome = pending.catch((error: unknown) => error);
  const requests: Extract<
    import("../sandbox-relay/protocol.js").ServerControlMessage,
    { type: "availability.request" }
  >[] = [];
  const census = new AvailabilityCensus(
    { userId: f.id, hostId: f.host.id, connectionEpoch: f.host.connectionEpoch },
    (message) => {
      if (message.type === "availability.request") requests.push(message);
    },
  );
  try {
    await verifying;
    await census.next();
    const request = requests[0]!;
    await census.accept({
      type: "availability.result",
      requestId: request.requestId,
      page: request.page,
      connectionEpoch: f.host.connectionEpoch,
      entries: request.bindings.map((binding) => ({ binding, status: "present" as const })),
    });
    const where = { revisionId_hostId: { revisionId: revision.id, hostId: f.host.id } };
    const newer = await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({ where });
    expect(newer.status).toBe("AVAILABLE");
    release();
    expect(await outcome).toMatchObject({ data: { code: "sandbox.template_image_missing" } });
    const retained = await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({ where });
    expect(retained.status).toBe("AVAILABLE");
    expect(retained.observedAt).toEqual(newer.observedAt);
  } finally {
    release();
    census.stop();
    bindHostImageVerifier(null);
    await outcome;
  }
});

it("B5 revision size is self-contained launch policy, independent of image verification and manifest digest", async () => {
  const f = await owner();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 512, daemonMaxCpuCount: 1 },
  });
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  const logical = await f.templates.createTemplate({
    defaultDiskGiB: 32,
    hostId: f.host.id,
    slug: "size-policy",
    label: "Size policy",
    imageRef: "images:base",
    cpuCount: 32,
    memoryMiB: 65536,
  });
  const first = await f.templates.getTemplateRevision({ id: logical.firstRevisionId });
  expect(first).toMatchObject({ defaultDiskGiB: 32, cpuCount: 32, memoryMiB: 65536 });
  const second = await f.templates.appendRevision({
    hostId: f.host.id,
    templateId: logical.id,
    imageRef: "images:base",
    memoryMiB: 2048,
  });
  const third = await f.templates.appendRevision({
    hostId: f.host.id,
    templateId: logical.id,
    imageRef: "images:base",
  });
  expect(second).toMatchObject({
    defaultDiskGiB: 32,
    cpuCount: 1,
    memoryMiB: 2048,
    manifestDigest: first.manifestDigest,
  });
  expect(third).toMatchObject({
    defaultDiskGiB: 32,
    cpuCount: 1,
    memoryMiB: 1024,
    manifestDigest: first.manifestDigest,
  });
  expect(await f.templates.getTemplateRevision({ id: first.id })).toMatchObject({
    defaultDiskGiB: 32,
    cpuCount: 32,
    memoryMiB: 65536,
  });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
});
