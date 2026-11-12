import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * Owner label edits and stored ledger projections against real PostgreSQL.
 * Label edits serialize with reservations without changing capacity policy.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c44-pg-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { sandboxHostsRouter } = await import("../../../../packages/api/src/routers/sandbox-hosts");
const { createSandbox } = await import("@wssp/api/sandbox/services/sandboxes");
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { bindHostImageVerifier } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
const FP = `sha256:${"e".repeat(64)}`;
bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
afterAll(() => db.close());

async function owner(options: { liveCount?: number } = {}) {
  const id = `edit-${randomUUID()}`;
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

      liveCount: options.liveCount ?? 0,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  const durableSession = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 60000) },
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session: durableSession,
    },
  } as Context;
  return { id, host, template, client: createRouterClient(sandboxHostsRouter, { context }) };
}
type Owner = Awaited<ReturnType<typeof owner>>;

const create = (o: Owner) =>
  createSandbox(
    { kind: "session", ownerId: o.id },
    createSandboxInput.parse({
      template: "revision/" + o.template.id,
      sandboxHostId: o.host.id,
      idempotencyKey: randomUUID(),
    }),
  );
const settle = (p: Promise<unknown>) =>
  p.then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error }),
  );
const hostRow = (id: string) => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id } });

it("two owners list disjoint hosts, each with the drain/capacity projection", async () => {
  const a = await owner({ liveCount: 1 });
  const b = await owner();
  const listA = await a.client.listHosts({ limit: 50 });
  const listB = await b.client.listHosts({ limit: 50 });
  expect(listA.items.map((host) => host.id)).toEqual([a.host.id]);
  expect(listB.items.map((host) => host.id)).toEqual([b.host.id]);
  expect(listA.items[0]).toMatchObject({
    liveSandboxCount: 1,
    drained: false,
    draining: false,
    daemonRuntime: null,
    daemonVersion: null,
  });
});

it("a foreign owner's edit is NOT_FOUND and changes nothing", async () => {
  const a = await owner();
  const b = await owner();
  await expect(b.client.updateHost({ id: a.host.id, label: "stolen" })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect(await hostRow(a.host.id)).toMatchObject({ label: "Lab" });
});

it("label-only edits preserve live reservations and do not apply a count cap", async () => {
  const a = await owner({ liveCount: 2 });
  await expect(a.client.updateHost({ id: a.host.id })).resolves.toMatchObject({
    liveSandboxCount: 2,
  });
  await expect(a.client.updateHost({ id: a.host.id, label: "Renamed" })).resolves.toMatchObject({
    label: "Renamed",

    liveSandboxCount: 2,
    drained: false,
  });
});

it("a host pending deletion cannot be edited", async () => {
  const a = await owner();
  await db.inspect.sandboxHost.update({
    where: { id: a.host.id },
    data: { deletionRequestedAt: new Date() },
  });
  await expect(a.client.updateHost({ id: a.host.id, label: "x" })).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.host_delete_conflict" },
  });
  expect(await hostRow(a.host.id)).toMatchObject({ label: "Lab" });
});

it("a label edit racing a create waits for H and sees its reservation", async () => {
  const a = await owner({ liveCount: 1 });
  const pause = db.pauseAt("work", { after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const work = settle(db.run("work", () => create(a)));
  await pause.waitReached();
  const edit = settle(db.run("edit", () => a.client.updateHost({ id: a.host.id })));
  try {
    await db.waitUntilBlocked("edit", { by: "work" });
  } finally {
    pause.release();
  }
  expect(await work).toMatchObject({ ok: true });
  expect(await edit).toMatchObject({ ok: true, value: { liveSandboxCount: 2 } });
  expect(await hostRow(a.host.id)).toMatchObject({ liveCount: 2 });
});

it("a create racing a label edit waits for H and preserves capacity policy", async () => {
  const a = await owner({ liveCount: 1 });
  const pause = db.pauseAt("edit", { after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const edit = settle(db.run("edit", () => a.client.updateHost({ id: a.host.id })));
  await pause.waitReached();
  const work = settle(db.run("work", () => create(a)));
  try {
    await db.waitUntilBlocked("work", { by: "edit" });
  } finally {
    pause.release();
  }
  expect(await edit).toMatchObject({ ok: true, value: {} });
  expect(await work).toMatchObject({ ok: true });
  expect(await hostRow(a.host.id)).toMatchObject({ liveCount: 2 });
});
