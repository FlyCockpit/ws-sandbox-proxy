import { randomUUID } from "node:crypto";
import { call, createRouterClient, ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../sandbox/testing/resource-fixtures";

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
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
const db = await pgTestDatabase();
const { liveOwnerSessionProcedure } = await import("../index");
const { sandboxesRouter } = await import("./sandboxes");
const services = await import("../sandbox/services/sandboxes");
const { runCommandInput } = await import("../sandbox/contracts");
const { invalidateForceTwoFactorSettingsCache } = await import("../lib/two-factor-policy");
afterAll(() => db.close());
beforeEach(() => invalidateForceTwoFactorSettingsCache());

async function owner() {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Owner",
      emailVerified: true,
      twoFactorEnabled: true,
      createdAt: new Date(0),
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const context: Context = { session: { user, session } as Session, clientIp: undefined };
  return { id, session, context, principal: { kind: "session" as const, ownerId: id } };
}
function barrier() {
  let release!: () => void;
  let reached!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const entered = new Promise<void>((resolve) => {
    reached = resolve;
  });
  return { release, reached, held, entered };
}

const sensitive = [
  "getOperationResult",
  "getSandboxCapabilities",
  "connectProcess",
  "killProcess",
  "sendProcessStdin",
  "runCommand",
  "writeStdin",
  "getCommandOutput",
  "readFile",
  "listDir",
  "statPath",
  "mkdir",
  "removePath",
  "movePath",
  "listProcesses",
  "signalProcess",
  "cancelOperation",
  "getOperation",
] as const;
it.each(sensitive)("%s rejects a revoked cookie before input or resource IO", async (name) => {
  const o = await owner();
  await db.inspect.session.delete({ where: { id: o.session.id } });
  await expect(
    call(sandboxesRouter[name], {} as never, { context: o.context }),
  ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});

const revocations = ["deleted", "expired", "impersonated", "banned", "deleting", "2fa"] as const;
for (const rejected of [false, true]) {
  it.each(revocations)(
    `rechecks durable %s on ${rejected ? "rejected" : "successful"} exit`,
    async (reason) => {
      const o = await owner();
      const b = barrier();
      const procedure = liveOwnerSessionProcedure.handler(async () => {
        b.reached();
        await b.held;
        if (rejected)
          throw new ORPCError("CONFLICT", {
            message: "PRIVATE-HANDLER-ERROR",
            data: { private: "PRIVATE-DATA" },
          });
        return { private: "PRIVATE-RESULT" };
      });
      const pending = call(procedure, undefined, { context: o.context });
      const result = expect(pending).rejects.toMatchObject({ code: "UNAUTHORIZED" });
      await b.entered;
      try {
        if (reason === "deleted") await db.inspect.session.delete({ where: { id: o.session.id } });
        if (reason === "expired")
          await db.inspect.session.update({
            where: { id: o.session.id },
            data: { expiresAt: new Date(0) },
          });
        if (reason === "impersonated")
          await db.inspect.session.update({
            where: { id: o.session.id },
            data: { impersonatedBy: "admin" },
          });
        if (reason === "banned")
          await db.inspect.user.update({ where: { id: o.id }, data: { banned: true } });
        if (reason === "deleting")
          await db.inspect.user.update({
            where: { id: o.id },
            data: { deletionRequestedAt: new Date() },
          });
        if (reason === "2fa") {
          await db.inspect.appSetting.upsert({
            where: { key: "force2faPublicUsers" },
            create: { key: "force2faPublicUsers", value: "true" },
            update: { value: "true" },
          });
          await db.inspect.user.update({ where: { id: o.id }, data: { twoFactorEnabled: false } });
          invalidateForceTwoFactorSettingsCache();
        }
      } finally {
        b.release();
      }
      await result;
    },
  );
}
it("preserves an authorized result and error", async () => {
  const o = await owner();
  expect(
    await call(
      liveOwnerSessionProcedure.handler(() => "ok"),
      undefined,
      { context: o.context },
    ),
  ).toBe("ok");
  await expect(
    call(
      liveOwnerSessionProcedure.handler(() => {
        throw new ORPCError("CONFLICT");
      }),
      undefined,
      { context: o.context },
    ),
  ).rejects.toMatchObject({ code: "CONFLICT" });
});

it.each(["mkdir", "runCommand", "cancelOperation"] as const)(
  "%s exit denial after commit preserves history and original-key recovery without another effect",
  async (action) => {
    const o = await owner();
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: o.id,
        slug: "lab",
        label: "Lab",
        status: "CONNECTED",
        connectionEpoch: 1,
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 1,
        egressEnforcement: true,
      },
    });
    const template = await seedTemplateRevision(db.inspect, {
      data: {
        userId: o.id,
        sandboxHostId: host.id,
        slug: "base",
        label: "Base",
        imageRef: "local:base",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: o.id,
        sandboxHostId: host.id,
        originHostId: host.id,
        templateId: template.id,
        state: "READY",
      },
    });
    const input = { id: sandbox.id, path: "/tmp/test", idempotencyKey: "original-key" };
    const command = runCommandInput.parse({
      id: sandbox.id,
      argv: ["true"],
      idempotencyKey: "original-key",
    });
    const target = action === "cancelOperation" ? await services.mkdir(o.principal, input) : null;
    const accept = () =>
      target
        ? services.cancelOperation(o.principal, { operationId: target.operationId })
        : action === "runCommand"
          ? services.runCommand(o.principal, command)
          : services.mkdir(o.principal, input);
    const kind = action === "runCommand" ? "RUN_COMMAND" : "MKDIR";
    const b = barrier();
    const procedure = liveOwnerSessionProcedure.handler(async () => {
      const receipt = await accept();
      b.reached();
      await b.held;
      return receipt;
    });
    const pending = call(procedure, undefined, { context: o.context });
    const denied = expect(pending).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await b.entered;
    await db.inspect.session.delete({ where: { id: o.session.id } });
    b.release();
    await denied;
    const rows = await db.inspect.sandboxOperation.findMany({
      where: { userId: o.id, kind },
      take: 2,
    });
    expect(rows).toHaveLength(1);
    const session = await db.inspect.session.create({
      data: { userId: o.id, token: randomUUID(), expiresAt: new Date(Date.now() + 60000) },
    });
    const context: Context = {
      ...o.context,
      session: { ...o.context.session!, session } as Session,
    };
    const api = createRouterClient(sandboxesRouter, { context });
    expect(
      (await api.listOperations({ limit: 10 })).items.some((row) => row.id === rows[0]!.id),
    ).toBe(true);
    const recovered = target
      ? await api.cancelOperation({ operationId: target.operationId })
      : action === "runCommand"
        ? await api.runCommand(command)
        : await api.mkdir(input);
    expect(recovered.operationId).toBe(rows[0]!.id);
    if (target) expect(recovered.state).toBe("CANCELLED");
    expect(await db.inspect.sandboxOperation.count({ where: { userId: o.id, kind } })).toBe(1);
    expect(
      await db.inspect.outboxEvent.count({
        where: {
          userId: o.id,
          aggregateId: sandbox.id,
          eventType:
            action === "runCommand" ? "sandbox.command_requested" : "sandbox.file_mkdir_requested",
        },
      }),
    ).toBe(1);
  },
);
