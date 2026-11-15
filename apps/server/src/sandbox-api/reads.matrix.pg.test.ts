import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { Hono } from "hono";
import { afterAll, beforeAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "matrix-pg-fixture",
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
    BETTER_AUTH_URL: "http://localhost:3000",
    TRANSFER_MAX_BYTES: 1073741824,
    TRANSFER_DISK_BYTES: 1073741824,
    TRANSFER_OWNER_ACTIVE: 10,
    TRANSFER_GLOBAL_ACTIVE: 100,
    TRANSFER_IDLE_SECONDS: 60,
    TRANSFER_ABSOLUTE_SECONDS: 600,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/auth", () => ({
  auth: { $context: Promise.resolve({ secretConfig: "matrix-pg-test-secret" }) },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, imageStoreMaintenanceQueue: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/api/lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "127.0.0.1" } }),
}));
vi.mock("../mcp-rate-limit", () => ({
  consumeMcpCreateQuota: async () => {},
  consumeMcpHostCommandQuota: async () => {},
}));
const db = await pgTestDatabase();
const spool = await mkdtemp(join(tmpdir(), "rp5-fuwssp-pg-matrix-"));
const { env } = await import("@wssp/env/server");
Object.assign(env, { TRANSFER_SPOOL_DIR: spool });
const { startTransferStore } = await import("../sandbox-transfers/runtime");
let store: Awaited<ReturnType<typeof startTransferStore>>;
beforeAll(async () => {
  store = await startTransferStore();
});
afterAll(async () => {
  await store?.close();
  await rm(spool, { recursive: true, force: true });
  await db.close();
});
const { seedLaunchHost, seedSandboxInstance, seedTemplateRevision, seedAcceptedOperation } =
  await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { createAgentToken } = await import(
  "../../../../packages/api/src/sandbox/services/agent-tokens"
);
const { authenticateSdkKeySecret, authenticateAgentTokenSecret, authorizeServiceAction } =
  await import("@wssp/api/lib/sdk-key-access");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { listSandboxes } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { callMcpTool } = await import("../mcp/tools");
const { createSandboxApi } = await import("./middleware");
async function person() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  return { kind: "session" as const, ownerId: id };
}
async function key(owner: Awaited<ReturnType<typeof person>>, ownSandboxesOnly: boolean) {
  const api = await createSdkKey(owner, {
    name: "Matrix API",
    scopes: [...SERVICE_SCOPES],
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly,
    hostIds: [],
    templateRevisionIds: [],
  });
  const agent = await createAgentToken(owner, {
    name: "Matrix agent",
    scopes: [...SERVICE_SCOPES],
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly,
    expiresAt: new Date(Date.now() + 86400000),
  });
  const p = await authenticateSdkKeySecret(api.secret),
    m = await authenticateAgentTokenSecret(agent.secret);
  if (!p || !m) throw new Error("fixture credential inactive");
  return { api, agent, p, m };
}
async function fixture(ownOnly = true) {
  const owner = await person();
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: owner.ownerId, slug: "host", label: "Host" },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: owner.ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const credentials = await key(owner, ownOnly);
  const sandboxes = [];
  for (const creator of [credentials.p.keyId, credentials.m.keyId, null]) {
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: owner.ownerId,
        sandboxHostId: host.id,
        hostOwnerId: owner.ownerId,
        originHostId: host.id,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        state: "READY",
        generation: 1,
      },
    });
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
      data: { authorizingKeyId: creator },
    });
    const operation = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: owner.ownerId,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "SUCCEEDED",
        authorizingKeyId: creator,
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
      },
    });
    sandboxes.push({ sandbox, operation });
  }
  return { owner, host, revision, ...credentials, sandboxes };
}
const targets = [
  "sandboxes.get",
  "commands.run",
  "commands.writeStdin",
  "files.read",
  "files.write",
  "files.listDir",
  "processes.list",
  "processes.connect",
  "processes.signal",
  "sandboxes.stop",
  "sandboxes.kill",
] as const;
it("ALL_OWNED own-only gates every sandbox action and operation read by its CREATE authorizer, before services or dispatch", async () => {
  const f = await fixture();
  for (const [principal, mine] of [
    [f.p, 0],
    [f.m, 1],
  ] as const) {
    const page = await listSandboxes(principal, { limit: 100 });
    expect(page.items.map((s) => s.id)).toEqual([f.sandboxes[mine]!.sandbox.id]);
    for (let i = 0; i < f.sandboxes.length; i++) {
      const row = f.sandboxes[i]!;
      for (const action of targets) {
        const promise = authorizeServiceAction(principal, action, {
          sandboxId: row.sandbox.id,
          operationKind: "RUN_COMMAND",
        });
        if (i === mine) await expect(promise, action).resolves.toBeDefined();
        else await expect(promise).rejects.toMatchObject({ code: "FORBIDDEN" });
      }
      const read = authorizeServiceAction(principal, "operations.get", {
        operationId: row.operation.id,
      });
      if (i === mine) await expect(read).resolves.toBeDefined();
      else await expect(read).rejects.toMatchObject({ code: "FORBIDDEN" });
    }
  }
});
it("the same creator filter holds through actual Hono handlers and MCP services", async () => {
  const f = await fixture();
  const app = new Hono().route("/v1", createSandboxApi());
  const headers = {
    authorization: `Bearer ${f.api.secret}`,
    "content-type": "application/json",
    "idempotency-key": randomUUID(),
  };
  const sibling = f.sandboxes[2]!.sandbox.id;
  const listed = await app.request("/v1/sandboxes", { headers });
  expect(listed.status).toBe(200);
  expect(
    ((await listed.json()) as { items: { id: string }[] }).items.map((s: { id: string }) => s.id),
  ).toEqual([f.sandboxes[0]!.sandbox.id]);
  const mcpList = await callMcpTool(f.m, "sandbox_list", {});
  expect(mcpList).toMatchObject({
    structuredContent: { result: { items: [{ id: f.sandboxes[1]!.sandbox.id }] } },
  });
  for (const [method, path, body] of [
    ["GET", `/sandboxes/${sibling}`, undefined],
    ["POST", `/sandboxes/${sibling}/commands`, { script: "true" }],
    ["POST", `/sandboxes/${sibling}/files/download`, { path: "/tmp/test" }],
    ["POST", `/sandboxes/${sibling}/stop`, {}],
    ["DELETE", `/sandboxes/${sibling}`, {}],
  ] as const) {
    const response = await app.request(`/v1${path}`, {
      method,
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    expect(response.status, path).toBe(403);
  }
  for (const [name, args] of [
    ["sandbox_get", { id: sibling }],
    ["command_start", { id: sibling, script: "true" }],
    ["file_read", { id: sibling, path: "/tmp/test" }],
    ["file_write", { id: sibling, path: "/tmp/test", content: "hi" }],
    ["sandbox_stop", { id: sibling }],
    ["sandbox_destroy", { id: sibling }],
  ] as const)
    expect(await callMcpTool(f.m, name, args), name).toMatchObject({
      isError: true,
      structuredContent: { error: { code: "FORBIDDEN" } },
    });
});
it("opting out exposes every owned sandbox in SQL, native gates and MCP listing", async () => {
  const f = await fixture(false);
  for (const principal of [f.p, f.m]) {
    expect((await listSandboxes(principal, { limit: 100 })).items).toHaveLength(3);
    for (const row of f.sandboxes)
      for (const action of targets)
        await expect(
          authorizeServiceAction(principal, action, {
            sandboxId: row.sandbox.id,
            operationKind: "RUN_COMMAND",
          }),
        ).resolves.toBeDefined();
  }
  const result = await callMcpTool(f.m, "sandbox_list", {});
  expect(result).toMatchObject({ structuredContent: { result: { items: expect.any(Array) } } });
  if (!result.structuredContent || !("result" in result.structuredContent))
    throw new Error("listing failed");
  expect((result.structuredContent.result as { items: unknown[] }).items).toHaveLength(3);
});
it("an ALLOWLIST host grant admits X and refuses another owned host Y for every host action", async () => {
  const owner = await person();
  const x = await seedLaunchHost(db.inspect, {
    data: { userId: owner.ownerId, slug: "x", label: "X" },
  });
  const y = await seedLaunchHost(db.inspect, {
    data: { userId: owner.ownerId, slug: "y", label: "Y" },
  });
  const minted = await createSdkKey(owner, {
    name: "Host only",
    scopes: ["hosts:read", "hosts:execute", "hosts:files"],
    resourceMode: "ALLOWLIST",
    hostIds: [x.id],
    templateRevisionIds: [],
  });
  const p = await authenticateSdkKeySecret(minted.secret);
  if (!p) throw new Error("fixture inactive");
  for (const action of [
    "hosts.get",
    "hostCommands.run",
    "hostCommands.get",
    "hostCommands.writeStdin",
    "hostCommands.cancel",
    "hostCommands.queue",
    "hostFiles.read",
    "hostFiles.list",
    "hostFiles.write",
    "hostFiles.edit",
  ] as const) {
    await expect(authorizeServiceAction(p, action, { sandboxHostId: x.id })).resolves.toBeDefined();
    await expect(authorizeServiceAction(p, action, { sandboxHostId: y.id })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
  }
});

it.each(["ALL_OWNED", "ALLOWLIST"] as const)(
  "%s B credentials cannot acquire physical host access through A's pool contribution, via HTTP or MCP",
  async (mode) => {
    const a = await fixture();
    const b = await person();
    const hostB = await seedLaunchHost(db.inspect, {
      data: { userId: b.ownerId, slug: "own-b", label: "B" },
    });
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: b.ownerId, slug: "shared", label: "Shared" },
    });
    const share = await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: b.ownerId,
        granteeUserId: a.owner.ownerId,
        canUse: true,
        canContribute: true,
      },
    });
    await db.inspect.sandboxPoolMember.create({
      data: {
        userId: b.ownerId,
        poolId: pool.id,
        sandboxHostId: a.host.id,
        hostOwnerId: a.owner.ownerId,
        shareId: share.id,
        contributeWitness: true,
        ownHostsOnlyWitness: false,
        enabled: true,
      },
    });
    const k = await key(b, false);
    if (mode === "ALLOWLIST") {
      // Adversarial persisted grant: even a direct foreign-host allowlist row
      // cannot bypass DB ownership. Normal minting refuses this selection.
      for (const id of [k.p.keyId, k.m.keyId]) {
        await db.inspect.sdkKey.update({ where: { id }, data: { resourceMode: "ALLOWLIST" } });
        await db.inspect.sdkKeyHostAllowlist.createMany({
          data: [
            { sdkKeyId: id, sandboxHostId: a.host.id },
            { sdkKeyId: id, sandboxHostId: hostB.id },
          ],
        });
      }
    }
    const app = new Hono().route("/v1", createSandboxApi());
    for (const [path, body] of [
      [`/hosts/${a.host.id}/commands`, { script: "true" }],
      [`/hosts/${a.host.id}/files/read`, { path: "/tmp/test" }],
      [`/hosts/${a.host.id}/files/write`, { path: "/tmp/test", content: "hi" }],
      [`/hosts/${a.host.id}/queued-commands`, { command: "true", reason: "review" }],
    ] as const) {
      const response = await app.request(`/v1${path}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${k.api.secret}`,
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
        },
        body: JSON.stringify(body),
      });
      expect(response.status, path).toBe(403);
    }
    const list = await callMcpTool(k.m, "host_list", {});
    expect(list).toMatchObject({ structuredContent: { result: { items: [{ id: hostB.id }] } } });
    if (!list.structuredContent || !("result" in list.structuredContent))
      throw new Error("host_list failed");
    expect(
      (list.structuredContent.result as { items: { id: string }[] }).items.map((host) => host.id),
    ).not.toContain(a.host.id);
    for (const [name, input] of [
      ["host_command_run", { hostId: a.host.id, script: "true" }],
      ["host_file_read", { hostId: a.host.id, path: "/tmp/test" }],
      ["host_file_write", { hostId: a.host.id, path: "/tmp/test", content: "hi" }],
      ["host_command_queue", { hostId: a.host.id, command: "true", reason: "review" }],
    ] as const) {
      const result = await callMcpTool(k.m, name, input);
      expect(result, name).toMatchObject({
        isError: true,
        structuredContent: {
          error: { code: expect.stringMatching(/^(FORBIDDEN|host.not_owned)$/) },
        },
      });
    }
    const session = await db.inspect.session.create({
      data: { userId: b.ownerId, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
    });
    const { mintHostTerminalTicket } = await import(
      "../../../../packages/api/src/sandbox/host-terminal-tickets"
    );
    await expect(
      mintHostTerminalTicket(
        { userId: b.ownerId, sessionId: session.id },
        { hostId: a.host.id, rows: 24, cols: 80 },
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(await callMcpTool(k.m, "host_terminal_open", { hostId: a.host.id })).toEqual({
      content: [{ type: "text", text: "Tool host_terminal_open not found" }],
      isError: true,
    });
    const terminal = await app.request(`/v1/hosts/${a.host.id}/terminal`, {
      method: "POST",
      headers: { authorization: `Bearer ${k.api.secret}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(terminal.status).toBe(404);
    expect(
      await db.inspect.hostAuditEvent.count({
        where: { userId: b.ownerId, sandboxHostId: a.host.id },
      }),
    ).toBe(0);
  },
);
