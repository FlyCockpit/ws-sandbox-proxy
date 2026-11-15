import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "host-policy-matrix",
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_MAX_HOSTS_PER_OWNER: null,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, imageStoreMaintenanceQueue: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/api/lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("../mcp-rate-limit", () => ({
  consumeMcpCreateQuota: async () => {},
  consumeMcpHostCommandQuota: async () => {},
}));
const db = await pgTestDatabase();
const { sandboxRelaySessionManager: manager } = await import("./session-manager");
const { FakeNodeDaemon, fakeClock } = await import("./fake-node-daemon-harness");
const { bindHostAccess } = await import("../../../../packages/api/src/sandbox/host-access");
const { createHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
const { createAgentToken } = await import(
  "../../../../packages/api/src/sandbox/services/agent-tokens"
);
const { authenticateAgentTokenSecret } = await import("@wssp/api/lib/sdk-key-access");
const { callMcpTool } = await import("../mcp/tools");
let daemon: InstanceType<typeof FakeNodeDaemon> | undefined;
afterAll(async () => {
  await daemon?.crash();
  bindHostAccess(null);
  await manager.dispose();
  await db.close();
});
it("commands and every file tool obey off/on and the durable dashboard veto through MCP with the real relay", async () => {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Owner",
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const owner = { kind: "session" as const, ownerId: id };
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "host", label: "Host" },
  });
  const token = await createHostToken(owner, { hostId: host.id, name: "Daemon" });
  const key = await createAgentToken(owner, {
    name: "Agent",
    scopes: ["hosts:execute", "hosts:files"],
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly: true,
    expiresAt: new Date(Date.now() + 86400000),
  });
  const p = await authenticateAgentTokenSecret(key.secret);
  if (!p) throw new Error("inactive fixture");
  daemon = new FakeNodeDaemon(
    manager,
    {
      hostId: host.id,
      userId: id,
      tokenId: token.token.id,
      credentialKind: "hostToken",
      expiresAt: null,
    },
    fakeClock(),
    { admission: true },
  );
  daemon.agentPolicy = {
    hostCommands: false,
    hostFiles: false,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 1,
  };
  bindHostAccess(manager.hostAccess);
  await daemon.connect();
  await daemon.idle();
  const cases = [
    ["host_command_run", { hostId: host.id, script: "true" }],
    ["host_file_read", { hostId: host.id, path: "/srv/test" }],
    ["host_file_list", { hostId: host.id, path: "/srv" }],
    ["host_file_write", { hostId: host.id, path: "/srv/test", content: "hi", createOnly: true }],
    [
      "host_file_edit",
      { hostId: host.id, path: "/srv/test", edits: [{ oldText: "hi", newText: "hello" }] },
    ],
  ] as const;
  for (const [name, input] of cases)
    expect(await callMcpTool(p, name, input), name).toMatchObject({
      isError: true,
      structuredContent: { error: { code: "host.agent_access_off", retryable: false } },
    });
  expect(
    daemon.received.filter((f) => f.type === "host.exec.start" || f.type === "host.file.request"),
  ).toHaveLength(0);
  daemon.agentPolicy = {
    ...daemon.agentPolicy,
    hostCommands: true,
    hostFiles: true,
    agentPolicyRevision: 2,
  };
  await daemon.reportAgentPolicy();
  await daemon.idle();
  for (const [name, input] of cases)
    await callMcpTool(p, name, name === "host_command_run" ? { ...input, waitMs: 0 } : input);
  expect(daemon.received.some((f) => f.type === "host.exec.start")).toBe(true);
  expect(
    daemon.received
      .filter((f) => f.type === "host.file.request")
      .map((f) => f.op)
      .sort(),
  ).toEqual(["edit", "list", "read", "write"]);
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { agentHostCommandsVetoedAt: new Date() },
  });
  const dispatched = daemon.received.filter(
    (f) => f.type === "host.exec.start" || f.type === "host.file.request",
  ).length;
  for (const [name, input] of cases)
    expect(await callMcpTool(p, name, input), name).toMatchObject({
      isError: true,
      structuredContent: { error: { code: "host.agent_access_off", retryable: false } },
    });
  expect(daemon.agentPolicy.hostCommands).toBe(true);
  expect(
    daemon.received.filter((f) => f.type === "host.exec.start" || f.type === "host.file.request"),
  ).toHaveLength(dispatched);
});
