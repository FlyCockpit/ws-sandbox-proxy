import { readFileSync } from "node:fs";
import { createRouterClient } from "@orpc/server";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "person-matrix-fixture" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
const { agentTokensRouter } = await import("./agent-tokens");
const { sdkKeysRouter } = await import("./sdk-keys");
const { mcpGrantsRouter } = await import("./mcp-grants");
const { hostQueuedCommandsRouter } = await import("./host-queued-commands");
const { hostTerminalsRouter } = await import("./host-terminals");
const { sandboxHostsRouter } = await import("./sandbox-hosts");
const { MCP_TOOLS } = await import("../mcp/tool-contracts");
const { authorizeSessionManagement } = await import("../lib/sdk-key-access");
const { SERVICE_SCOPES } = await import("../lib/service-scopes");

it.each(["API", "AGENT_TOKEN", "OAUTH_GRANT"] as const)(
  "%s with every scope is refused person management",
  (kind) => {
    expect(() =>
      authorizeSessionManagement({
        kind: "sdkKey",
        credentialKind: kind,
        keyId: "key",
        ownerId: "owner",
        expiresAt: null,
        resourceMode: "ALL_OWNED",
        ownSandboxesOnly: false,
        scopes: new Set(SERVICE_SCOPES),
        allowedHostIds: "allOwned",
        allowedRevisionIds: "allOwned",
        allowedPoolIds: "allUsable",
      }),
    ).toThrowError(expect.objectContaining({ code: "FORBIDDEN" }));
  },
);
it("every person-only procedure refuses a credential without a cookie session, before input or service work", async () => {
  const context = { session: null };
  const groups = [
    agentTokensRouter,
    sdkKeysRouter,
    mcpGrantsRouter,
    hostQueuedCommandsRouter,
    hostTerminalsRouter,
    {
      lowerAgentHostCommands: sandboxHostsRouter.lowerAgentHostCommands,
      lowerHostTerminal: sandboxHostsRouter.lowerHostTerminal,
    },
  ];
  let checked = 0;
  for (const router of groups) {
    const client = createRouterClient(router, { context }) as Record<
      string,
      (input: unknown) => Promise<unknown>
    >;
    for (const name of Object.keys(router)) {
      await expect(client[name]!({}), name).rejects.toMatchObject({ code: "UNAUTHORIZED" });
      checked++;
    }
  }
  expect(checked).toBe(16);
});
it("pins the registered person builders and forbids management/terminal tool exposure", () => {
  for (const file of [
    "agent-tokens",
    "sdk-keys",
    "mcp-grants",
    "host-queued-commands",
    "host-terminals",
  ]) {
    const source = readFileSync(new URL(`./${file}.ts`, import.meta.url), "utf8");
    const builders = [...source.matchAll(/\w+:\s*(\w+Procedure)/g)].map((match) => match[1]);
    expect(builders.length, file).toBeGreaterThan(0);
    for (const builder of builders)
      expect(["protectedProcedure", "liveOwnerSessionProcedure"], file).toContain(builder);
  }
  const hosts = readFileSync(new URL("./sandbox-hosts.ts", import.meta.url), "utf8");
  for (const lower of ["lowerAgentHostCommands", "lowerHostTerminal"])
    expect(hosts).toMatch(new RegExp(`${lower}: liveOwnerSessionProcedure`));
  expect(hosts).not.toMatch(/(?:raiseAgentHostCommands|setAgentHostCommands|raiseHostTerminal):/);
  for (const tool of MCP_TOOLS) {
    expect(tool.name).not.toMatch(/token|key|grant|terminal|lower|raise|queue_(?:run|dismiss)/);
    for (const action of tool.actions)
      expect(action).not.toMatch(
        /agentTokens|sdkKeys|mcpGrants|hostTerminals|lower|raise|QueuedCommands\.(run|dismiss)/,
      );
  }
});
