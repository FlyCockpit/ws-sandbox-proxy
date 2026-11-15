import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "host-poll-test" } }));
vi.mock("../budgets", () => ({ consumeSandboxWriteBudget: vi.fn() }));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => vi.fn() }));
// These cases exercise the poll/audit race; authorization has its own service tests.
vi.mock("../../lib/sdk-key-access", () => ({
  authorizeServiceAction: vi.fn(),
  serviceProcedure: (_rules: unknown, handler: unknown) => handler,
}));
const { default: db } = await import("@wssp/db");
const { bindHostAccess, hostAccessError } = await import("../host-access");
const { getHostCommand } = await import("./host-commands");
const principal = {
  kind: "sdkKey" as const,
  credentialKind: "API" as const,
  keyId: "key",
  ownerId: "owner",
  ownSandboxesOnly: false,
  expiresAt: null,
  resourceMode: "ALL_OWNED" as const,
  scopes: new Set(["hosts:execute"] as const),
  allowedHostIds: "allOwned" as const,
  allowedRevisionIds: "allOwned" as const,
  allowedPoolIds: "allUsable" as const,
};
const poll = vi.fn();
const input = { hostId: "host", commandId: "a".repeat(22) };
const row = { state: "running", exitCode: null, startedAt: new Date(1), finishedAt: null };
beforeEach(() => {
  vi.clearAllMocks();
  bindHostAccess({
    read: () => null,
    start: vi.fn(),
    poll,
    stdin: vi.fn(),
    cancel: vi.fn(),
    file: vi.fn(),
    lower: vi.fn(),
  });
});
afterEach(() => bindHostAccess(null));
it.each(["host.agent_access_off", "host.node_offline"] as const)(
  "rereads the audit after %s races the first read",
  async (code) => {
    db.hostAuditEvent.findFirst
      .mockResolvedValueOnce(row as never)
      .mockResolvedValueOnce({ ...row, state: "cancelled", finishedAt: new Date(2) } as never);
    poll.mockRejectedValue(hostAccessError(code));
    await expect(getHostCommand(principal, input)).resolves.toMatchObject({
      state: "cancelled",
      finishedAt: 2,
      stdout: { data: "" },
      stderr: { data: "" },
    });
    expect(db.hostAuditEvent.findFirst).toHaveBeenCalledTimes(2);
  },
);
it.each(["host.agent_access_off", "host.node_offline"] as const)(
  "preserves %s when the command is still running",
  async (code) => {
    db.hostAuditEvent.findFirst.mockResolvedValue(row as never);
    poll.mockRejectedValue(hostAccessError(code));
    await expect(getHostCommand(principal, input)).rejects.toMatchObject({ data: { code } });
  },
);
