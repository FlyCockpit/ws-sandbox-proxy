import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const { hostQueuedCommandsRouter } = await import("./host-queued-commands");
const { sandboxHostsRouter } = await import("./sandbox-hosts");
it("exposes only person decisions and lower-only host access controls", () => {
  expect(Object.keys(hostQueuedCommandsRouter).sort()).toEqual(["dismiss", "list", "run"]);
  expect(Object.keys(sandboxHostsRouter)).toContain("lowerAgentHostCommands");
  expect(Object.keys(sandboxHostsRouter)).toContain("lowerHostTerminal");
  expect(Object.keys(sandboxHostsRouter).filter((key) => /raise/i.test(key))).toEqual([]);
});
