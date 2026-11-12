import { expect, it, vi } from "vitest";
import type { ProcedureBudgetOptions } from "../lib/procedure-budget";

const { configured, consumed } = vi.hoisted(() => ({
  configured: [] as ProcedureBudgetOptions[],
  consumed: vi.fn(async (_key: string) => {}),
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_CREATE_CONNECT_BUDGET_POINTS: 300,
    SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
  },
}));
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: (options: ProcedureBudgetOptions) => {
    configured.push(options);
    return consumed;
  },
}));
const { consumeCreateConnectBudget, consumeSandboxWriteBudget } = await import("./budgets");
it("create/connect share one finite fail-closed owner procedure bucket; every retry consumes it", async () => {
  await consumeCreateConnectBudget("owner");
  await consumeCreateConnectBudget("owner");
  expect(configured).toHaveLength(1);
  expect(configured[0]).toMatchObject({
    keyPrefix: "sandbox-create-connect",
    points: 300,
    durationSeconds: 60,
    failClosed: true,
    redactErrors: true,
  });
  expect(consumed.mock.calls).toEqual([["uid:owner"], ["uid:owner"]]);
  await consumeSandboxWriteBudget("owner", "lease");
  await consumeSandboxWriteBudget("owner", "template");
  await consumeSandboxWriteBudget("owner", "tag");
  expect(
    configured
      .slice(1)
      .map(({ keyPrefix, points, durationSeconds }) => ({ keyPrefix, points, durationSeconds })),
  ).toEqual([
    { keyPrefix: "sandbox-lease", points: 100, durationSeconds: 60 },
    { keyPrefix: "sandbox-template", points: 100, durationSeconds: 60 },
    { keyPrefix: "sandbox-tag", points: 100, durationSeconds: 60 },
  ]);
});

it("ordinary100/stdin600/termination30 are separately keyed, owner scoped, fail closed and RPC-scaled", async () => {
  const { consumeSandboxWriteBudget } = await import("./budgets");
  const start = configured.length;
  for (const family of ["ordinary", "stdin", "termination"] as const)
    await consumeSandboxWriteBudget("operator", family);
  expect(configured.slice(start)).toMatchObject([
    {
      keyPrefix: "sandbox-ordinary",
      points: 100,
      durationSeconds: 60,
      failClosed: true,
      redactErrors: true,
    },
    {
      keyPrefix: "sandbox-stdin",
      points: 600,
      durationSeconds: 60,
      failClosed: true,
      redactErrors: true,
    },
    {
      keyPrefix: "sandbox-termination",
      points: 30,
      durationSeconds: 60,
      failClosed: true,
      redactErrors: true,
    },
  ]);
  expect(consumed.mock.calls.slice(-3)).toEqual([
    ["uid:operator"],
    ["uid:operator"],
    ["uid:operator"],
  ]);
  // Four sandboxes × five iterations × (3 stat/exists + run + list).
  expect(4 * 5 * (3 + 1 + 1)).toBe(configured[start]!.points);
});

it("all three procedure families scale together independently of absolute HTTP budgets", async () => {
  vi.resetModules();
  const { env } = await import("@wssp/env/server");
  env.RATE_LIMIT_RPC_POINTS = 250;
  env.RATE_LIMIT_RPC_WINDOW_SECONDS = 120;
  const { consumeSandboxWriteBudget } = await import("./budgets");
  const start = configured.length;
  for (const family of ["ordinary", "stdin", "termination"] as const)
    await consumeSandboxWriteBudget("scaled", family);
  expect(
    configured.slice(start).map(({ points, durationSeconds }) => [points, durationSeconds]),
  ).toEqual([
    [250, 120],
    [1500, 120],
    [75, 120],
  ]);
});
