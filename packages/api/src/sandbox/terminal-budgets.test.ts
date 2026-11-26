import { ORPCError } from "@orpc/server";
import { expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  configs: [] as {
    keyPrefix: string;
    points: number;
    durationSeconds: number;
    failClosed: boolean;
    redactErrors: boolean;
  }[],
  calls: [] as string[],
  counts: new Map<string, number>(),
  unavailable: false,
}));
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: (options: (typeof state.configs)[number]) => {
    state.configs.push(options);
    return async (key: string) => {
      const bucket = `${options.keyPrefix}:${key}`;
      state.calls.push(bucket);
      if (state.unavailable) throw new ORPCError("SERVICE_UNAVAILABLE");
      const count = (state.counts.get(bucket) ?? 0) + 1;
      state.counts.set(bucket, count);
      if (count > options.points) throw new ORPCError("TOO_MANY_REQUESTS");
    };
  },
}));
const { consumeHostProofBudget, consumeTerminalEndBudget, consumeTerminalMintBudget } =
  await import("./terminal-budgets");
it("charges day then minute per durable user across every host/session/IP/batched procedure", async () => {
  for (let i = 0; i < 5; i++) await consumeHostProofBudget("actor");
  await expect(consumeHostProofBudget("actor")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  expect(state.calls.slice(-2)).toEqual([
    "host-terminal-proof-day:uid:actor",
    "host-terminal-proof-minute:uid:actor",
  ]);
  for (let i = 0; i < 14; i++) {
    state.counts.set("host-terminal-proof-minute:uid:actor", 0);
    await consumeHostProofBudget("actor");
  }
  state.counts.set("host-terminal-proof-minute:uid:actor", 0);
  await expect(consumeHostProofBudget("actor")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  await consumeHostProofBudget("other-user");
  expect(state.configs).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ points: 5, durationSeconds: 60 }),
      expect.objectContaining({ points: 20, durationSeconds: 86400 }),
    ]),
  );
  expect(state.configs.every((c) => c.failClosed && c.redactErrors)).toBe(true);
});
it("generic mints share 20/minute across host/guest and dependency uncertainty refuses", async () => {
  for (let i = 0; i < 20; i++) await consumeTerminalMintBudget("uid:actor");
  await expect(consumeTerminalMintBudget("uid:actor")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  state.unavailable = true;
  await expect(consumeHostProofBudget("fresh")).rejects.toMatchObject({
    code: "SERVICE_UNAVAILABLE",
  });
});

it("Terminals page ends share 30/minute per user and refuse when the limiter is down", async () => {
  state.unavailable = false;
  for (let i = 0; i < 30; i++) await consumeTerminalEndBudget("uid:ender");
  await expect(consumeTerminalEndBudget("uid:ender")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  await consumeTerminalEndBudget("uid:someone-else");
  expect(state.configs).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ keyPrefix: "terminal-end", points: 30, durationSeconds: 60 }),
    ]),
  );
  state.unavailable = true;
  await expect(consumeTerminalEndBudget("uid:fresh")).rejects.toMatchObject({
    code: "SERVICE_UNAVAILABLE",
  });
  state.unavailable = false;
});
