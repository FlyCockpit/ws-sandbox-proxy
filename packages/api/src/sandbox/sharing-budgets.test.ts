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
  calls: [] as [string, string][],
  counts: new Map<string, number>(),
}));
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: (options: (typeof state.configs)[number]) => {
    state.configs.push(options);
    return async (key: string) => {
      state.calls.push([options.keyPrefix, key]);
      const id = `${options.keyPrefix}:${key}`,
        count = (state.counts.get(id) ?? 0) + 1;
      state.counts.set(id, count);
      if (count > options.points) throw new ORPCError("TOO_MANY_REQUESTS");
    };
  },
}));
const { consumeInviteAccept, consumeInviteIssue, consumeSharingWrite } = await import(
  "./sharing-budgets"
);
it("charges minute/day/hashed recipient plus a separate nonrefundable 5/day signup issuer budget", async () => {
  // Spread across recipients so the issuer's allowance is the deciding bucket.
  for (let i = 0; i < 5; i++) {
    await consumeInviteIssue("issuer", `pool-${i}`, `person-${i}@example.test`, true);
    state.counts.set("pool-sharing-invite-minute:issuer", 0);
  }
  await expect(
    consumeInviteIssue("issuer", "pool-5", "person-5@example.test", true),
  ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  expect(state.configs).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        keyPrefix: "pool-sharing-invite-minute",
        points: 5,
        durationSeconds: 60,
      }),
      expect.objectContaining({
        keyPrefix: "pool-sharing-invite-day",
        points: 50,
        durationSeconds: 86400,
      }),
      expect.objectContaining({
        keyPrefix: "pool-sharing-invite-recipient",
        points: 3,
        durationSeconds: 3600,
      }),
    ]),
  );
  // Only the minute window advances; the daily issuer allowance never resets.
  expect(state.calls.filter(([name]) => name === "pool-sharing-signup-issuer")).toHaveLength(6);
  expect(JSON.stringify(state.calls)).not.toContain("@example.test");
});
it("resend shares issuance/recipient budgets without allocating a fresh signup allowance", async () => {
  await consumeInviteIssue("resender", "pool", "target@example.test", true);
  for (let i = 0; i < 2; i++)
    await consumeInviteIssue("resender", "pool", "target@example.test", false);
  await expect(
    consumeInviteIssue("resender", "pool", "target@example.test", false),
  ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  expect(
    state.calls.filter(
      ([name, key]) => name === "pool-sharing-signup-issuer" && key === "resender",
    ),
  ).toHaveLength(1);
});
it("invalid accept attempts share the actor's 10/minute budget; all sharing buckets fail closed without error text", async () => {
  for (let i = 0; i < 10; i++) await consumeInviteAccept("acceptor");
  await expect(consumeInviteAccept("acceptor")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  await consumeSharingWrite("writer");
  expect(state.configs.every((config) => config.failClosed && config.redactErrors)).toBe(true);
});
