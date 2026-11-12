import { createRouterClient } from "@orpc/server";
import { describe, expect, it, vi } from "vitest";
import type { Context } from "../context";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "webhooks-router-test" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { webhooksRouter } = await import("./webhooks");

describe("webhooks router (unit; real services: webhooks.pg.test.ts, webhook-ledger.pg.test.ts)", () => {
  it("exposes exactly the endpoint and delivery procedures plus the configuration probe", () => {
    expect(Object.keys(webhooksRouter).sort()).toEqual(
      [
        "status",
        "list",
        "get",
        "create",
        "update",
        "delete",
        "rotateSecret",
        "test",
        "listDeliveries",
        "getDelivery",
        "redeliver",
      ].sort(),
    );
  });

  it("refuses every procedure without a session", async () => {
    const client = createRouterClient(webhooksRouter, {
      context: { session: null } as unknown as Context,
    });
    for (const call of [
      () => client.status(),
      () => client.list({ limit: 1 }),
      () => client.create({ url: "https://hooks.example.com/x", events: ["sandbox.ready"] }),
      () => client.test({ id: "whe-1" }),
      () => client.redeliver({ id: "whd-1" }),
    ])
      await expect(call()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});
