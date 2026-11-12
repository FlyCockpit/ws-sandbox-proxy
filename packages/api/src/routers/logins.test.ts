import { readFileSync } from "node:fs";
import { createRouterClient } from "@orpc/server";
import { describe, expect, it, vi } from "vitest";
import type { Context } from "../context";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "logins-router-test" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { loginsRouter } = await import("./logins");

/** Procedures that must run on the durable, non-impersonated owner session. */
const LIVE_OWNER = ["createLogin", "updateLoginPolicy", "repinLogin"];

describe("logins router (unit; real services: credentials/service.pg.test.ts)", () => {
  it("every procedure refuses without a session", async () => {
    const client = createRouterClient(loginsRouter, {
      context: { session: null } as unknown as Context,
    });
    for (const call of [
      () => client.status(),
      () => client.listLogins({ limit: 1 }),
      () => client.createDefinition({ text: "{}" }),
      () => client.createLogin({ name: "x", definitionId: "d" }),
      () => client.repinLogin({ id: "c", definitionId: "d" }),
      () => client.writeValue({ credentialId: "c", instanceId: "i", env: { A: "b" } }),
      () => client.getLoginSession({ id: "s" }),
      () => client.finishLogin({ id: "s" }),
      () => client.cancelLogin({ id: "s" }),
    ])
      await expect(call()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("delivery, policy and re-pin use liveOwnerSessionProcedure; the rest protectedProcedure", () => {
    const source = readFileSync(new URL("./logins.ts", import.meta.url), "utf8");
    for (const name of Object.keys(loginsRouter)) {
      const builder = new RegExp(`\\n  ${name}: (\\w+)`).exec(source)?.[1];
      expect(builder, name).toBe(
        LIVE_OWNER.includes(name) ? "liveOwnerSessionProcedure" : "protectedProcedure",
      );
    }
  });
});
