import { createRouterClient } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

// Mutable env mock — emailEnabled reads SMTP_HOST/SMTP_FROM (via the mailer's
// isEmailConfigured, mocked below against this same object) at call time, so
// flipping them between tests exercises both branches of the flag.
const envMock = {
  SMTP_HOST: undefined as string | undefined,
  SMTP_FROM: undefined as string | undefined,
  SIGNUP_ENABLED: true,
  RATE_LIMIT_AUTH_POINTS: 30,
  RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
  RATE_LIMIT_RPC_POINTS: 100,
  RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
  RATE_LIMIT_EMAIL_POINTS: 3,
  RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
};
const adminEmailsMock = new Set<string>();
vi.mock("@wssp/env/server", () => ({
  env: envMock,
  get SIGNUP_ENABLED() {
    return envMock.SIGNUP_ENABLED;
  },
  ADMIN_EMAILS: adminEmailsMock,
}));

// `@wssp/env/shared` VALIDATES process.env at module load and throws when it
// is empty — which is exactly CI. The backup-freshness helper reads it, so
// importing the full router graph pulls it in. Same module-load boundary
// rule as the queue mock below.
vi.mock("@wssp/env/shared", () => ({
  env: {},
}));

// Mock @wssp/db so importing the full appRouter graph never touches Postgres.
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

// @wssp/queue opens IORedis sockets at import time — mock every producer the
// import graph touches or the suite hangs in CI (no Redis). See
// Never open a real socket from a unit test.
vi.mock("@wssp/queue", () => {
  const fakeQueue = { add: vi.fn() };
  return {
    reapExpiredAuthTokensQueue: fakeQueue,
    imageStoreMaintenanceQueue: {
      add: vi.fn(),
      upsertJobScheduler: vi.fn(),
      removeJobScheduler: vi.fn(),
    },
    checkBackupFreshnessQueue: fakeQueue,
    webhookDeliveryQueue: fakeQueue,
    reapWebhookLogQueue: fakeQueue,
    notifyDataDeletionsQueue: fakeQueue,
    ensureRunnableJob: vi.fn(),
    QUEUE_NAMES: {},
    redisConnection: {},
  };
});

// @wssp/auth builds the Better-Auth instance (prismaAdapter, plugins) at
// import time — stub it so the graph loads without that machinery.
vi.mock("@wssp/auth", () => ({
  auth: { api: {} },
}));

// @wssp/mailer would open SMTP — stub the surface the import graph uses.
// isEmailConfigured mirrors the real implementation against the env mock.
vi.mock("@wssp/mailer", () => ({
  sendEmail: vi.fn(),
  renderInviteUser: vi.fn(() => ({ subject: "", html: "" })),
  verifyTransport: vi.fn(async () => false),
  isEmailConfigured: () => Boolean(envMock.SMTP_HOST && envMock.SMTP_FROM),
}));

const { appRouter } = await import("./index");

const publicContext: Context = { session: null };

describe("health", () => {
  it("exposes only the cheap check — no RPC readiness probe on the datastore", () => {
    // A DB-touching `ready` procedure was removed as an anonymous
    // datastore-drain vector bounded only by the generic /rpc limiter;
    // readiness is the HTTP /ready route with its own readyLimiter bucket.
    expect(Object.keys(appRouter.health)).toEqual(["check"]);
  });

  it("answers check without a session", async () => {
    const client = createRouterClient(appRouter, { context: publicContext });

    await expect(client.health.check()).resolves.toBe("OK");
  });
});

describe("appConfig", () => {
  beforeEach(() => {
    envMock.SMTP_HOST = undefined;
    envMock.SMTP_FROM = undefined;
    envMock.SIGNUP_ENABLED = true;
    adminEmailsMock.clear();
  });

  it("reports emailEnabled=false when SMTP_HOST is unset", async () => {
    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.emailEnabled).toBe(false);
  });

  it("reports emailEnabled=true when SMTP_HOST and SMTP_FROM are configured", async () => {
    envMock.SMTP_HOST = "smtp.example.com";
    envMock.SMTP_FROM = "App <no-reply@example.com>";
    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.emailEnabled).toBe(true);
  });

  it("reports emailEnabled=false when SMTP_HOST is set without SMTP_FROM", async () => {
    envMock.SMTP_HOST = "smtp.example.com";
    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.emailEnabled).toBe(false);
  });

  it("surfaces signup flags alongside emailEnabled", async () => {
    envMock.SIGNUP_ENABLED = false;
    envMock.SMTP_HOST = "smtp.example.com";
    envMock.SMTP_FROM = "App <no-reply@example.com>";

    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config).toEqual({
      signupEnabled: false,
      adminBootstrapSignupEnabled: false,
      emailEnabled: true,
    });
  });

  it("surfaces the admin bootstrap signup carve-out when signup is otherwise disabled", async () => {
    envMock.SIGNUP_ENABLED = false;
    adminEmailsMock.add("admin@example.com");

    const client = createRouterClient(appRouter, { context: publicContext });
    const config = await client.appConfig();

    expect(config.adminBootstrapSignupEnabled).toBe(true);
  });
});

it("hides every mounted administrative procedure before input validation", async () => {
  const adminProcedures = {
    ...Object.fromEntries(
      Object.entries(appRouter.users).map(([name, procedure]) => [`users.${name}`, procedure]),
    ),
    ...Object.fromEntries(
      Object.entries(appRouter.queue).map(([name, procedure]) => [`queue.${name}`, procedure]),
    ),
    ...Object.fromEntries(
      Object.entries(appRouter.adminObservability).map(([name, procedure]) => [
        `adminObservability.${name}`,
        procedure,
      ]),
    ),
    "settings.update": appRouter.settings.update,
    "settings.adminGet": appRouter.settings.adminGet,
    "push.send": appRouter.push.send,
  };
  const client = createRouterClient(adminProcedures, { context: publicContext });
  const names = Object.keys(adminProcedures);
  expect(names.length).toBeGreaterThan(10);
  for (const name of names) {
    const procedure: unknown = Reflect.get(client, name);
    if (typeof procedure !== "function") throw new Error(`Missing admin procedure: ${name}`);
    // No input: a public/weak builder would leak BAD_REQUEST or invoke IO.
    await expect(Reflect.apply(procedure, undefined, [])).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  }
});
