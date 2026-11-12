import { describe, expect, it, vi } from "vitest";

// Review M1: the external worker validates only @wssp/env/shared. If anything
// the webhook path imports reached @wssp/env/server, the worker would crash at
// load. Make that import fail loudly, then load the real modules.
vi.mock("@wssp/env/server", () => {
  throw new Error("webhook worker graph imported @wssp/env/server");
});
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", async () => ({
  ...(await import("@wssp/queue/jobs")),
  webhookDeliveryQueue: {},
  reapWebhookLogQueue: {},
}));

describe("webhook worker import graph", () => {
  it("never reaches @wssp/env/server", async () => {
    await expect(import("./handlers/deliver-webhook")).resolves.toBeDefined();
    await expect(import("./handlers/reap-webhook-log")).resolves.toBeDefined();
    await expect(import("./webhook-dispatcher")).resolves.toBeDefined();
    await expect(import("@wssp/api/webhooks/render")).resolves.toBeDefined();
    await expect(import("@wssp/api/webhooks/deliver")).resolves.toBeDefined();
  });
});
