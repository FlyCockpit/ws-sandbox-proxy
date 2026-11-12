vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

const { default: db } = await import("@wssp/db");
const { reserveLiveResources } = await import("@wssp/api/sandbox/host-admission");
const { createFenceStore, installFenceTransaction } = await import("./fenced-prisma-harness.js");

describe("host live slot reservation (transactional)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("refuses a third reservation at cap", async () => {
    const store = createFenceStore({
      hosts: [
        {
          id: "host-1",
          userId: "user-1",
          connectionEpoch: 1,

          daemonVcpuBudget: 2,
          liveCount: 0,
        },
      ],
      sandboxes: ["sbx-1", "sbx-2", "sbx-3"].map((id) => ({
        id,
        userId: "user-1",
        generation: 1,
        state: "REQUESTED",
        sandboxHostId: "host-1",
        liveResourcesHeld: false,
        templateId: "tpl-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      })),
    });
    installFenceTransaction(db as unknown as { $transaction: ReturnType<typeof vi.fn> }, store);

    for (const sandboxId of ["sbx-1", "sbx-2"]) {
      await db.$transaction(async (tx) => {
        await reserveLiveResources(tx, {
          hostId: "host-1",
          ownerId: "user-1",
          sandboxId,
        });
      });
    }

    await expect(
      db.$transaction(async (tx) => {
        await reserveLiveResources(tx, {
          hostId: "host-1",
          ownerId: "user-1",
          sandboxId: "sbx-3",
        });
      }),
    ).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "sandbox.host_capacity" },
    });
    expect(store.hosts.get("host-1")?.liveCount).toBe(2);
  });
});
