import { beforeEach, expect, it, vi } from "vitest";
import { deviceRow, deviceStore, gate } from "./device-code-test-harness";

vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
const { default: prisma } = await import("@wssp/db");
const { transitionDeviceCode } = await import("./device-code-transitions");
let store: ReturnType<typeof deviceStore>;
const decide = (action: "claim" | "approve" | "deny", userId = "user-1") =>
  transitionDeviceCode({ userCode: "ABCD-EFGH", userId, action, intent: { kind: "create" } });
beforeEach(() => {
  store = deviceStore();
  Object.assign(prisma, store.db);
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending" }));
  store.state.user.set("user-1", { id: "user-1" });
  store.state.user.set("user-2", { id: "user-2" });
});
it.each(["approve", "deny"] as const)(
  "interleaved %s cannot overwrite a committed opposite decision",
  async (action) => {
    const reached = gate(),
      release = gate();
    let first = true;
    store.hooks.beforeLock = async () => {
      if (first) {
        first = false;
        reached.open();
        await release.promise;
      }
    };
    const delayed = decide(action);
    await reached.promise;
    await decide(action === "approve" ? "deny" : "approve");
    release.open();
    await expect(delayed).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.state.deviceCode.get("code-1")?.status).toBe(
      action === "approve" ? "denied" : "approved",
    );
  },
);
it("competing claims cannot change the winning owner", async () => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
  const results = await Promise.allSettled([decide("claim"), decide("claim", "user-2")]);
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  expect(store.state.deviceCode.get("code-1")?.userId).toBe("user-1");
});
it("approval persists exactly the displayed replacement identity", async () => {
  await transitionDeviceCode({
    userCode: "ABCDEFGH",
    userId: "user-1",
    action: "approve",
    intent: { kind: "replace", hostId: "host-reviewed" },
  });
  expect(store.state.deviceCode.get("code-1")).toMatchObject({
    status: "approved",
    enrollmentIntent: "replace",
    replaceHostId: "host-reviewed",
  });
});
it.each(["claim", "approve", "deny"] as const)("expiry after waiting blocks %s", async (action) => {
  store.hooks.beforeLock = async () => {
    store.now = new Date("2026-07-01T00:11:00Z");
  };
  await expect(decide(action)).rejects.toMatchObject({ code: "CONFLICT" });
  expect(store.state.deviceCode.get("code-1")?.status).toBe("pending");
});
it("unclaimed approval and missing requests cannot succeed", async () => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
  await expect(decide("approve")).rejects.toMatchObject({ code: "BAD_REQUEST" });
  store.state.deviceCode.clear();
  await expect(decide("claim")).rejects.toMatchObject({ code: "CONFLICT" });
});

it("unknown and expired claim failures share the same CONFLICT message", async () => {
  store.state.deviceCode.clear();
  const unknown = await decide("claim").catch((error: { message?: string }) => error);
  store.state.deviceCode.set(
    "code-1",
    deviceRow({ status: "pending", userId: null, expiresAt: new Date("2026-06-01") }),
  );
  store.hooks.beforeLock = async () => {
    store.now = new Date("2026-07-01T00:11:00Z");
  };
  const expired = await decide("claim").catch((error: { message?: string }) => error);
  expect(unknown).toMatchObject({
    code: "CONFLICT",
    message: "Device request is no longer available.",
  });
  expect(expired).toMatchObject({
    code: "CONFLICT",
    message: "Device request is no longer available.",
  });
});

it("concurrent same-owner claims succeed idempotently and Deny remains available", async () => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
  const reached = gate(),
    release = gate();
  let first = true;
  store.hooks.beforeLock = async () => {
    if (first) {
      first = false;
      reached.open();
      await release.promise;
    }
  };
  const delayed = decide("claim");
  await reached.promise;
  await expect(decide("claim")).resolves.toEqual({ success: true, deviceRequestId: "code-1" });
  release.open();
  await expect(delayed).resolves.toEqual({ success: true, deviceRequestId: "code-1" });
  await expect(decide("claim")).resolves.toEqual({ success: true, deviceRequestId: "code-1" });
  await expect(decide("deny")).resolves.toEqual({ success: true, deviceRequestId: "code-1" });
  expect(store.state.deviceCode.get("code-1")?.status).toBe("denied");
  expect(store.events).not.toContain("lock:user:user-1");
});

it.each(["P2034", "40P01", "40001"])(
  "claim maps %s to a retryable device outcome",
  async (code) => {
    store.db.$transaction.mockRejectedValueOnce({ code });
    await expect(decide("claim")).rejects.toMatchObject({
      code: "SERVICE_UNAVAILABLE",
      data: { deviceFlowError: "authorization_pending" },
    });
  },
);

const grant = {
  access: "read",
  poolMode: "ALL_USABLE",
  poolIds: [],
  ownSandboxesOnly: false,
  maxLiveSandboxes: 3,
  expiresInDays: 30,
  name: "wssp login",
} as const;

it("user-login approval stores exactly the chosen grant and no enrollment intent", async () => {
  store.state.deviceCode.set(
    "code-1",
    deviceRow({ status: "pending", scope: "user-login", enrollmentIntent: null }),
  );
  await transitionDeviceCode({ userCode: "ABCDEFGH", userId: "user-1", action: "approve", grant });
  expect(store.state.deviceCode.get("code-1")).toMatchObject({
    status: "approved",
    enrollmentIntent: null,
    loginGrant: grant,
  });
});

it.each([
  ["user-login row with an intent", "user-login", { intent: { kind: "create" } as const }],
  ["user-login row without a grant", "user-login", {}],
  ["host row with a grant", "host-slug:desk-01", { intent: { kind: "create" } as const, grant }],
  ["host row with only a grant", "host-slug:desk-01", { grant }],
  ["row of neither kind", "openid", { grant }],
])("approval refuses a %s", async (_name, scope, decision) => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", scope }));
  await expect(
    transitionDeviceCode({
      userCode: "ABCDEFGH",
      userId: "user-1",
      action: "approve",
      ...decision,
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(store.state.deviceCode.get("code-1")?.status).toBe("pending");
});

it.each([
  { ...grant, poolMode: "SELECTED", poolIds: [] },
  { ...grant, poolIds: ["pool-1"] },
  { ...grant, expiresInDays: 0 },
  { ...grant, maxLiveSandboxes: 1001 },
  { ...grant, name: " " },
  { ...grant, scopes: ["hosts:execute"] },
])("user-login approval refuses an invalid grant %#", async (invalid) => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", scope: "user-login" }));
  await expect(
    transitionDeviceCode({
      userCode: "ABCDEFGH",
      userId: "user-1",
      action: "approve",
      grant: invalid,
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(store.state.deviceCode.get("code-1")?.status).toBe("pending");
});
