import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSession: vi.fn(),
  loadUser: vi.fn(),
  policy: vi.fn(),
  transition: vi.fn(),
  handler: vi.fn(),
}));
vi.mock("@wssp/env/load-dotenv", () => ({}));
vi.mock("@wssp/env/server", () => ({
  env: {
    NODE_ENV: "test",
    BETTER_AUTH_URL: "https://api.example.test",
    CORS_ORIGIN: "https://console.other.test",
    LOG_LEVEL: "silent",
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
  },
  ADMIN_EMAILS: new Set(),
  resolveAppName: () => "WS Sandbox Proxy",
}));
vi.mock("@wssp/db", async () => ({ default: (await import("vitest-mock-extended")).mockDeep() }));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, QUEUE_NAMES: {} }));
vi.mock("@wssp/api/routers/index", () => ({ appRouter: {} }));
vi.mock("@wssp/api/lib/push-subscription", () => ({
  pushSubscriptionInputSchema: {},
  upsertPushSubscription: vi.fn(),
}));
vi.mock("@wssp/auth", () => ({
  auth: { api: { getSession: mocks.getSession }, handler: mocks.handler },
  passwordPepper: {},
}));
// The server entry seals stored password hashes before it listens.
vi.mock("@wssp/auth/password-pepper-store", () => ({
  PasswordPepperKeyError: class PasswordPepperKeyError extends Error {},
  syncPasswordPepper: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("@wssp/api/lib/sensitive-session-two-factor-gate", () => ({
  loadSensitiveSessionGateUser: mocks.loadUser,
  isLiveOwnerSessionAuthorized: vi.fn().mockResolvedValue(true),
  isSensitiveSessionTwoFactorPolicySatisfied: mocks.policy,
  sensitiveSessionRefusal: async () => ((await mocks.policy()) ? null : "two_factor_required"),
  isSessionRowLive: async () => true,
}));
vi.mock("@wssp/api/lib/device-code-transitions", () => ({
  transitionDeviceCode: mocks.transition,
}));
vi.mock("./lifecycle.js", () => ({
  createServerLifecycle: () => ({ start: vi.fn(), isShuttingDown: () => false }),
  withTimeout: vi.fn(),
}));
vi.mock("./sandbox-relay/websocket.js", () => ({
  createSandboxRelayWebsocketMiddleware: vi.fn(),
  sandboxRelayUpgradeHandler: vi.fn(),
  sandboxConnectManager: vi.fn(),
}));
vi.mock("./rate-limit.js", () => {
  const limiter = { consume: vi.fn(), reward: vi.fn() };
  return {
    authLimiter: limiter,
    credentialBurstLimiter: limiter,
    credentialLimiter: limiter,
    readyLimiter: limiter,
    rpcLimiter: limiter,
    signinRecipientLimiter: limiter,
    signupLimiter: limiter,
    signupRecipientLimiter: limiter,
    ssrLimiter: limiter,
    terminalUpgradeLimiter: limiter,
    imageRelayLimiter: limiter,
    createRateLimiterMiddleware: () => async (_c: unknown, next: () => Promise<void>) => next(),
  };
});
vi.mock("./email-recipient-limit.js", () => ({
  EMAIL_RECIPIENT_PATHS: [],
  FORM_OR_JSON_MEDIA_TYPES: [],
  SIGNIN_RECIPIENT_PATH: "/api/auth/sign-in/email",
  SIGNUP_RECIPIENT_PATH: "/api/auth/sign-up/email",
  signinSentMail: vi.fn(),
  emailRecipientLimit: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
vi.mock("./signin-failure-limit.js", () => ({
  SIGNIN_FAILURE_PATH: "/api/auth/sign-in/email",
  signinFailureLimit: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
vi.mock("./two-factor-otp-limit.js", () => ({
  TWO_FACTOR_OTP_PATH: "/api/auth/two-factor/send-otp",
  twoFactorOtpLimit: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
vi.mock("./signup-gate.js", () => ({
  adminBootstrapMarker: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
const { app } = await import("./index");
function request(
  path = "/api/auth/device/approve",
  method = "POST",
  origin = "https://console.other.test",
  secFetchSite = "same-site",
) {
  return app.request(`https://api.example.test${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      origin,
      authorization: "Bearer ignored",
      "sec-fetch-site": secFetchSite,
    },
    ...(method === "POST"
      ? { body: JSON.stringify({ userCode: "ABCDEFGH", intent: { kind: "create" } }) }
      : {}),
  });
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.getSession.mockResolvedValue({ user: { id: "owner", banned: false } });
  mocks.loadUser.mockResolvedValue({ emailVerified: true, banned: false });
  mocks.policy.mockResolvedValue(true);
  mocks.transition.mockResolvedValue({ success: true });
  mocks.handler.mockResolvedValue(new Response("plugin", { status: 200 }));
});
describe("production server device mounts", () => {
  it.each(["", "/approve", "/deny"])("owner gate protects %s", async (suffix) => {
    mocks.getSession.mockResolvedValue(null);
    expect((await request(`/api/auth/device${suffix}`)).status).toBe(401);
    expect(mocks.transition).not.toHaveBeenCalled();
    expect(mocks.handler).not.toHaveBeenCalled();
  });
  it.each(["", "/approve", "/deny"])("blocked 2FA protects %s", async (suffix) => {
    mocks.policy.mockResolvedValue(false);
    expect((await request(`/api/auth/device${suffix}`)).status).toBe(403);
    expect(mocks.transition).not.toHaveBeenCalled();
    expect(mocks.handler).not.toHaveBeenCalled();
  });
  it("GET claim is rejected even for an authenticated owner", async () => {
    expect((await request("/api/auth/device?user_code=ABCDEFGH", "GET")).status).toBe(405);
    expect(mocks.transition).not.toHaveBeenCalled();
    expect(mocks.handler).not.toHaveBeenCalled();
  });
  it.each(["", "/approve", "/deny"])("cross-site %s is rejected", async (suffix) => {
    expect(
      (await request(`/api/auth/device${suffix}`, "POST", "https://evil.example")).status,
    ).toBe(403);
    expect(mocks.transition).not.toHaveBeenCalled();
    expect(mocks.handler).not.toHaveBeenCalled();
  });
  it.each(["/approve/", "/deny/", "//approve", "%2Fapprove", "/approve%2F", "/"])(
    "path variant %s cannot reach plugin or transition",
    async (suffix) => {
      expect((await request(`/api/auth/device${suffix}`)).status).toBe(404);
      expect(mocks.transition).not.toHaveBeenCalled();
      expect(mocks.handler).not.toHaveBeenCalled();
    },
  );
  it("session lookup failure remains a server error", async () => {
    mocks.getSession.mockRejectedValue(new Error("session store unavailable"));
    expect((await request()).status).toBe(500);
  });
  it("banned owner receives the correct description", async () => {
    mocks.loadUser.mockResolvedValue({ emailVerified: true, banned: true, banExpires: null });
    const response = await request();
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error_description: "Account is banned" });
  });
  it("an owner with an admin-set temporary password cannot decide until it is replaced", async () => {
    mocks.loadUser.mockResolvedValue({ emailVerified: true, mustChangePassword: true });
    const response = await request();
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      error_description: "Password change required",
    });
    expect(mocks.transition).not.toHaveBeenCalled();
  });
  it("unverified owner cannot decide", async () => {
    mocks.loadUser.mockResolvedValue({ emailVerified: false });
    expect((await request()).status).toBe(403);
    expect(mocks.transition).not.toHaveBeenCalled();
  });
  it.each(["", "/approve", "/deny"])(
    "verified owner reaches own %s handler with cookie-only session",
    async (suffix) => {
      expect((await request(`/api/auth/device${suffix}`)).status).toBe(200);
      expect(mocks.transition).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: "owner",
          action: suffix === "" ? "claim" : suffix.slice(1),
        }),
      );
      expect(mocks.getSession.mock.calls[0]?.[0].headers.has("authorization")).toBe(false);
      expect(mocks.handler).not.toHaveBeenCalled();
    },
  );
  it("public issuance reaches the plugin without consulting owner session", async () => {
    expect((await request("/api/auth/device/code")).status).toBe(200);
    expect(mocks.getSession).not.toHaveBeenCalled();
    expect(mocks.handler).toHaveBeenCalledTimes(1);
  });
});

it.each(["", "/approve", "/deny"])(
  "trusted cross-site frontend reaches %s through production mount",
  async (suffix) => {
    const response = await request(
      `/api/auth/device${suffix}`,
      "POST",
      "https://console.other.test",
      "cross-site",
    );
    expect(response.status).toBe(200);
    expect(mocks.transition).toHaveBeenCalledWith(
      expect.objectContaining({ action: suffix ? suffix.slice(1) : "claim", userId: "owner" }),
    );
    expect(mocks.handler).not.toHaveBeenCalled();
  },
);
it.each([
  "https://evil.test",
  "https://console.other.test.evil.test",
  "https://console.other.test/",
  "https://CONSOLE.other.test",
  "null",
])("cross-site Origin %s is not an exact trusted origin", async (origin) => {
  for (const suffix of ["", "/approve", "/deny"])
    expect((await request(`/api/auth/device${suffix}`, "POST", origin, "cross-site")).status).toBe(
      403,
    );
  expect(mocks.getSession).not.toHaveBeenCalled();
  expect(mocks.transition).not.toHaveBeenCalled();
});
