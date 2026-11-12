import { generateProductCredentialSecret } from "@wssp/db/credential-security";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPathOnlyRequestLogger, requestLogPath } from "./request-logger.js";
import { createSandboxRelayWebsocketMiddleware } from "./sandbox-relay/websocket.js";

vi.mock("@wssp/db", () => ({
  default: {
    sandboxHost: {
      update: vi.fn().mockResolvedValue({}),
    },
  },
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    RATE_LIMIT_AUTH_POINTS: 100,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    TRUST_PROXY_HOPS: undefined,
    DATABASE_URL: "postgresql://localhost:5432/test",
    REDIS_URL: "redis://localhost:6379",
  },
}));
vi.mock("@wssp/env/shared", () => ({
  env: {
    DATABASE_URL: "postgresql://localhost:5432/test",
    REDIS_URL: "redis://localhost:6379",
  },
}));
vi.mock("./sandbox-relay/auth.js", () => ({
  authenticateSandboxHostWebsocket: vi.fn().mockResolvedValue(null),
}));
vi.mock("./rate-limit.js", () => ({
  hostRelayLimiter: {},
  createRateLimiterMiddleware: () => async (_context: unknown, next: () => Promise<void>) => {
    await next();
  },
}));

describe("createPathOnlyRequestLogger", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not log query credentials on relay websocket rejections", async () => {
    const credential = generateProductCredentialSecret("hostToken").raw;
    const lines: string[] = [];
    const app = new Hono();
    app.use(
      "/*",
      createPathOnlyRequestLogger((message) => {
        lines.push(message);
      }),
    );
    app.use("/ws/sandbox-host", createSandboxRelayWebsocketMiddleware());
    app.get("/ws/sandbox-host", (c) => c.text("ok"));

    const response = await app.request(`/ws/sandbox-host?token=${credential}`, {
      method: "GET",
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": "ws-sandbox-proxy.relay.v1",
      },
    });

    expect(response.status).toBe(401);
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(line).not.toContain(credential);
      expect(line).toContain("/ws/sandbox-host");
      expect(line).not.toContain("?token=");
    }
  });
});

it.each(["wssp_sdk_", "wssp_host_", "wssp_device_"])(
  "redacts %s credentials in raw and encoded path segments while preserving the route",
  async (prefix) => {
    const credential = `${prefix}syntheticLogTestValue`;
    for (const segment of [
      credential,
      credential.replace("_", "%5F"),
      credential.replace("_", "%255F"),
      credential.replace("_", "%25255F"),
      encodeURIComponent(`Bearer ${credential}`),
      `${credential.replace("_", "%5F")}%ZZ`,
    ]) {
      const lines: string[] = [];
      const app = new Hono();
      app.use(
        "/*",
        createPathOnlyRequestLogger((message) => lines.push(message)),
      );
      app.get("/v1/sandboxes/*", (c) => c.text("ok"));
      expect((await app.request(`/v1/sandboxes/${segment}?trace=private-query-value`)).status).toBe(
        200,
      );
      expect(lines[0]).toBe("<-- GET /v1/sandboxes/[redacted]");
      expect(lines[1]).toContain("--> GET /v1/sandboxes/[redacted] 200");
      expect(JSON.stringify(lines)).not.toContain(credential);
      expect(JSON.stringify(lines)).not.toContain("private-query-value");
    }
  },
);

it("does not expose arbitrary HTTP method text in access logs", async () => {
  const credential = "wssp_sdk_syntheticMethodValue";
  const lines: string[] = [];
  const app = new Hono();
  app.use(
    "/*",
    createPathOnlyRequestLogger((message) => lines.push(message)),
  );
  app.all("/v1/probe", (c) => c.text("ok"));
  expect((await app.request("/v1/probe", { method: credential })).status).toBe(200);
  expect(lines[0]).toBe("<-- OTHER /v1/probe");
  expect(lines[1]).toContain("--> OTHER /v1/probe 200");
  expect(JSON.stringify(lines)).not.toContain(credential);
});

// Route inventory: only reset-password has a secret path parameter in the
// installed Better Auth endpoints. The other families use query/body secrets.
it.each([
  ["/api/auth/reset-password/RESET-SENTINEL", "/api/auth/reset-password/[redacted]"],
  ["/api/auth/reset-password/%2552ESET-SENTINEL", "/api/auth/reset-password/[redacted]"],
  ["/api/%2561uth/reset-password/RESET-SENTINEL", "/api/%2561uth/reset-password/[redacted]"],
  ["/api/auth/verify-email?token=RESET-SENTINEL", "/api/auth/verify-email"],
  ["/api/auth/magic-link/verify?token=RESET-SENTINEL", "/api/auth/magic-link/verify"],
  [
    "/api/auth/organization/accept-invitation?invitationId=RESET-SENTINEL",
    "/api/auth/organization/accept-invitation",
  ],
  ["/api/auth/email-otp/verify-email?otp=RESET-SENTINEL", "/api/auth/email-otp/verify-email"],
  ["/api/auth/two-factor/verify-otp?code=RESET-SENTINEL", "/api/auth/two-factor/verify-otp"],
  ["/api/auth/device?user_code=RESET-SENTINEL", "/api/auth/device"],
  ["/api/auth/device/token?device_code=RESET-SENTINEL", "/api/auth/device/token"],
  ["/en-US/device?user_code=RESET-SENTINEL", "/en-US/device"],
  ["/api/auth/callback/github?code=RESET-SENTINEL", "/api/auth/callback/github"],
  ["/api/auth/delete-user/callback?token=RESET-SENTINEL", "/api/auth/delete-user/callback"],
])("redacts secrets for route family %s", async (path, expected) => {
  expect(requestLogPath(path)).toBe(expected);
  const lines: string[] = [];
  const app = new Hono();
  app.use(
    "*",
    createPathOnlyRequestLogger((message) => lines.push(message)),
  );
  app.all("*", (c) => c.text("ok"));
  await app.request(path);
  expect(lines).toHaveLength(2);
  expect(lines.join("\n")).not.toContain("SENTINEL");
});

/** The pre-optimization implementation, kept as the reference oracle. */
function referenceRequestLogPath(path: string): string {
  const decode = (segment: string) => {
    let decoded = segment;
    for (let layer = 0; layer < 3; layer++) {
      const next = decoded.replace(/%([0-9a-f]{2})/gi, (_match, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      );
      if (next === decoded) break;
      decoded = next;
    }
    return decoded;
  };
  const segments = (path.split(/[?#]/, 1)[0] ?? "").split("/");
  const decoded = segments.map(decode);
  return segments
    .map((segment, index) => {
      const prefix = decoded
        .slice(0, index + 1)
        .join("/")
        .replace(/\/+/g, "/");
      const resetToken = /^\/api\/auth\/reset-password\//i.test(prefix);
      return resetToken || /wssp_(?:sdk|host|device)_/i.test(decoded[index] ?? "")
        ? "[redacted]"
        : segment;
    })
    .join("/");
}

it("matches the reference redaction on adversarial and random paths", () => {
  const pieces = [
    "",
    "api",
    "auth",
    "AUTH",
    "reset-password",
    "%2561uth",
    "reset%2dpassword",
    "%2f",
    "%252f",
    "x",
    "wssp_sdk_x",
    "wssp%5fhost%5fy",
    "v1",
    "a%2fb",
  ];
  const fixed = [
    "//api//auth//reset-password//TOKEN",
    "/api/auth%2freset-password/TOKEN",
    "/api%2fauth%2freset-password%2fTOKEN/next",
    "///",
    "",
    "/api/auth/reset-password",
    "/api/auth/reset-password/",
    "/API/Auth/Reset-Password/T/U",
  ];
  let seed = 7;
  const random = () => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed / 2147483648;
  };
  const generated = Array.from({ length: 2000 }, () =>
    Array.from({ length: 1 + Math.floor(random() * 7) }, () => {
      return pieces[Math.floor(random() * pieces.length)] ?? "";
    }).join("/"),
  );
  for (const path of [...fixed, ...generated]) {
    expect(requestLogPath(path)).toBe(referenceRequestLogPath(path));
  }
});

it("stays linear on very long paths", () => {
  const path = `/${"a/".repeat(8_000)}`;
  const started = performance.now();
  expect(requestLogPath(path)).toBe(path);
  expect(requestLogPath(`/api/auth/reset-password/${"t/".repeat(8_000)}`)).not.toContain("t/");
  expect(performance.now() - started).toBeLessThan(1_000);
});
