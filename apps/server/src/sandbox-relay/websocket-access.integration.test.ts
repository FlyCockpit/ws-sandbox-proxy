import { digestHostTokenSecret } from "@wssp/api/lib/host-token-access";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
} from "@wssp/db/credential-security";
import { Hono } from "hono";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SandboxHostWebsocketIdentity } from "./auth.js";
import { SANDBOX_RELAY_SUBPROTOCOL } from "./protocol.js";
import { createSandboxRelayWebsocketMiddleware } from "./websocket.js";

vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "test-better-auth-secret",
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

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("../rate-limit.js", () => ({
  hostRelayLimiter: {},
  createRateLimiterMiddleware: () => async (_context: unknown, next: () => Promise<void>) => {
    await next();
  },
}));

const { default: prisma } = await import("@wssp/db");

const db = prisma as unknown as {
  hostToken: {
    findUnique: MockInstance;
    update: MockInstance;
  };
  hostDeviceCredential: { findUnique: MockInstance; update: MockInstance };
  appSetting: { findMany: MockInstance };
};

const enrolledOwner = {
  banned: false,
  banExpires: null,
  twoFactorEnabled: true,
  createdAt: new Date("2020-01-01T00:00:00.000Z"),
  role: "user",
};

const now = new Date("2026-01-01T00:00:00.000Z");

function relayApp() {
  const hono = new Hono<{ Variables: { sandboxRelayIdentity: SandboxHostWebsocketIdentity } }>();
  hono.use("/ws/sandbox-host", createSandboxRelayWebsocketMiddleware());
  hono.get("/ws/sandbox-host", (c) => c.json(c.get("sandboxRelayIdentity")));
  return hono;
}

function websocketHeaders(token: string) {
  return {
    Upgrade: "websocket",
    "Sec-WebSocket-Protocol": SANDBOX_RELAY_SUBPROTOCOL,
    Authorization: `Bearer ${token}`,
  };
}

describe("sandbox relay websocket access (real verifier)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.setSystemTime(now);
  });

  it("authenticates a minted host token through the middleware", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    const lookupPrefix = credentialLookupPrefix(credential);
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      secretDigest: digestHostTokenSecret(credential),
      User: enrolledOwner,
      revokedAt: null,
      expiresAt: null,
    });
    db.hostToken.update.mockResolvedValue({ id: "token-id" });

    const response = await relayApp().request("/ws/sandbox-host", {
      method: "GET",
      headers: websocketHeaders(credential.raw),
    });

    expect(response.status).toBe(200);
    expect(db.hostToken.update).toHaveBeenCalledOnce();
  });

  it("does not write lastUsedAt for revoked credentials", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    const lookupPrefix = credentialLookupPrefix(credential);
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      secretDigest: digestHostTokenSecret(credential),
      User: enrolledOwner,
      revokedAt: now,
      expiresAt: null,
    });

    const response = await relayApp().request("/ws/sandbox-host", {
      method: "GET",
      headers: websocketHeaders(credential.raw),
    });

    expect(response.status).toBe(401);
    expect(db.hostToken.update).not.toHaveBeenCalled();
  });
});

const { invalidateForceTwoFactorSettingsCache } = await import("@wssp/api/lib/two-factor-policy");
describe("device credentials through the real relay middleware", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
  });
  it.each(["active", "revoked", "banned", "unenrolled", "bad-digest", "unknown"])(
    "device %s",
    async (kind) => {
      const secret = generateProductCredentialSecret("deviceCredential");
      db.hostDeviceCredential.findUnique.mockResolvedValue(
        kind === "unknown"
          ? null
          : {
              id: "device",
              userId: "owner",
              sandboxHostId: "bound-host",
              SandboxHost: { userId: "owner", deletionRequestedAt: null },
              lookupPrefix: credentialLookupPrefix(secret),
              secretDigest: hmacDigestForProductPurpose({
                purpose: kind === "bad-digest" ? "hostToken" : "deviceCredential",
                value: secret.raw,
              }),
              revokedAt: kind === "revoked" ? now : null,
              User: {
                ...enrolledOwner,
                banned: kind === "banned",
                twoFactorEnabled: kind !== "unenrolled",
              },
            },
      );
      db.hostDeviceCredential.update.mockResolvedValue({ id: "device" });
      const response = await relayApp().request("/ws/sandbox-host", {
        headers: websocketHeaders(secret.raw),
      });
      expect(response.status).toBe(kind === "active" ? 200 : 401);
      expect(db.hostDeviceCredential.update).toHaveBeenCalledTimes(kind === "active" ? 1 : 0);
      expect(db.hostToken.findUnique).not.toHaveBeenCalled();
      if (kind === "active")
        expect(await response.json()).toEqual({
          hostId: "bound-host",
          userId: "owner",
          tokenId: "device",
          credentialKind: "deviceCredential",
          expiresAt: null,
        });
    },
  );
  it.each([
    "wssp_device_",
    "wssp_device_" + "A".repeat(42),
    "wssp_sdk_" + "A".repeat(43),
    "plain-code",
  ])("malformed/wrong plane %s", async (value) => {
    const response = await relayApp().request("/ws/sandbox-host", {
      headers: websocketHeaders(value),
    });
    expect(response.status).toBe(401);
    expect(db.hostToken.findUnique).not.toHaveBeenCalled();
    expect(db.hostDeviceCredential.findUnique).not.toHaveBeenCalled();
  });
});
