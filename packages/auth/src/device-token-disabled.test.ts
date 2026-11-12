import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { deviceAuthorization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  DISABLED_DEVICE_AUTHORIZATION_PATHS,
  requireHostDeviceLoginScope,
} from "./host-device-login-scope";

const BASE_URL = "http://localhost:3000";

type Row = Record<string, unknown>;

function buildAuth(disabledPaths: string[]) {
  const db: Record<string, Row[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
    deviceCode: [],
  };
  const auth = betterAuth({
    baseURL: BASE_URL,
    secret: "device-token-disabled-test-secret-at-least-32-chars",
    database: memoryAdapter(db),
    disabledPaths,
    plugins: [
      deviceAuthorization({
        expiresIn: "30m",
        interval: "5s",
        onDeviceAuthRequest: requireHostDeviceLoginScope,
        schema: undefined,
      }),
    ],
  });
  return { auth, db };
}

async function approvedDeviceCode(setup: ReturnType<typeof buildAuth>) {
  const started = await setup.auth.handler(
    new Request(`${BASE_URL}/api/auth/device/code`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_id: "wssp",
        scope: "host-slug:desk-01",
      }),
    }),
  );
  expect(started.status).toBe(200);
  const { device_code: deviceCode } = (await started.json()) as { device_code: string };
  const now = new Date();
  setup.db.user?.push({
    id: "user-1",
    name: "Owner",
    email: "owner@example.test",
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  });
  const row = setup.db.deviceCode?.find((candidate) => candidate.deviceCode === deviceCode);
  if (!row) throw new Error("device code row missing");
  row.userId = "user-1";
  row.status = "approved";
  return deviceCode;
}

function redeem(setup: ReturnType<typeof buildAuth>, deviceCode: string, path = "/device/token") {
  return setup.auth.handler(
    new Request(`${BASE_URL}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "wssp",
      }),
    }),
  );
}

describe("Better Auth /device/token", () => {
  it("is disabled", () => {
    expect(DISABLED_DEVICE_AUTHORIZATION_PATHS).toContain("/device/token");
  });

  it.each(["/device/token", "/device/token/", "/device", "/device/approve", "/device/deny"])(
    "refuses to redeem an approved code at %s",
    async (path) => {
      const setup = buildAuth([...DISABLED_DEVICE_AUTHORIZATION_PATHS]);
      const deviceCode = await approvedDeviceCode(setup);

      const response = await redeem(setup, deviceCode, path);

      expect(response.status).toBe(404);
      expect(setup.db.session).toHaveLength(0);
      expect(setup.db.deviceCode?.find((row) => row.deviceCode === deviceCode)?.status).toBe(
        "approved",
      );
    },
  );
});

it("the replaced GET claim endpoint is disabled in Better Auth itself", async () => {
  const setup = buildAuth([...DISABLED_DEVICE_AUTHORIZATION_PATHS]);
  await approvedDeviceCode(setup);
  const response = await setup.auth.handler(
    new Request(`${BASE_URL}/api/auth/device?user_code=ABCDEFGH`),
  );
  expect(response.status).toBe(404);
});
