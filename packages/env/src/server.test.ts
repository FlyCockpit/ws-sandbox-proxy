import type { Mock } from "vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// server.ts validates process.env and runs its startup guards as import-time
// side effects, so every case re-imports a freshly reset module under a fully
// controlled environment. The helper snapshots and restores process.env so
// cases cannot leak state into each other or the surrounding test run.

type EnvMap = Record<string, string | undefined>;

const BASE_ENV: EnvMap = {
  NODE_ENV: "development",
  DATABASE_URL: "postgresql://localhost:5432/test",
  REDIS_URL: "redis://localhost:6379",
  // Strong enough for the entropy check: >10 distinct characters, no
  // placeholder words, no repeating pattern.
  BETTER_AUTH_SECRET: "kV3mQ7xZ2bN9wL5pR8tY4cJ6hF1dS0gU",
  // https, so the production-only http:// guards stay out of the way.
  SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
  BETTER_AUTH_URL: "https://app.example.com",
  // Every optional key the startup guards read starts explicitly undefined,
  // so a value exported in the developer's shell cannot skew a case.
  ADMIN_EMAILS: undefined,
  SETUP_KEY: undefined,
  SIGNUP_ENABLED: undefined,
  VAPID_PUBLIC_KEY: undefined,
  VAPID_PRIVATE_KEY: undefined,
  VAPID_SUBJECT: undefined,
  SMTP_HOST: undefined,
  SMTP_FROM: undefined,
  DATABASE_POOL_MAX: undefined,
  RATE_LIMIT_SDK_IP_POINTS: undefined,
  RATE_LIMIT_SDK_KEY_POINTS: undefined,
  RATE_LIMIT_SDK_OWNER_POINTS: undefined,
  DATA_ENCRYPTION_KEY: undefined,
  DATA_ENCRYPTION_KEY_PREVIOUS: undefined,
};

const ENV_SNAPSHOT: EnvMap = { ...process.env };

async function importServerEnv(overrides: EnvMap = {}): Promise<typeof import("./server.js")> {
  const effective: EnvMap = { ...BASE_ENV, ...overrides };
  for (const [key, value] of Object.entries(effective)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    return await import("./server.js");
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in ENV_SNAPSHOT)) {
        delete process.env[key];
      }
    }
    for (const [key, value] of Object.entries(ENV_SNAPSHOT)) {
      process.env[key] = value;
    }
  }
}

function lockoutMessage(warn: Mock) {
  return warn.mock.calls.some((call) =>
    call.join(" ").includes("SIGNUP_ENABLED=false and ADMIN_EMAILS is empty"),
  );
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("server env — rate-limit budget defaults", () => {
  it("defaults every budget to its family reference (collapse is behavior-neutral)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv();
    expect(mod.env.RATE_LIMIT_AUTH_POINTS).toBe(30);
    expect(mod.env.RATE_LIMIT_AUTH_WINDOW_SECONDS).toBe(60);
    expect(mod.env.RATE_LIMIT_RPC_POINTS).toBe(100);
    expect(mod.env.RATE_LIMIT_RPC_WINDOW_SECONDS).toBe(60);
    expect(mod.env.RATE_LIMIT_EMAIL_POINTS).toBe(3);
    expect(mod.env.RATE_LIMIT_EMAIL_WINDOW_SECONDS).toBe(3600);
  });

  it("accepts 0 points for RATE_LIMIT_EMAIL_POINTS — the documented family disable", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ RATE_LIMIT_EMAIL_POINTS: "0" });
    expect(mod.env.RATE_LIMIT_EMAIL_POINTS).toBe(0);
  });

  it("rejects a non-positive budget points/window", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(importServerEnv({ RATE_LIMIT_AUTH_POINTS: "0" })).rejects.toThrow();
    await expect(importServerEnv({ RATE_LIMIT_AUTH_WINDOW_SECONDS: "0" })).rejects.toThrow();
  });
});

describe("server env — native /v1 budgets (RATE_LIMIT_SDK_*)", () => {
  it("defaults to 300 per IP, 100 per key and 300 per owner", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({
      RATE_LIMIT_SDK_IP_POINTS: undefined,
      RATE_LIMIT_SDK_KEY_POINTS: undefined,
      RATE_LIMIT_SDK_OWNER_POINTS: undefined,
    });
    expect(mod.env.RATE_LIMIT_SDK_IP_POINTS).toBe(300);
    expect(mod.env.RATE_LIMIT_SDK_KEY_POINTS).toBe(100);
    expect(mod.env.RATE_LIMIT_SDK_OWNER_POINTS).toBe(300);
  });

  it("accepts a positive integer per dimension, independently", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({
      RATE_LIMIT_SDK_IP_POINTS: "1000",
      RATE_LIMIT_SDK_KEY_POINTS: "1",
      RATE_LIMIT_SDK_OWNER_POINTS: "42",
    });
    expect(mod.env.RATE_LIMIT_SDK_IP_POINTS).toBe(1000);
    expect(mod.env.RATE_LIMIT_SDK_KEY_POINTS).toBe(1);
    expect(mod.env.RATE_LIMIT_SDK_OWNER_POINTS).toBe(42);
  });

  it.each(["RATE_LIMIT_SDK_IP_POINTS", "RATE_LIMIT_SDK_KEY_POINTS", "RATE_LIMIT_SDK_OWNER_POINTS"])(
    "%s rejects zero, negative, fractional and non-numeric values",
    async (key) => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      vi.spyOn(console, "error").mockImplementation(() => {});
      for (const bad of ["0", "-5", "1.5", "many"]) {
        vi.resetModules();
        await expect(importServerEnv({ [key]: bad }), `${key}=${bad}`).rejects.toThrow();
      }
    },
  );
});

describe("server env — TRANSFER_MAX_BYTES", () => {
  it("defaults to and accepts at most the 1 GiB host transfer ceiling", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect((await importServerEnv()).env.TRANSFER_MAX_BYTES).toBe(1024 ** 3);
    vi.resetModules();
    expect((await importServerEnv({ TRANSFER_MAX_BYTES: "1048576" })).env.TRANSFER_MAX_BYTES).toBe(
      1048576,
    );
    vi.resetModules();
    expect(
      (await importServerEnv({ TRANSFER_MAX_BYTES: String(1024 ** 3) })).env.TRANSFER_MAX_BYTES,
    ).toBe(1024 ** 3);
  });

  it("rejects a cap above the 1 GiB host ceiling at startup", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(importServerEnv({ TRANSFER_MAX_BYTES: String(1024 ** 3 + 1) })).rejects.toThrow();
    vi.resetModules();
    await expect(importServerEnv({ TRANSFER_MAX_BYTES: String(2 * 1024 ** 3) })).rejects.toThrow();
  });
});

describe("server env — C52-R2-3 host and socket caps", () => {
  it("defaults to 20 hosts per owner and 2 sockets per host", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { env } = await importServerEnv();
    expect(env.SANDBOX_MAX_HOSTS_PER_OWNER).toBe(20);
    expect(env.SANDBOX_MAX_SOCKETS_PER_HOST).toBe(2);
  });

  it("accepts a raised host cap, `unlimited` (null) and a raised socket cap", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(
      (await importServerEnv({ SANDBOX_MAX_HOSTS_PER_OWNER: "500" })).env
        .SANDBOX_MAX_HOSTS_PER_OWNER,
    ).toBe(500);
    vi.resetModules();
    expect(
      (await importServerEnv({ SANDBOX_MAX_HOSTS_PER_OWNER: "unlimited" })).env
        .SANDBOX_MAX_HOSTS_PER_OWNER,
    ).toBeNull();
    vi.resetModules();
    expect(
      (await importServerEnv({ SANDBOX_MAX_SOCKETS_PER_HOST: "64" })).env
        .SANDBOX_MAX_SOCKETS_PER_HOST,
    ).toBe(64);
  });

  it.each([
    ["SANDBOX_MAX_HOSTS_PER_OWNER", "0"],
    ["SANDBOX_MAX_HOSTS_PER_OWNER", "-1"],
    ["SANDBOX_MAX_HOSTS_PER_OWNER", "100001"],
    ["SANDBOX_MAX_HOSTS_PER_OWNER", "Unlimited"],
    ["SANDBOX_MAX_HOSTS_PER_OWNER", "2.5"],
    ["SANDBOX_MAX_SOCKETS_PER_HOST", "0"],
    ["SANDBOX_MAX_SOCKETS_PER_HOST", "65"],
    ["SANDBOX_MAX_SOCKETS_PER_HOST", "unlimited"],
  ])("rejects %s=%s at startup", async (key, value) => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(importServerEnv({ [key]: value })).rejects.toThrow();
  });
});

describe("shared env — DATABASE_POOL_MAX", () => {
  it("defaults to the node-postgres default of 10", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv();
    expect(mod.env.DATABASE_POOL_MAX).toBe(10);
  });

  it("accepts a positive integer", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ DATABASE_POOL_MAX: "25" });
    expect(mod.env.DATABASE_POOL_MAX).toBe(25);
  });

  it("rejects zero, negative, and non-numeric values", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(importServerEnv({ DATABASE_POOL_MAX: "0" })).rejects.toThrow();
    await expect(importServerEnv({ DATABASE_POOL_MAX: "-5" })).rejects.toThrow();
    await expect(importServerEnv({ DATABASE_POOL_MAX: "many" })).rejects.toThrow();
  });
});

describe("server env startup guards — admin lockout", () => {
  it("warns (never throws) in production when signup is disabled and ADMIN_EMAILS is unset — provisioned installs keep their DB admins", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ NODE_ENV: "production" });
    expect(mod.ADMIN_EMAILS.size).toBe(0);
    expect(lockoutMessage(warn)).toBe(true);
  });

  it("treats an empty-string ADMIN_EMAILS as unset (lockout still warns)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ NODE_ENV: "production", ADMIN_EMAILS: "" });
    expect(mod.ADMIN_EMAILS.size).toBe(0);
    expect(lockoutMessage(warn)).toBe(true);
  });

  it("does not throw when SIGNUP_ENABLED=true (the signup path exists)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({
      NODE_ENV: "production",
      SIGNUP_ENABLED: "true",
      SMTP_HOST: "smtp.example.com",
      SMTP_FROM: "App <no-reply@example.com>",
    });
    expect(mod.ADMIN_EMAILS.size).toBe(0);
    expect(lockoutMessage(warn)).toBe(false);
    // The pre-existing non-lockout warning still fires for this shape.
    expect(
      warn.mock.calls.some((call) =>
        call.join(" ").includes("no users will have admin privileges"),
      ),
    ).toBe(true);
  });

  it("does not throw in dev — the lockout shape only warns", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ NODE_ENV: "development" });
    expect(mod.ADMIN_EMAILS.size).toBe(0);
    expect(lockoutMessage(warn)).toBe(true);
  });

  it("boots fine with a populated ADMIN_EMAILS, trimmed and lowercased", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({
      NODE_ENV: "production",
      ADMIN_EMAILS: "  Admin@Example.com , ,bob@example.com  ",
    });
    expect(mod.ADMIN_EMAILS).toEqual(new Set(["admin@example.com", "bob@example.com"]));
    expect(warn.mock.calls.some((call) => call.join(" ").includes("ADMIN_EMAILS"))).toBe(false);
  });
});

describe("server env — SETUP_KEY", () => {
  const STRONG_KEY = "Qm7vT2xK9pL4wN8rB3cZ6hJ1dF5sG0yU";

  it("is unset by default, and an empty string counts as unset", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect((await importServerEnv()).env.SETUP_KEY).toBeUndefined();
    vi.resetModules();
    expect((await importServerEnv({ SETUP_KEY: "" })).env.SETUP_KEY).toBeUndefined();
  });

  it("rejects a key shorter than 32 characters", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(importServerEnv({ SETUP_KEY: STRONG_KEY.slice(0, 31) })).rejects.toThrow();
  });

  it("rejects a key longer than 512 characters, so every valid key fits the route's body", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const long = STRONG_KEY.repeat(17).slice(0, 513);
    await expect(importServerEnv({ SETUP_KEY: long })).rejects.toThrow();
    vi.resetModules();
    expect((await importServerEnv({ SETUP_KEY: long.slice(0, 512) })).env.SETUP_KEY).toHaveLength(
      512,
    );
  });

  it("accepts a 32-character key and tells the operator to remove it", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv({ NODE_ENV: "production", SETUP_KEY: STRONG_KEY });
    expect(mod.env.SETUP_KEY).toBe(STRONG_KEY);
    expect(warn.mock.calls.some((call) => call.join(" ").includes("Remove SETUP_KEY"))).toBe(true);
    // The key itself is never logged.
    expect(warn.mock.calls.some((call) => call.join(" ").includes(STRONG_KEY))).toBe(false);
  });

  it("refuses a weak key in production and only warns in dev", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const weak = "a".repeat(40);
    await expect(importServerEnv({ NODE_ENV: "production", SETUP_KEY: weak })).rejects.toThrow(
      "SETUP_KEY is weak",
    );
    vi.resetModules();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await importServerEnv({ NODE_ENV: "development", SETUP_KEY: weak });
    expect(warn.mock.calls.some((call) => call.join(" ").includes("SETUP_KEY is weak"))).toBe(true);
  });

  it("counts as a bootstrap path, so the admin-lockout warning stays quiet", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await importServerEnv({ NODE_ENV: "production", SETUP_KEY: STRONG_KEY });
    expect(lockoutMessage(warn)).toBe(false);
    expect(
      warn.mock.calls.some((call) =>
        call.join(" ").includes("no users will have admin privileges"),
      ),
    ).toBe(false);
  });
});

describe("server env — resolveAppName", () => {
  it("defaults to WS Sandbox Proxy when unset or empty (Docker exports empty-string ARGs)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv();
    expect(mod.resolveAppName(undefined)).toBe("WS Sandbox Proxy");
    expect(mod.resolveAppName("")).toBe("WS Sandbox Proxy");
  });

  it("passes through a configured name via the canonical web schema", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv();
    expect(mod.resolveAppName("Acme")).toBe("Acme");
  });

  it("fails fast on names the client schema rejects", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const mod = await importServerEnv();
    expect(() => mod.resolveAppName("x".repeat(81))).toThrow();
  });
});

describe("server env — required sandbox HMAC secret", () => {
  it.each(["development", "test", "production"])(
    "rejects a missing secret in %s",
    async (NODE_ENV) => {
      vi.spyOn(console, "error").mockImplementation(() => {});
      await expect(
        importServerEnv({ NODE_ENV, SANDBOX_REQUEST_HMAC_SECRET: undefined }),
      ).rejects.toThrow();
    },
  );
});

describe("server env — template image store", () => {
  it("defaults to auto/peer with the relay spool inside the transfers volume", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { env } = await importServerEnv();
    expect(env.IMAGE_DISTRIBUTION).toBe("auto");
    expect(env.IMAGE_RELAY_SPOOL_DIR).toBe(".data/image-relay");
    expect(env.SANDBOX_CREATE_PROVISION_MAX_MS).toBe(7_200_000);
    expect(env.IMAGE_STORE_MAX_GIB_PER_ACCOUNT).toBe(50);
    const { imageStoreMode } = await import("./image-store-config.js");
    expect(imageStoreMode(env)).toBe("peer");
  });

  it("accepts a complete S3 configuration and `unlimited` quotas", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { env } = await importServerEnv({
      IMAGE_S3_ENDPOINT: "https://example.r2.cloudflarestorage.com",
      IMAGE_S3_BUCKET: "images",
      IMAGE_S3_ACCESS_KEY_ID: "test-access-key",
      IMAGE_S3_SECRET_ACCESS_KEY: "test-secret-key",
      IMAGE_STORE_ENCRYPTION: "on",
      IMAGE_STORE_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      IMAGE_DOWNLOADS_PER_HOUR_MAX: "unlimited",
    });
    const { imageStoreMode } = await import("./image-store-config.js");
    expect(imageStoreMode(env)).toBe("s3");
    expect(env.IMAGE_DOWNLOADS_PER_HOUR_MAX).toBeNull();
  });

  it.each([
    [{ IMAGE_S3_BUCKET: "images", IMAGE_S3_ENDPOINT: "https://s3.example.test" }],
    [{ IMAGE_S3_ACCESS_KEY_ID: "only-a-key" }],
    [{ IMAGE_STORE_ENCRYPTION: "on" }],
    [{ IMAGE_STORE_ENCRYPTION_KEY: Buffer.alloc(16, 1).toString("base64") }],
    [{ IMAGE_S3_PRESIGN_TTL_SECONDS: "59" }],
    [{ IMAGE_RELAY_MAX_ACTIVE: "0" }],
    [{ SANDBOX_CREATE_PROVISION_MAX_MS: "599999" }],
    // Presigned bearer URLs and image bytes never cross the network in cleartext.
    [{ IMAGE_S3_ENDPOINT: "http://s3.example.test" }],
    [{ IMAGE_S3_PUBLIC_ENDPOINT: "http://10.0.0.5:9000" }],
  ])("refuses an incomplete or out-of-range image store setting %o", async (overrides) => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(importServerEnv(overrides)).rejects.toThrow();
  });

  it.each(["http://127.0.0.1:9000", "http://localhost:9000", "http://[::1]:9000"])(
    "allows cleartext S3 only on a loopback host (%s)",
    async (endpoint) => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      const { env } = await importServerEnv({
        IMAGE_S3_ENDPOINT: endpoint,
        IMAGE_S3_PUBLIC_ENDPOINT: endpoint,
      });
      expect(env.IMAGE_S3_ENDPOINT).toBe(endpoint);
    },
  );
});

describe("server env — DATA_ENCRYPTION_KEY rotation forwarding", () => {
  // Dummy test-only roots; never real keys.
  const ROOT = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
  const PREVIOUS = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

  it("boots with the previous root forwarded empty by Compose outside a rotation", async () => {
    const mod = await importServerEnv({
      DATA_ENCRYPTION_KEY: ROOT,
      DATA_ENCRYPTION_KEY_PREVIOUS: "",
    });
    expect(mod.env.DATA_ENCRYPTION_KEY).toBe(ROOT);
    expect(mod.env.DATA_ENCRYPTION_KEY_PREVIOUS).toBeUndefined();
    vi.resetModules();
    const unset = await importServerEnv({
      DATA_ENCRYPTION_KEY: "",
      DATA_ENCRYPTION_KEY_PREVIOUS: "",
    });
    expect(unset.env.DATA_ENCRYPTION_KEY).toBeUndefined();
  });

  it("accepts a forwarded previous root during a rotation and rejects a malformed one", async () => {
    const mod = await importServerEnv({
      DATA_ENCRYPTION_KEY: ROOT,
      DATA_ENCRYPTION_KEY_PREVIOUS: PREVIOUS,
    });
    expect(mod.env.DATA_ENCRYPTION_KEY_PREVIOUS).toBe(PREVIOUS);
    vi.resetModules();
    await expect(
      importServerEnv({ DATA_ENCRYPTION_KEY: ROOT, DATA_ENCRYPTION_KEY_PREVIOUS: "not-hex" }),
    ).rejects.toThrow();
  });
});
