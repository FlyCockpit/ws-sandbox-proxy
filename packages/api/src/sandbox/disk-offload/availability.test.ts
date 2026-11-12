import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { canOffload, canRestore, offloadBlocker } from "./availability";

const KEY_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

function configureS3() {
  vi.stubEnv("IMAGE_S3_ENDPOINT", "http://127.0.0.1:7457");
  vi.stubEnv("IMAGE_S3_BUCKET", "wssp-offload-dev");
  vi.stubEnv("IMAGE_S3_ACCESS_KEY_ID", "access");
  vi.stubEnv("IMAGE_S3_SECRET_ACCESS_KEY", "secret");
}

beforeEach(() => {
  for (const name of [
    "IMAGE_DISTRIBUTION",
    "IMAGE_S3_ENDPOINT",
    "IMAGE_S3_BUCKET",
    "IMAGE_S3_ACCESS_KEY_ID",
    "IMAGE_S3_SECRET_ACCESS_KEY",
    "DATA_ENCRYPTION_KEY",
    "DATA_ENCRYPTION_KEY_PREVIOUS",
    "SANDBOX_OFFLOAD",
  ])
    vi.stubEnv(name, "");
});
afterEach(() => vi.unstubAllEnvs());

describe("offload availability split (R12)", () => {
  it("S3 + key + auto (the default) + capable host: offload and restore", () => {
    configureS3();
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    expect(canOffload(true)).toBe(true);
    expect(canRestore()).toBe(true);
    expect(offloadBlocker(true)).toBeNull();
  });

  it("SANDBOX_OFFLOAD=off stops offload but not restore", () => {
    configureS3();
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    vi.stubEnv("SANDBOX_OFFLOAD", "off");
    expect(canOffload(true)).toBe(false);
    expect(offloadBlocker(true)).toBe("offload_disabled");
    expect(canRestore()).toBe(true);
  });

  it("a missing data key blocks both", () => {
    configureS3();
    expect(canOffload(true)).toBe(false);
    expect(offloadBlocker(true)).toBe("data_key_missing");
    expect(canRestore()).toBe(false);
  });

  it("missing S3 blocks both", () => {
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    expect(canOffload(true)).toBe(false);
    expect(offloadBlocker(true)).toBe("s3_not_configured");
    expect(canRestore()).toBe(false);
  });

  it("a host without the capability blocks offload only", () => {
    configureS3();
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    expect(canOffload(false)).toBe(false);
    expect(offloadBlocker(false)).toBe("host_unsupported");
    expect(canRestore()).toBe(true);
  });

  it("IMAGE_DISTRIBUTION=off does not strand offloaded disks", () => {
    configureS3();
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    vi.stubEnv("IMAGE_DISTRIBUTION", "off");
    expect(canRestore()).toBe(true);
  });

  it("rejects an invalid SANDBOX_OFFLOAD value instead of guessing", () => {
    configureS3();
    vi.stubEnv("DATA_ENCRYPTION_KEY", KEY_HEX);
    vi.stubEnv("SANDBOX_OFFLOAD", "on");
    expect(() => canOffload(true)).toThrow();
  });
});
