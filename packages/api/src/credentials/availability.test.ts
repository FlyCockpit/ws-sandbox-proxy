import { afterEach, describe, expect, it, vi } from "vitest";
import { readCredentialsAvailability } from "./availability";

// Dummy test-only root; never a real key.
const ROOT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("CLI logins feature gate", () => {
  it("is on by default whenever the data-encryption root is present", () => {
    vi.stubEnv("CREDENTIALS_ENABLED", "");
    vi.stubEnv("DATA_ENCRYPTION_KEY", ROOT_HEX);
    expect(readCredentialsAvailability()).toEqual({
      flag: true,
      keyPresent: true,
      enabled: true,
      drain: false,
    });
  });

  it("is unavailable, never a failure, without the root (flag default or explicit)", () => {
    vi.stubEnv("DATA_ENCRYPTION_KEY", "");
    for (const flag of ["", "true", "false"]) {
      vi.stubEnv("CREDENTIALS_ENABLED", flag);
      const state = readCredentialsAvailability();
      expect(state.enabled).toBe(false);
      expect(state.keyPresent).toBe(false);
      expect(state.drain).toBe(false);
    }
  });

  it("drains when explicitly off with the root present", () => {
    vi.stubEnv("CREDENTIALS_ENABLED", "false");
    vi.stubEnv("DATA_ENCRYPTION_KEY", ROOT_HEX);
    expect(readCredentialsAvailability()).toEqual({
      flag: false,
      keyPresent: true,
      enabled: false,
      drain: true,
    });
  });

  it("rejects a non-boolean flag without echoing it", () => {
    vi.stubEnv("CREDENTIALS_ENABLED", "yes");
    expect(() => readCredentialsAvailability()).toThrow(/^CREDENTIALS_ENABLED is invalid\.$/);
  });
});
