import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DATA_KEY_PURPOSES,
  type DataKeyPurpose,
  dataRootKey,
  deriveSubkey,
  deriveSubkeys,
  readDataKeyring,
} from "./data-key";

// Dummy test-only roots; never real keys.
const CURRENT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const PREVIOUS_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
// Not a real purpose: separation is also proven against a label outside the
// closed union.
const OTHER_PURPOSE = "test-only-purpose:v1" as DataKeyPurpose;

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("data-encryption root key and HKDF sub-keys", () => {
  it("matches an independently computed HKDF-SHA256 known-answer vector", () => {
    // RFC 5869 with salt "wssp-data-key-v1", computed outside Node (Python hmac).
    const root = dataRootKey(CURRENT_HEX);
    expect(root.id).toBe("6685009530c3e0f4");
    expect(deriveSubkey(root, "webhook-endpoint-secret:v1").key.toString("hex")).toBe(
      "350d4d1a30a8d76f82963339bf74b6d6893d670956e00444900a30e656cbae06",
    );
    expect(deriveSubkey(root, "cred-dek-wrap:v1").key.toString("hex")).toBe(
      "9f211b9d0c69591e3206187be83973ad10d16440f153b460ca540d02dd9f47ce",
    );
    expect(deriveSubkey(root, "cred-return-key-wrap:v1").key.toString("hex")).toBe(
      "d164bf65e41d2e194bd63850abe6cb9174be5df98aa4672a7f6e1a764105069c",
    );
    expect(deriveSubkey(root, OTHER_PURPOSE).key.toString("hex")).toBe(
      "d458c3748de62f939563dc558c7a25d3bc90c5676ae249a5151611ce9548b5a4",
    );
  });

  it("is deterministic and gives every purpose a distinct key, never the root", () => {
    const root = dataRootKey(CURRENT_HEX);
    const purposes = [...DATA_KEY_PURPOSES, OTHER_PURPOSE];
    const keys = purposes.map((purpose) => deriveSubkey(root, purpose));
    for (const [i, subkey] of keys.entries()) {
      expect(subkey.key).toHaveLength(32);
      expect(subkey.rootKeyId).toBe(root.id);
      expect(subkey.purpose).toBe(purposes[i]);
      expect(subkey.key.equals(root.key)).toBe(false);
      expect(deriveSubkey(dataRootKey(CURRENT_HEX), subkey.purpose).key.equals(subkey.key)).toBe(
        true,
      );
    }
    expect(new Set(keys.map((k) => k.key.toString("hex"))).size).toBe(purposes.length);
  });

  it("derives from the previous root too, tagged with that root's kid", () => {
    const current = dataRootKey(CURRENT_HEX);
    const previous = dataRootKey(PREVIOUS_HEX);
    const { current: sub, all } = deriveSubkeys(
      { current, previous },
      "webhook-endpoint-secret:v1",
    );
    expect(all).toHaveLength(2);
    expect(all[0]).toBe(sub);
    expect(all[1]?.rootKeyId).toBe(previous.id);
    expect(all[1]?.key.equals(deriveSubkey(previous, "webhook-endpoint-secret:v1").key)).toBe(true);
    expect(all[1]?.key.equals(sub.key)).toBe(false);
  });

  it("requires exactly 64 lowercase hex characters", () => {
    expect(() => dataRootKey("ab".repeat(31))).toThrow();
    expect(() => dataRootKey("AB".repeat(32))).toThrow();
    expect(dataRootKey(CURRENT_HEX).key).toHaveLength(32);
  });

  it("reads the keyring from the environment without echoing values", () => {
    vi.stubEnv("DATA_ENCRYPTION_KEY", "");
    vi.stubEnv("DATA_ENCRYPTION_KEY_PREVIOUS", "");
    expect(readDataKeyring()).toBeNull();
    vi.stubEnv("DATA_ENCRYPTION_KEY", CURRENT_HEX);
    expect(readDataKeyring()).toMatchObject({
      current: { id: "6685009530c3e0f4" },
      previous: null,
    });
    vi.stubEnv("DATA_ENCRYPTION_KEY_PREVIOUS", CURRENT_HEX);
    expect(readDataKeyring()?.previous).toBeNull();
    vi.stubEnv("DATA_ENCRYPTION_KEY_PREVIOUS", PREVIOUS_HEX);
    expect(readDataKeyring()?.previous?.id).toBe(dataRootKey(PREVIOUS_HEX).id);
    vi.stubEnv("DATA_ENCRYPTION_KEY", "not-hex");
    expect(() => readDataKeyring()).toThrow(/^DATA_ENCRYPTION_KEY is invalid\.$/);
  });
});
