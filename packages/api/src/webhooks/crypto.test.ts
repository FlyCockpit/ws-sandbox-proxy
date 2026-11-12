import { describe, expect, it } from "vitest";
import { type DataKeyPurpose, dataRootKey, deriveSubkey } from "../crypto/data-key";
import {
  generateSigningSecret,
  openSecret,
  sealSecret,
  WEBHOOK_SECRET_PURPOSE,
  WebhookSecretUnavailableError,
} from "./crypto";

// Dummy test-only roots; never real keys.
const currentRoot = dataRootKey("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
const previousRoot = dataRootKey(
  "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
);
const current = deriveSubkey(currentRoot, WEBHOOK_SECRET_PURPOSE);
const previous = deriveSubkey(previousRoot, WEBHOOK_SECRET_PURPOSE);
const binding = { endpointId: "whe_a", userId: "user-a", version: 1 };

describe("webhook secret encryption (AES-256-GCM)", () => {
  it("round-trips and never stores plaintext", () => {
    const secret = generateSigningSecret();
    const sealed = sealSecret(secret.raw, binding, current);
    // Rows store the ROOT kid, so a rewrap job finds them by root.
    expect(sealed.keyId).toBe(currentRoot.id);
    expect(sealed.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(sealed.nonce).toHaveLength(12);
    expect(sealed.ciphertext.includes(secret.raw)).toBe(false);
    expect(openSecret(sealed, binding, [current])).toEqual(secret.raw);
    expect(secret.text).toMatch(/^whsec_[A-Za-z0-9+/]{43}=$/);
  });

  it("uses a fresh nonce per encryption", () => {
    const raw = Buffer.alloc(32, 9);
    const a = sealSecret(raw, binding, current);
    const b = sealSecret(raw, binding, current);
    expect(a.nonce.equals(b.nonce)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it("fails on any AAD mismatch: a ciphertext copied onto another row does not open", () => {
    const sealed = sealSecret(Buffer.alloc(32, 1), binding, current);
    for (const other of [
      { ...binding, endpointId: "whe_b" },
      { ...binding, userId: "user-b" },
      { ...binding, version: 2 },
    ])
      expect(() => openSecret(sealed, other, [current])).toThrow(WebhookSecretUnavailableError);
  });

  it("decrypts with the previous root's sub-key by root kid, and refuses an unknown key", () => {
    const sealed = sealSecret(Buffer.alloc(32, 2), binding, previous);
    expect(openSecret(sealed, binding, [current, previous])).toEqual(Buffer.alloc(32, 2));
    expect(() => openSecret(sealed, binding, [current])).toThrow(WebhookSecretUnavailableError);
    const tampered = { ...sealed, ciphertext: Buffer.from(sealed.ciphertext).fill(0, 0, 1) };
    expect(() => openSecret(tampered, binding, [current, previous])).toThrow(
      WebhookSecretUnavailableError,
    );
  });

  it("fails closed for a value sealed under the root itself or another purpose's sub-key", () => {
    const raw = Buffer.alloc(32, 3);
    // Same root kid, wrong key material: the retired raw-key scheme.
    const legacy = sealSecret(raw, binding, { ...current, key: currentRoot.key });
    expect(legacy.keyId).toBe(current.rootKeyId);
    expect(() => openSecret(legacy, binding, [current])).toThrow(WebhookSecretUnavailableError);
    // A test-only label outside the closed union stands in for another purpose.
    const other = deriveSubkey(currentRoot, "test-only-purpose:v1" as DataKeyPurpose);
    const foreign = sealSecret(raw, binding, { ...other, purpose: WEBHOOK_SECRET_PURPOSE });
    expect(() => openSecret(foreign, binding, [current])).toThrow(WebhookSecretUnavailableError);
  });
});
