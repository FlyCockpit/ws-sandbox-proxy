import { describe, expect, it } from "vitest";
import fixtures from "../../../../crates/sandbox-protocol/fixtures/template_identity.json";
import { guestIdentityInput } from "./guest-identity";

import {
  isIncusFingerprint,
  isIncusImageRef,
  MALICIOUS_INCUS_IMAGE_REFS,
  normalizeIncusFingerprint,
  resolveIncusLaunchFingerprint,
} from "./incus-image";

const FP = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

describe("incus-image fingerprint contract", () => {
  it("accepts operator aliases but not digest-shaped registration refs", () => {
    expect(isIncusImageRef("images:ubuntu/24.04/cloud")).toBe(true);
    expect(isIncusImageRef("sha256:abc")).toBe(false);
    expect(isIncusImageRef(FP)).toBe(false);
  });

  it("normalizes fingerprints for launch argv", () => {
    expect(normalizeIncusFingerprint(FP)).toBe(FP);
    expect(normalizeIncusFingerprint(FP)).toBe(FP);
    expect(resolveIncusLaunchFingerprint(FP)).toBe(FP);
    expect(resolveIncusLaunchFingerprint("images:ubuntu/24.04/cloud")).toBeUndefined();
  });

  it("rejects malicious flag-shaped operator refs", () => {
    for (const imageRef of MALICIOUS_INCUS_IMAGE_REFS) {
      expect(isIncusImageRef(imageRef)).toBe(false);
    }
  });

  it("alias movement cannot change stored fingerprint identity", () => {
    const registered = normalizeIncusFingerprint(FP);
    const relaunched = resolveIncusLaunchFingerprint(registered);
    expect(relaunched).toBe(registered);
    expect(resolveIncusLaunchFingerprint("images:ubuntu/24.04/cloud")).not.toBe(registered);
  });
});

describe("isIncusFingerprint", () => {
  it("accepts only canonical sha256 fingerprints", () => {
    expect(isIncusFingerprint(FP)).toBe(true);
    expect(isIncusFingerprint(FP)).toBe(true);
    expect(isIncusFingerprint("sha256:abc")).toBe(false);
  });
});

it("shares strict fingerprint and UTF-8 guest path boundaries with Rust", () => {
  for (const { value, valid } of fixtures.fingerprints) {
    expect(isIncusFingerprint(value), value).toBe(valid);
    if (!valid) expect(() => normalizeIncusFingerprint(value)).toThrow();
  }
  for (const { value, valid } of fixtures.guestPaths) {
    expect(guestIdentityInput.safeParse({ guestHome: value }).success, value).toBe(valid);
    expect(guestIdentityInput.safeParse({ guestShell: value }).success, value).toBe(valid);
  }
});

it("rejects unpaired UTF-16 surrogates that cannot cross the Rust JSON boundary", () => {
  expect(guestIdentityInput.safeParse({ guestHome: "/home/\ud800" }).success).toBe(false);
  expect(guestIdentityInput.safeParse({ guestHome: "/home/😀" }).success).toBe(true);
});
