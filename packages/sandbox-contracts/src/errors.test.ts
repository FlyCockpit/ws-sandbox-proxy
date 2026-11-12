import { expect, it } from "vitest";

import {
  CAPACITY_REASONS,
  POOL_FULL_REASONS,
  RETRYABLE_REFUSAL_CODES,
  type RetryableRefusalCode,
  SDK_ERRORS,
  sdkErrorEnvelopeSchema,
} from "./errors";

it("capacity reasons are bounded and only valid for the two capacity codes", () => {
  const requestId = "11111111-1111-4111-8111-111111111111";
  for (const [code, reasons] of [
    ["sandbox.host_capacity", CAPACITY_REASONS],
    ["sandbox.pool_full", POOL_FULL_REASONS],
  ] as const) {
    for (const reason of reasons) {
      expect(
        sdkErrorEnvelopeSchema.safeParse({
          error: { code, reason, requestId, message: "Capacity", retryable: true },
        }).success,
      ).toBe(true);
    }
    expect(
      sdkErrorEnvelopeSchema.safeParse({
        error: { code, requestId, message: "Capacity", retryable: true },
      }).success,
    ).toBe(false);
  }
  // A per-sandbox receipt cap is a host condition, never a pool verdict.
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: {
        code: "sandbox.pool_full",
        reason: "sandbox_receipts",
        requestId,
        message: "Full",
        retryable: true,
      },
    }).success,
  ).toBe(false);
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: { code: "sandbox.vm_size_invalid", reason: "disk", requestId, message: "Invalid" },
    }).success,
  ).toBe(false);
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: {
        code: "sandbox.host_capacity",
        reason: "path",
        requestId,
        message: "Capacity",
        retryable: true,
      },
    }).success,
  ).toBe(false);
});

it("capacity, quota and pool refusals require a boolean retryable; no other code accepts it", () => {
  const requestId = "11111111-1111-4111-8111-111111111111";
  const fields: Partial<Record<RetryableRefusalCode, Record<string, unknown>>> = {
    "sandbox.host_capacity": { reason: "ram" },
    "sandbox.pool_full": { reason: "reserved" },
    "sandbox.share_quota": { resource: "disk" },
    "sandbox.member_quota": { resource: "vcpu" },
    "sandbox.capacity_queue_full": { scope: "owner" },
  };
  expect(RETRYABLE_REFUSAL_CODES.every((code) => SDK_ERRORS[code][0] === 409)).toBe(true);
  for (const code of RETRYABLE_REFUSAL_CODES) {
    const base = { code, requestId, message: "Refused", ...fields[code] };
    for (const retryable of [true, false])
      expect(
        sdkErrorEnvelopeSchema.safeParse({ error: { ...base, retryable } }).success,
        `${code} ${retryable}`,
      ).toBe(true);
    expect(
      sdkErrorEnvelopeSchema.safeParse({
        error: { ...base, retryable: true, retryAfterSeconds: 30 },
      }).success,
    ).toBe(true);
    for (const retryable of [undefined, null, "true", 1])
      expect(
        sdkErrorEnvelopeSchema.safeParse({ error: { ...base, retryable } }).success,
        `${code} ${String(retryable)}`,
      ).toBe(false);
  }
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: { code: "sandbox.host_unavailable", requestId, message: "x", retryable: true },
    }).success,
  ).toBe(false);
});
