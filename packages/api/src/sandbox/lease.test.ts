import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

vi.mock("@wssp/db", () => ({ default: {} }));

import {
  initialLeaseFields,
  leaseExpiryIdempotencyKey,
  leaseExpiryRequestHash,
  resolveLeaseTimeout,
} from "./lease";

describe("lease helpers", () => {
  it("builds revision-scoped expiry identity", () => {
    expect(leaseExpiryIdempotencyKey("sbx-1", 3, 2, "STOP")).toBe("lease-expire:sbx-1:3:2:STOP");
    const hash = leaseExpiryRequestHash({
      sandboxId: "sbx-1",
      action: "expire-stop",
      generation: 3,
      leaseRevision: 2,
    });
    expect(hash).toHaveLength(64);
    expect(hash).not.toEqual(
      leaseExpiryRequestHash({
        sandboxId: "sbx-1",
        action: "expire-stop",
        generation: 3,
        leaseRevision: 1,
      }),
    );
  });

  it("initializes create lease fields with requested values", () => {
    const now = Date.parse("2026-01-01T00:00:00.000Z");
    vi.setSystemTime(now);
    const fields = initialLeaseFields({
      timeoutMs: 60_000,
      onExpire: "destroy",
      now,
    });
    expect(fields).toMatchObject({
      leaseRevision: 1,
      leaseExpireAction: "DESTROY",
      leaseExpireActionRequested: "DESTROY",
      leaseExpiresAtEffective: null,
    });
    vi.useRealTimers();
  });

  it("checks only the lease shape; zero is the far-future no-timer deadline", () => {
    const now = Date.parse("2026-01-01T00:00:00.000Z");
    expect(resolveLeaseTimeout(0, now).toISOString()).toBe("9999-12-31T23:59:59.999Z");
    expect(resolveLeaseTimeout(25 * 60 * 60 * 1000, now).getTime()).toBe(now + 90_000_000);
    expect(resolveLeaseTimeout(2_073_600_000, now).getTime()).toBe(now + 2_073_600_000);
    for (const invalid of [-1, 1.5, 2_073_600_001, Number.NaN])
      expect(() => resolveLeaseTimeout(invalid, now)).toThrow();
  });
});
