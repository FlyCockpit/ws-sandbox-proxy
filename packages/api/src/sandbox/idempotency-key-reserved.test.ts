import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { runCommandInput } from "./contracts";
import {
  INTERNAL_IDEMPOTENCY_KEY_PREFIXES,
  inventoryObservationIdempotencyKey,
  isReservedInternalIdempotencyKey,
  leaseExpiryIdempotencyKey,
  leasePolicyIdempotencyKey,
  readinessFailureIdempotencyKey,
  teardownRetryIdempotencyKey,
  teardownRetryIndex,
} from "./idempotency-key-reserved";

describe("reserved internal idempotency key namespaces", () => {
  it.each(INTERNAL_IDEMPOTENCY_KEY_PREFIXES)(
    "rejects public mutation keys starting with %s",
    (prefix) => {
      expect(
        runCommandInput.safeParse({ id: "sandbox-1", idempotencyKey: prefix, argv: ["true"] })
          .success,
      ).toBe(false);
    },
  );

  it("the public SDK key schema also refuses the system lease pull-in namespace", async () => {
    const { idempotencyKeySchema } = await import("@wssp/sandbox-contracts");
    expect(idempotencyKeySchema.safeParse("lease-policy:sbx:1:2").success).toBe(false);
    expect(leasePolicyIdempotencyKey("sbx", 1, 2)).toBe("lease-policy:sbx:1:2");
  });

  it.each(INTERNAL_IDEMPOTENCY_KEY_PREFIXES)(
    "parity: %s is refused on both the session path and /v1",
    async (prefix) => {
      const { idempotencyKeySchema } = await import("@wssp/sandbox-contracts");
      const key = `${prefix}x:1`;
      expect(isReservedInternalIdempotencyKey(key)).toBe(true);
      expect(idempotencyKeySchema.safeParse(key).success).toBe(false);
      // A user key that merely contains the prefix later is still accepted.
      expect(idempotencyKeySchema.safeParse(`user-${prefix}x`).success).toBe(true);
    },
  );

  it("reserves the template-build orchestrator namespace (tb:)", () => {
    expect(INTERNAL_IDEMPOTENCY_KEY_PREFIXES).toContain("tb:");
    expect(
      runCommandInput.safeParse({ id: "sandbox-1", idempotencyKey: "tb:b1:kill:0:0", argv: ["x"] })
        .success,
    ).toBe(false);
  });

  it("rejects readiness-failed keys that could block another sandbox cleanup", () => {
    expect(
      runCommandInput.safeParse({
        id: "sandbox-1",
        idempotencyKey: "readiness-failed:other:2",
        argv: ["true"],
      }).success,
    ).toBe(false);
  });

  it("internal producers prefix keys from the shared reserved list", () => {
    expect(leaseExpiryIdempotencyKey("sbx-1", 3, 2, "STOP")).toBe(
      `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[0]}sbx-1:3:2:STOP`,
    );
    expect(readinessFailureIdempotencyKey("victim", 2)).toBe(
      `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[1]}victim:2`,
    );
  });

  it("numbers system teardown retries; any other key is retry 0", () => {
    expect(teardownRetryIdempotencyKey("sbx-1", 4, 2)).toBe("teardown-retry:sbx-1:4:2");
    expect(teardownRetryIndex(teardownRetryIdempotencyKey("sbx-1", 4, 2))).toBe(2);
    for (const key of ["stop", "lease-expire:sbx-1:3:2:STOP", "teardown-retry:sbx-1:4:x"])
      expect(teardownRetryIndex(key)).toBe(0);
  });

  it("binds every internal producer to the shared prefix list", () => {
    const samples = [
      leaseExpiryIdempotencyKey("sbx-1", 3, 2, "STOP"),
      readinessFailureIdempotencyKey("victim", 2),
      inventoryObservationIdempotencyKey("sbx-1", 3),
      leasePolicyIdempotencyKey("sbx-1", 3, 7),
      teardownRetryIdempotencyKey("sbx-1", 4, 1),
    ];
    for (const key of samples) {
      expect(INTERNAL_IDEMPOTENCY_KEY_PREFIXES.some((prefix) => key.startsWith(prefix))).toBe(true);
    }
    const leasePath = join(dirname(fileURLToPath(import.meta.url)), "lease.ts");
    const leaseSource = readFileSync(leasePath, "utf8");
    expect(leaseSource).not.toMatch(/readiness-failed:/);
    expect(leaseSource).not.toMatch(/`lease-expire:/);
  });
});
