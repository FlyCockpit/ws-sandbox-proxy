import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { OPERATION_DISPATCH_KIND } from "./contracts";
import { LEASE_DISPATCH_KINDS, leaseWireSchema } from "./lease-wire";

it("all lease dispatch kinds share the durable carrier on both peers", () => {
  expect([...LEASE_DISPATCH_KINDS].sort()).toEqual(
    [
      OPERATION_DISPATCH_KIND.CREATE_SANDBOX,
      OPERATION_DISPATCH_KIND.RECONNECT_SANDBOX,
      OPERATION_DISPATCH_KIND.RENEW_SANDBOX_LEASE,
    ].sort(),
  );
  const supervisor = readFileSync(
    new URL("../../../../apps/cli/src/sandbox_relay/supervisor.rs", import.meta.url),
    "utf8",
  );
  const guarded = supervisor.match(
    /else if let Some\(refusal\) = matches!\(\s*d\.kind\.as_str\(\),([\s\S]*?)\)\s*\.then\(\|\| journal\.accept_lease\(d\)\)/,
  )?.[1];
  expect(guarded, "the worker must admit leases before recording/issuing effects").toBeDefined();
  for (const kind of LEASE_DISPATCH_KINDS) expect(guarded).toContain(`"${kind}"`);
  const lease = {
    revision: 1,
    deadlineUnixMs: 1_800_000_000_000,
    action: "stop",
    expiryPolicy: "retry-force-60s",
  };
  expect(leaseWireSchema.parse(lease)).toEqual(lease);
  const unlimited = { ...lease, deadlineUnixMs: 253_402_300_799_999 };
  expect(leaseWireSchema.parse(unlimited)).toEqual(unlimited);
  for (const invalid of [
    { revision: 0 },
    { revision: 2_147_483_648 },
    { deadlineUnixMs: Number.NaN },
    { deadlineUnixMs: -1 },
    // One millisecond past the far-future "no lease timer" deadline.
    { deadlineUnixMs: 253_402_300_800_000 },
    { action: "pause" },
    { expiryPolicy: "ignore" },
  ])
    expect(leaseWireSchema.safeParse({ ...lease, ...invalid }).success).toBe(false);
});

it("lease wire cases are shared with crates/sandbox-protocol (shortenOnly is additive)", () => {
  const cases = JSON.parse(
    readFileSync(
      new URL(
        "../../../../crates/sandbox-protocol/fixtures/lease_wire_cases.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as { valid: unknown[]; invalid: unknown[] };
  for (const lease of cases.valid) expect(leaseWireSchema.parse(lease)).toEqual(lease);
  for (const lease of cases.invalid) expect(leaseWireSchema.safeParse(lease).success).toBe(false);
  expect(
    leaseWireSchema.safeParse({ ...(cases.valid[0] as object), shortenOnly: false }).success,
  ).toBe(false);
});

describe("lease from READY (M7) ACK window", () => {
  const base = {
    acceptedAtMs: 1_000_000,
    timeoutMs: 600_000,
    provisionalMs: 1_000_000 + 600_000 + 7_200_000,
  };
  it("accepts readyAt + timeout within ±60 s of skew and refuses beyond it", async () => {
    const { fromReadyDeadlineAcceptable, LEASE_FROM_READY_SKEW_MS } = await import("./lease-wire");
    const nowMs = base.acceptedAtMs + 120_000;
    const exact = nowMs + base.timeoutMs;
    for (const skew of [0, LEASE_FROM_READY_SKEW_MS, -LEASE_FROM_READY_SKEW_MS])
      expect(fromReadyDeadlineAcceptable({ ...base, nowMs, deadlineMs: exact + skew })).toBe(true);
    expect(
      fromReadyDeadlineAcceptable({
        ...base,
        nowMs,
        deadlineMs: exact + LEASE_FROM_READY_SKEW_MS + 1,
      }),
    ).toBe(false);
    // Earlier than acceptance + timeout (minus skew) is a forged shortening.
    expect(
      fromReadyDeadlineAcceptable({
        ...base,
        nowMs,
        deadlineMs: base.acceptedAtMs + base.timeoutMs - LEASE_FROM_READY_SKEW_MS - 1,
      }),
    ).toBe(false);
    // Never past the provisional backstop (plus skew).
    expect(
      fromReadyDeadlineAcceptable({
        ...base,
        nowMs: base.provisionalMs,
        deadlineMs: base.provisionalMs + LEASE_FROM_READY_SKEW_MS + 1,
      }),
    ).toBe(false);
  });
  it("carries fromReadyMs only when set", async () => {
    const { leaseDispatchPayload } = await import("./lease-wire");
    const row = {
      leaseRevision: 1,
      leaseExpiresAt: new Date(2_000_000_000_000),
      leaseExpireAction: "STOP" as const,
    };
    expect(leaseDispatchPayload(row)).not.toHaveProperty("fromReadyMs");
    expect(leaseDispatchPayload(row, false, 600_000)).toMatchObject({ fromReadyMs: 600_000 });
  });
});
