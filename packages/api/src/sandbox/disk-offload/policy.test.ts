import { sandboxOffloadPolicySchema } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { offloadDueAt, offloadPolicyColumns, offloadPolicyOf } from "./policy";

const HOUR = 3_600_000;

describe("offload policy columns", () => {
  it("round-trips every public policy through the row columns", () => {
    for (const policy of [
      { mode: "on_stop" },
      { mode: "after", afterMs: 2 * HOUR },
      { mode: "on_pressure" },
    ] as const)
      expect(offloadPolicyOf(offloadPolicyColumns(policy))).toEqual(policy);
    expect(offloadPolicyColumns({ mode: "after", afterMs: 60_000 })).toEqual({
      offloadMode: "AFTER",
      offloadAfterMs: 60_000,
    });
    expect(offloadPolicyColumns({ mode: "on_pressure" })).toEqual({
      offloadMode: "ON_PRESSURE",
      offloadAfterMs: null,
    });
  });

  it("the public schema bounds the delay to 1 minute .. 24 days and refuses stray fields", () => {
    const ok = (value: unknown) => sandboxOffloadPolicySchema.safeParse(value).success;
    expect(ok({ mode: "after", afterMs: 60_000 })).toBe(true);
    expect(ok({ mode: "after", afterMs: 2_073_600_000 })).toBe(true);
    expect(ok({ mode: "after", afterMs: 59_999 })).toBe(false);
    expect(ok({ mode: "after", afterMs: 2_073_600_001 })).toBe(false);
    expect(ok({ mode: "after", afterMs: 90_000.5 })).toBe(false);
    expect(ok({ mode: "after" })).toBe(false);
    expect(ok({ mode: "on_stop", afterMs: 60_000 })).toBe(false);
    expect(ok({ mode: "never" })).toBe(false);
  });
});

describe("offloadDueAt", () => {
  const stoppedAt = new Date("2026-11-16T10:00:00.000Z");
  const now = new Date("2026-11-16T10:05:00.000Z");
  it("ON_STOP is due at the stop, AFTER at stop + delay, ON_PRESSURE never", () => {
    expect(
      offloadDueAt({ offloadMode: "ON_STOP", offloadAfterMs: null, lastStoppedAt: stoppedAt }, now),
    ).toEqual(stoppedAt);
    expect(
      offloadDueAt({ offloadMode: "AFTER", offloadAfterMs: HOUR, lastStoppedAt: stoppedAt }, now),
    ).toEqual(new Date("2026-11-16T11:00:00.000Z"));
    expect(
      offloadDueAt(
        { offloadMode: "ON_PRESSURE", offloadAfterMs: null, lastStoppedAt: stoppedAt },
        now,
      ),
    ).toBeNull();
  });

  it("an unknown stop time is due now, as the candidate query treats it", () => {
    expect(
      offloadDueAt({ offloadMode: "AFTER", offloadAfterMs: HOUR, lastStoppedAt: null }, now),
    ).toEqual(now);
  });
});
