import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const {
  buildContextRoot,
  contextBudgetRefusal,
  contextOpenExpiresAt,
  contextSealedExpiresAt,
  CONTEXT_PLACEMENT_GRACE_MS,
} = await import("./context-store.js");

const GiB = 1024 ** 3;
const SIX_HOURS = 6 * 60 * 60 * 1000;

/** Budget arithmetic at open (template-builds §3.7, r3 N21). Real-DB: context-store.pg.test.ts. */
describe("contextBudgetRefusal (account share vs global cap)", () => {
  const defaults = { perAccount: 2 * GiB, global: 8 * GiB };
  const refusal = (requested: number, accountUsed: number, globalUsed: number, caps = defaults) =>
    contextBudgetRefusal({
      requested: BigInt(requested),
      accountUsed: BigInt(accountUsed),
      globalUsed: BigInt(globalUsed),
      ...caps,
    });

  it("admits up to and including each cap", () => {
    expect(refusal(GiB, 0, 0)).toBeNull();
    expect(refusal(GiB, GiB, 7 * GiB - GiB)).toBeNull();
    expect(refusal(2 * GiB, 0, 6 * GiB)).toBeNull();
  });
  it("refuses one byte over the account share as account scope", () => {
    expect(refusal(GiB, GiB + 1, GiB + 1)).toBe("account");
    expect(refusal(2 * GiB + 1, 0, 0)).toBe("account");
  });
  it("refuses one byte over the global cap as global scope", () => {
    expect(refusal(GiB, 0, 7 * GiB + 1)).toBe("global");
  });
  it("names the account first when both are exceeded (the account waits for its own builds)", () => {
    expect(refusal(GiB, 2 * GiB, 8 * GiB)).toBe("account");
  });
  it("with the defaults one account holds at most a quarter of the global budget", () => {
    let account = 0;
    while (refusal(GiB, account, account) === null) account += GiB;
    expect(account).toBe(2 * GiB);
    expect(account / defaults.global).toBe(0.25);
  });
  it("is exact above 2^53 (bigint sums)", () => {
    const huge = { perAccount: Number.MAX_SAFE_INTEGER, global: Number.MAX_SAFE_INTEGER };
    expect(refusal(2, Number.MAX_SAFE_INTEGER - 1, 0, huge)).toBe("account");
    expect(refusal(1, Number.MAX_SAFE_INTEGER - 1, 0, huge)).toBeNull();
  });
});

// Coordinator ruling on §3.7: OPEN is bounded by idle progress plus an
// absolute ceiling from when it opened, never a fixed window from acceptance;
// SEALED lives seal + 15 min + min(wait, 6 h).
describe("context expiry (§3.7)", () => {
  const at = new Date("2026-11-03T00:00:00Z");
  it("OPEN: the upload phase's absolute ceiling is 6 h after it opened", () => {
    expect(contextOpenExpiresAt(at).getTime()).toBe(at.getTime() + SIX_HOURS);
  });
  const sealed = (ms: number) => at.getTime() + CONTEXT_PLACEMENT_GRACE_MS + ms;
  it("SEALED: seal + 15 min + the build's wait; no wait is the grace alone", () => {
    expect(contextSealedExpiresAt(at, 60_000).getTime()).toBe(sealed(60_000));
    expect(contextSealedExpiresAt(at, null).getTime()).toBe(sealed(0));
  });
  it("SEALED: clamps the wait to the 6 h ceiling; an invalid wait fails closed to it", () => {
    expect(contextSealedExpiresAt(at, 2_073_600_000).getTime()).toBe(sealed(SIX_HOURS));
    expect(contextSealedExpiresAt(at, SIX_HOURS).getTime()).toBe(sealed(SIX_HOURS));
    expect(contextSealedExpiresAt(at, Number.POSITIVE_INFINITY).getTime()).toBe(sealed(SIX_HOURS));
    expect(contextSealedExpiresAt(at, -1).getTime()).toBe(sealed(SIX_HOURS));
  });
});

describe("buildContextRoot", () => {
  it("is a sibling of the transfer spool root, never inside it", () => {
    expect(buildContextRoot("/var/lib/wssp/spool")).toBe("/var/lib/wssp/spool.build-context");
    expect(buildContextRoot("/var/lib/wssp/spool/")).toBe("/var/lib/wssp/spool.build-context");
    expect(buildContextRoot("relative/spool")).toMatch(/\/relative\/spool\.build-context$/);
  });
});
