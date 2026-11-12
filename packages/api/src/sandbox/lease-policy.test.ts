import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/db", () => ({ default: {} }));

import {
  effectiveLeaseLimit,
  leaseDeadline,
  leasePathOf,
  leasePathPools,
  leaseRequestOf,
  leaseWithinPolicy,
  requireLeaseWithinPolicy,
  sameLeasePath,
} from "./lease-policy";

const H6 = 21_600_000;
const H24 = 86_400_000;
const F = 2_073_600_000;

describe("effectiveLeaseLimit (unit; real-DB parity: lease-policy.pg.test.ts)", () => {
  const pool = (maxLeaseMs: number | null, unlimitedForShares = false) => ({
    maxLeaseMs,
    ownerId: "owner",
    unlimitedForShares,
  });
  it.each([
    // deployment, host, pool, member, requester, finite, unlimited
    [H24, H24, null, null, "owner", H24, false],
    [null, null, null, null, "owner", F, true],
    [null, H6, null, null, "owner", H6, false],
    [null, null, pool(H6), null, "owner", H6, false],
    [null, null, pool(null), 3_600_000, "owner", 3_600_000, false],
    [null, null, pool(null), null, "owner", F, true],
    [null, null, pool(null), null, "grantee", F, false],
    [null, null, pool(null, true), null, "grantee", F, true],
    [H24, null, pool(null, true), null, "grantee", H24, false],
    [null, H24, pool(H6), 3_600_000, "grantee", 3_600_000, false],
  ] as const)(
    "deployment %s host %s pool %o member %s requester %s → %s/%s",
    (deployment, host, p, member, requesterId, finite, unlimited) => {
      expect(
        effectiveLeaseLimit({
          deployment,
          host,
          pool: p,
          memberMaxLeaseMs: member,
          requesterId,
        }),
      ).toEqual({ finiteMaxMs: finite, unlimited });
    },
  );

  it("checks requests without clamping and throws the finite maximum", () => {
    const limit = { finiteMaxMs: H6, unlimited: false };
    expect(leaseWithinPolicy(leaseRequestOf(H6), limit)).toBe(true);
    expect(leaseWithinPolicy(leaseRequestOf(H6 + 1), limit)).toBe(false);
    expect(leaseWithinPolicy(leaseRequestOf(0), limit)).toBe(false);
    expect(leaseWithinPolicy(leaseRequestOf(0), { finiteMaxMs: F, unlimited: true })).toBe(true);
    expect(() => requireLeaseWithinPolicy(leaseRequestOf(0), limit)).toThrow(
      expect.objectContaining({
        code: "BAD_REQUEST",
        data: { code: "lease_exceeds_policy", maxTimeoutMs: H6 },
      }),
    );
  });

  it("maps 0 to the far-future deadline and positive values relative to now", () => {
    const now = new Date("2030-01-01T00:00:00.000Z");
    expect(leaseDeadline(leaseRequestOf(0), now).toISOString()).toBe("9999-12-31T23:59:59.999Z");
    expect(leaseDeadline(leaseRequestOf(H6), now).getTime()).toBe(now.getTime() + H6);
  });
});

describe("lease path (§3.1)", () => {
  const base = {
    userId: "creator",
    sandboxHostId: "host",
    originPoolId: "origin",
    usagePoolId: null,
    usageMemberId: null,
  };
  it("own host takes the origin pool for life, ignoring the cleared usage path", () => {
    const own = { ...base, hostOwnerId: "creator" };
    expect(leasePathOf(own)).toEqual({ kind: "own", poolId: "origin", hostId: "host" });
    expect(leasePathPools(own)).toEqual(["origin"]);
    expect(leasePathOf({ ...own, usagePoolId: "other", usageMemberId: "m" })).toEqual(
      leasePathOf(own),
    );
    expect(leasePathOf({ ...own, originPoolId: null })).toEqual({ kind: "none" });
  });
  it("foreign host takes the usage path; no usage path means host and deployment only", () => {
    const foreign = { ...base, hostOwnerId: "host-owner", usagePoolId: "use", usageMemberId: "m" };
    expect(leasePathOf(foreign)).toEqual({
      kind: "foreign",
      poolId: "use",
      memberId: "m",
      hostId: "host",
    });
    expect(leasePathPools({ ...foreign, usagePoolId: null })).toEqual([]);
  });
  it("detects drift of the path or the host owner", () => {
    const foreign = { ...base, hostOwnerId: "host-owner", usagePoolId: "use", usageMemberId: "m" };
    expect(sameLeasePath(foreign, { ...foreign })).toBe(true);
    expect(sameLeasePath(foreign, { ...foreign, usageMemberId: "m2" })).toBe(false);
    expect(sameLeasePath(foreign, { ...foreign, hostOwnerId: "creator" })).toBe(false);
    // Own-host usage clearing is not drift.
    const own = { ...base, hostOwnerId: "creator", usagePoolId: "origin", usageMemberId: "m" };
    expect(sameLeasePath(own, { ...own, usagePoolId: null, usageMemberId: null })).toBe(true);
  });
});
