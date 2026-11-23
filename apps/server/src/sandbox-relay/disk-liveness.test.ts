import { describe, expect, it } from "vitest";
import {
  confirmDiskLiveness,
  DISK_LIVENESS_PROBES_MAX,
  grantDiskLiveness,
  takeDiskLivenessSlot,
} from "./disk-liveness.js";

describe("disk liveness allowance (rounds 2-4)", () => {
  it("is per connection and bounded; probes lapse with the interval", () => {
    const theirs = new Map<string, number>();
    const mine = new Map<string, number>();
    for (let i = 0; i < DISK_LIVENESS_PROBES_MAX; i++)
      expect(takeDiskLivenessSlot(theirs, `tr-${i}`, 0)).toBe(true);
    expect(takeDiskLivenessSlot(theirs, "tr-over", 0)).toBe(false);
    // Another connection's map is its own.
    expect(takeDiskLivenessSlot(mine, "tr-disk", 0)).toBe(true);
    expect(takeDiskLivenessSlot(theirs, "tr-over", 10_000)).toBe(true);
  });

  it("a proven disk upload keeps its own slot once per interval; proven non-disk ids stop probing", () => {
    const mine = new Map<string, number>();
    expect(takeDiskLivenessSlot(mine, "tr-disk", 0)).toBe(true);
    confirmDiskLiveness(mine, "tr-disk", true, 0);
    for (let i = 0; i < DISK_LIVENESS_PROBES_MAX; i++) {
      expect(takeDiskLivenessSlot(mine, `tr-template-${i}`, 10_000)).toBe(true);
      confirmDiskLiveness(mine, `tr-template-${i}`, false, 10_000);
    }
    expect(takeDiskLivenessSlot(mine, "tr-disk", 9_999)).toBe(false);
    expect(takeDiskLivenessSlot(mine, "tr-disk", 10_000)).toBe(true);
    expect(takeDiskLivenessSlot(mine, "tr-disk", 15_000)).toBe(false);
    // A proven template id never takes a probe again, so it cannot keep the
    // probes full interval after interval.
    expect(takeDiskLivenessSlot(mine, "tr-template-0", 30_000)).toBe(false);
    expect(takeDiskLivenessSlot(mine, "tr-new", 30_000)).toBe(true);
  });

  it("a disk upload granted on this connection holds a slot before its first heartbeat (round 4)", () => {
    const fresh = new Map<string, number>();
    grantDiskLiveness(fresh, "tr-disk");
    // Unproven ids fill every probe first ...
    for (let i = 0; i < DISK_LIVENESS_PROBES_MAX; i++)
      expect(takeDiskLivenessSlot(fresh, `tr-other-${i}`, 1_000)).toBe(true);
    expect(takeDiskLivenessSlot(fresh, "tr-unknown", 1_000)).toBe(false);
    // ... and the granted disk upload's heartbeat still gets its try, each interval.
    expect(takeDiskLivenessSlot(fresh, "tr-disk", 1_000)).toBe(true);
    for (let i = 0; i < DISK_LIVENESS_PROBES_MAX; i++)
      takeDiskLivenessSlot(fresh, `tr-next-${i}`, 11_000);
    expect(takeDiskLivenessSlot(fresh, "tr-disk", 11_000)).toBe(true);
  });

  it("probes stay charged after they prove an id non-disk: at most the limit of lookups per interval (round 5)", () => {
    const mine = new Map<string, number>();
    for (let i = 0; i < DISK_LIVENESS_PROBES_MAX; i++) {
      expect(takeDiskLivenessSlot(mine, `tr-fake-${i}`, 0)).toBe(true);
      confirmDiskLiveness(mine, `tr-fake-${i}`, false, 0);
    }
    expect(takeDiskLivenessSlot(mine, "tr-fake-next", 0)).toBe(false);
    expect(takeDiskLivenessSlot(mine, "tr-fake-next", 10_000)).toBe(true);
  });
});
