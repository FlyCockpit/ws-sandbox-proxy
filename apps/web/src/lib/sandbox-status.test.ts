import { describe, expect, it } from "vitest";

import {
  finiteDeadline,
  formatClock,
  formatSpan,
  provisionProgress,
  renewDefaultMinutes,
  renewPreview,
  runningSinceMs,
  sandboxDisplayOverride,
} from "./sandbox-status";

const op = (kind: string, state: string, extra: Record<string, unknown> = {}) =>
  ({ kind, state, createdAt: new Date(0), completedAt: null, ...extra }) as never;

describe("sandboxDisplayOverride", () => {
  it("names a start, a restore and a destroy in flight; nothing else", () => {
    expect(
      sandboxDisplayOverride({
        state: "STOPPED",
        lastLifecycleOperation: op("RECONNECT_SANDBOX", "QUEUED"),
      }),
    ).toBe("STARTING");
    expect(
      sandboxDisplayOverride({
        state: "OFFLOADED",
        lastLifecycleOperation: op("RECONNECT_SANDBOX", "RUNNING"),
      }),
    ).toBe("RESTORING");
    expect(
      sandboxDisplayOverride({
        state: "STOPPING",
        lastLifecycleOperation: op("KILL_SANDBOX", "DISPATCHED"),
      }),
    ).toBe("DESTROYING");
    // A settled or uncertain request is not in flight.
    expect(
      sandboxDisplayOverride({
        state: "STOPPED",
        lastLifecycleOperation: op("RECONNECT_SANDBOX", "UNKNOWN_OUTCOME"),
      }),
    ).toBeNull();
    // A warm reconnect of a ready sandbox is not a start.
    expect(
      sandboxDisplayOverride({
        state: "READY",
        lastLifecycleOperation: op("RECONNECT_SANDBOX", "QUEUED"),
      }),
    ).toBeNull();
    expect(
      sandboxDisplayOverride({
        state: "DELETED",
        lastLifecycleOperation: op("KILL_SANDBOX", "QUEUED"),
      }),
    ).toBeNull();
  });
});

describe("provisionProgress", () => {
  const current = (state: string, receipt: never | null) =>
    provisionProgress({ state: state as never, lastLifecycleOperation: receipt })?.steps.find(
      (step) => step.status === "current",
    )?.step;

  it("follows the receipt: queued is placing, sent or accepted is creating, running is booting", () => {
    expect(current("REQUESTED", op("CREATE_SANDBOX", "QUEUED"))).toBe("placed");
    expect(current("REQUESTED", op("CREATE_SANDBOX", "DISPATCHED"))).toBe("creating");
    expect(current("SCHEDULED", op("CREATE_SANDBOX", "ACCEPTED"))).toBe("creating");
    expect(current("REQUESTED", op("CREATE_SANDBOX", "RUNNING"))).toBe("booting");
    expect(current("PROVISIONING", op("CREATE_SANDBOX", "ACCEPTED"))).toBe("booting");
    expect(
      current(
        "PROVISIONING",
        op("RECONNECT_SANDBOX", "RUNNING", { progressPhase: "fetching_image" }),
      ),
    ).toBe("creating");
    expect(current("REQUESTED", null)).toBe("placed");
  });

  it("is a start of a stopped sandbox too, and nothing for a ready or stopped one", () => {
    expect(current("STOPPED", op("RECONNECT_SANDBOX", "DISPATCHED"))).toBe("creating");
    expect(provisionProgress({ state: "READY", lastLifecycleOperation: null })).toBeNull();
    expect(provisionProgress({ state: "STOPPED", lastLifecycleOperation: null })).toBeNull();
  });

  it("marks earlier steps done and later ones to do, and times from the request", () => {
    const progress = provisionProgress({
      state: "PROVISIONING",
      lastLifecycleOperation: op("CREATE_SANDBOX", "RUNNING", { createdAt: new Date(5000) }),
    });
    expect(progress?.steps.map((step) => step.status)).toEqual(["done", "done", "current", "todo"]);
    expect(progress?.sinceMs).toBe(5000);
  });
});

describe("runningSinceMs", () => {
  it("is the completion of a successful create or start of a ready sandbox", () => {
    const at = new Date(1_000_000);
    expect(
      runningSinceMs({
        state: "READY",
        lastLifecycleOperation: op("CREATE_SANDBOX", "SUCCEEDED", { completedAt: at }),
      }),
    ).toBe(1_000_000);
    expect(
      runningSinceMs({
        state: "READY",
        lastLifecycleOperation: op("RENEW_SANDBOX_LEASE", "SUCCEEDED", { completedAt: at }),
      }),
    ).toBeNull();
    expect(
      runningSinceMs({
        state: "STOPPED",
        lastLifecycleOperation: op("CREATE_SANDBOX", "SUCCEEDED", { completedAt: at }),
      }),
    ).toBeNull();
  });
});

describe("formatting", () => {
  it("formatSpan shows the two largest units, seconds only under a minute or on request", () => {
    expect(formatSpan(3 * 3_600_000 + 59 * 60_000 + 30_000, "en-US")).toBe("3 hr 59 min");
    expect(formatSpan(2 * 86_400_000 + 5 * 60_000, "en-US")).toBe("2 days");
    expect(formatSpan(45_000, "en-US")).toBe("45 sec");
    expect(formatSpan(75_000, "en-US")).toBe("1 min");
    expect(formatSpan(75_000, "en-US", { seconds: true })).toBe("1 min 15 sec");
    expect(formatSpan(-5, "en-US")).toBe("0 sec");
  });

  it("formatClock is the time today and adds the date another day", () => {
    const now = Date.UTC(2026, 10, 25, 1, 0);
    expect(formatClock(Date.UTC(2026, 10, 25, 3, 50), "en-US", now, "UTC")).toBe("03:50 AM");
    expect(formatClock(Date.UTC(2026, 10, 26, 3, 50), "en-US", now, "UTC")).toBe(
      "Nov 26, 03:50 AM",
    );
  });

  it("finiteDeadline drops the far-future no-time-limit end", () => {
    expect(finiteDeadline(null)).toBeNull();
    expect(finiteDeadline("9999-12-31T23:59:59.999Z")).toBeNull();
    expect(finiteDeadline(new Date(5000))).toBe(5000);
  });
});

describe("renew", () => {
  const limit = { maxTimeoutMs: 14 * 86_400_000, allowUnlimited: false };

  it("defaults to the current lifetime or the next step up, never below what is left", () => {
    expect(
      renewDefaultMinutes({ ...limit, remainingMs: 3_600_000, rememberedMs: 2 * 3_600_000 }),
    ).toBe("120");
    expect(
      renewDefaultMinutes({ ...limit, remainingMs: 3 * 3_600_000, rememberedMs: 300_000 }),
    ).toBe("240");
    expect(renewDefaultMinutes({ ...limit, remainingMs: 0, rememberedMs: 90 * 60_000 })).toBe(
      "120",
    );
  });

  it("falls back to the largest allowed choice, or keeps no time limit where allowed", () => {
    expect(
      renewDefaultMinutes({
        maxTimeoutMs: 17 * 60_000,
        allowUnlimited: false,
        remainingMs: 3_600_000,
        rememberedMs: null,
      }),
    ).toBe("15");
    expect(
      renewDefaultMinutes({
        maxTimeoutMs: 3_600_000,
        allowUnlimited: true,
        remainingMs: null,
        rememberedMs: 0,
      }),
    ).toBe("0");
  });

  it("previews the new end and whether it shortens the current one", () => {
    const now = 1_000_000;
    expect(renewPreview("60", now + 2 * 3_600_000, now)).toEqual({
      newDeadline: now + 3_600_000,
      shortens: true,
    });
    expect(renewPreview("240", now + 2 * 3_600_000, now)).toEqual({
      newDeadline: now + 4 * 3_600_000,
      shortens: false,
    });
    expect(renewPreview("0", now, now)).toEqual({ newDeadline: null, shortens: false });
    // From no time limit, any finite end is earlier.
    expect(renewPreview("60", null, now)?.shortens).toBe(true);
    expect(renewPreview("x", now, now)).toBeNull();
  });
});
