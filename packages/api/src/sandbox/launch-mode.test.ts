import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  acceptedLaunchMode,
  currentlyRestoring,
  isCurrentlyRestoring,
  isRestoreAttempt,
  launchModeOf,
} = await import("./launch-mode");

const restore = { kind: "RECONNECT_SANDBOX", launchMode: "NEW_ROOT" as const };

describe("accepted launch mode (§8.4)", () => {
  it("CREATE is a new root; a reconnect from STOPPED is COLD and from READY is WARM", () => {
    expect(acceptedLaunchMode("CREATE_SANDBOX")).toBe("NEW_ROOT");
    expect(acceptedLaunchMode("RECONNECT_SANDBOX", "STOPPED")).toBe("COLD");
    expect(acceptedLaunchMode("RECONNECT_SANDBOX", "READY")).toBe("WARM");
  });

  it("a reconnect from any other state is never stamped (OFFLOADED resumes only by restore)", () => {
    for (const state of ["OFFLOADED", "PROVISIONING", "ERROR", "STOPPING"] as const)
      expect(() => acceptedLaunchMode("RECONNECT_SANDBOX", state)).toThrow();
  });

  it("launchModeOf reads the stored mode, never the prior state, when one is stored", () => {
    expect(launchModeOf(restore)).toBe("NEW_ROOT");
    expect(launchModeOf({ kind: "RECONNECT_SANDBOX", launchMode: "WARM" })).toBe("WARM");
    expect(launchModeOf({ kind: "RECONNECT_SANDBOX", launchMode: "COLD" })).toBe("COLD");
  });

  it("non-launch operations have no launch mode", () => {
    expect(launchModeOf({ kind: "RUN_COMMAND", launchMode: null })).toBeNull();
  });

  it("only a NEW_ROOT reconnect is a restore attempt", () => {
    expect(isRestoreAttempt(restore)).toBe(true);
    expect(isRestoreAttempt({ kind: "CREATE_SANDBOX", launchMode: "NEW_ROOT" })).toBe(false);
    expect(isRestoreAttempt({ kind: "RECONNECT_SANDBOX", launchMode: "COLD" })).toBe(false);
    expect(isRestoreAttempt({ kind: "RECONNECT_SANDBOX", launchMode: "WARM" })).toBe(false);
  });
});

describe("currentlyRestoring (CN2)", () => {
  const offloaded = { generation: 4, diskOffloadId: "off-1" };

  it("holds only with the offload pointer and an active restore of the current generation", () => {
    expect(
      isCurrentlyRestoring(offloaded, [{ ...restore, generation: 4, state: "DISPATCHED" }]),
    ).toBe(true);
    expect(
      isCurrentlyRestoring({ ...offloaded, diskOffloadId: null }, [
        { ...restore, generation: 4, state: "DISPATCHED" },
      ]),
    ).toBe(false);
    expect(isCurrentlyRestoring(offloaded, [{ ...restore, generation: 3, state: "QUEUED" }])).toBe(
      false,
    );
  });

  it("a restored sandbox past READY is not restoring; its warm reconnect is WARM, not a restore", () => {
    // The restore reached READY: its operation SUCCEEDED.
    expect(
      isCurrentlyRestoring(offloaded, [{ ...restore, generation: 4, state: "SUCCEEDED" }]),
    ).toBe(false);
    const warm = {
      kind: "RECONNECT_SANDBOX",
      launchMode: acceptedLaunchMode("RECONNECT_SANDBOX", "READY"),
    };
    expect(warm.launchMode).toBe("WARM");
    expect(isRestoreAttempt(warm)).toBe(false);
    expect(
      isCurrentlyRestoring(offloaded, [
        { ...restore, generation: 4, state: "SUCCEEDED" },
        { ...warm, generation: 4, state: "QUEUED" },
      ]),
    ).toBe(false);
    // A later cold start of the restored sandbox is COLD.
    expect(acceptedLaunchMode("RECONNECT_SANDBOX", "STOPPED")).toBe("COLD");
  });

  it("the transactional form queries an active NEW_ROOT reconnect of the current generation", async () => {
    const findFirst = vi.fn().mockResolvedValueOnce({ id: "op" }).mockResolvedValueOnce(null);
    const tx = { sandboxOperation: { findFirst } } as never;
    const sandbox = { id: "sbx", userId: "u", ...offloaded };
    expect(await currentlyRestoring(tx, sandbox)).toBe(true);
    expect(await currentlyRestoring(tx, sandbox)).toBe(false);
    expect(await currentlyRestoring(tx, { ...sandbox, diskOffloadId: null })).toBe(false);
    expect(findFirst).toHaveBeenCalledTimes(2);
    expect(findFirst.mock.calls[0]?.[0]).toMatchObject({
      where: {
        sandboxId: "sbx",
        userId: "u",
        kind: "RECONNECT_SANDBOX",
        launchMode: "NEW_ROOT",
        generation: 4,
        state: { in: ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"] },
      },
    });
  });
});
