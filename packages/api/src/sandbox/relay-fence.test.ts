import { describe, expect, it, vi } from "vitest";

// Only the pure fence-state table is under test; every import is IO-bound.
vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/db/account-deletion", () => ({ AccountDeletionConflictError: class {} }));
vi.mock("./host-admission", () => ({ noteHostBlockerReleased: vi.fn() }));
vi.mock("./outbox", () => ({ sandboxOutboxTransaction: vi.fn() }));
vi.mock("./result-finalization", () => ({ noteTerminalResultRelease: vi.fn() }));

const { sandboxStatesForOperation } = await import("./relay-fence");

describe("sandboxStatesForOperation is mode-aware (offload plan U9)", () => {
  it("a restore attempt (RECONNECT + NEW_ROOT) is fenced in PROVISIONING only", () => {
    expect(
      sandboxStatesForOperation({ kind: "RECONNECT_SANDBOX", launchMode: "NEW_ROOT" }),
    ).toEqual(["PROVISIONING"]);
  });

  it("a non-restore reconnect is still refused in PROVISIONING", () => {
    for (const launchMode of ["COLD", "WARM", null] as const) {
      const states = sandboxStatesForOperation({ kind: "RECONNECT_SANDBOX", launchMode });
      expect(states).toEqual(["READY", "STOPPED"]);
      expect(states).not.toContain("PROVISIONING");
    }
  });

  it("the launch mode never widens any other kind", () => {
    expect(sandboxStatesForOperation({ kind: "CREATE_SANDBOX", launchMode: "NEW_ROOT" })).toEqual([
      "REQUESTED",
      "SCHEDULED",
      "PROVISIONING",
    ]);
    expect(sandboxStatesForOperation({ kind: "KILL_SANDBOX", launchMode: null })).toEqual([
      "STOPPING",
      "RECLAIMING",
      "DELETED",
    ]);
    expect(sandboxStatesForOperation({ kind: "RUN_COMMAND", launchMode: null })).toEqual(["READY"]);
  });
});
