import type { OperationState, SandboxState } from "@wssp/db";
import { describe, expect, it } from "vitest";
import {
  ACTIVE_OPERATION_STATES,
  canTransitionLifecycleResult,
  canTransitionSandboxState,
  HEALTHY_GUEST_STATES,
  isLifecycleOperationKind,
  KILLABLE_SANDBOX_STATES,
  SANDBOX_TRANSITIONS,
  STOPPABLE_SANDBOX_STATES,
  sandboxStateForLifecycleResult,
} from "./state-transitions";

describe("sandbox state transitions", () => {
  it("allows requested -> scheduled", () => {
    expect(canTransitionSandboxState("REQUESTED", "SCHEDULED")).toBe(true);
  });

  it("rejects deleted -> ready", () => {
    expect(canTransitionSandboxState("DELETED", "READY")).toBe(false);
  });

  it("marks ready as killable", () => {
    expect(KILLABLE_SANDBOX_STATES.has("READY")).toBe(true);
    expect(KILLABLE_SANDBOX_STATES.has("DELETED")).toBe(false);
  });

  it("does not toggle READY for ordinary work", () => {
    expect(canTransitionSandboxState("READY", "PROVISIONING")).toBe(false);
    expect(canTransitionSandboxState("READY", "REQUESTED")).toBe(false);
  });

  it("allows create success and rejects resurrection of stopped/deleted guests", () => {
    expect(canTransitionSandboxState("REQUESTED", "READY")).toBe(true);
    expect(canTransitionSandboxState("STOPPED", "READY")).toBe(true);
    expect(canTransitionSandboxState("DELETED", "READY")).toBe(false);
    // STOPPING → READY exists only for the credential re-arm branch.
    expect(canTransitionSandboxState("STOPPING", "READY")).toBe(false);
    expect(canTransitionLifecycleResult("STOPPING", "READY", false)).toBe(false);
    expect(canTransitionLifecycleResult("STOPPING", "READY", true)).toBe(true);
    expect(canTransitionLifecycleResult("STOPPED", "READY", false)).toBe(true);
    expect(canTransitionSandboxState("STOPPED", "DELETED")).toBe(true);
  });

  it("lets every killable state reach STOPPING (OFFLOADED: a hostless destroy, straight to DELETED)", () => {
    for (const state of KILLABLE_SANDBOX_STATES) {
      if (state === "OFFLOADED") {
        expect(canTransitionSandboxState(state, "STOPPING")).toBe(false);
        expect(canTransitionSandboxState(state, "DELETED")).toBe(true);
        continue;
      }
      expect(canTransitionSandboxState(state, "STOPPING") || state === "STOPPING").toBe(true);
    }
  });

  it("OFFLOADED edges (offload plan §1, C1): exactly the detach sources in, restore and destroy out", () => {
    const all = Object.keys(SANDBOX_TRANSITIONS) as SandboxState[];
    const into = all.filter(
      (from) => from !== "OFFLOADED" && canTransitionSandboxState(from, "OFFLOADED"),
    );
    expect(into.sort()).toEqual(["ERROR", "PROVISIONING", "STOPPED", "STOPPING"]);
    const out = all.filter(
      (to) => to !== "OFFLOADED" && canTransitionSandboxState("OFFLOADED", to),
    );
    expect(out.sort()).toEqual(["DELETED", "PROVISIONING"]);
    expect(canTransitionSandboxState("OFFLOADED", "OFFLOADED")).toBe(true);
    expect(KILLABLE_SANDBOX_STATES.has("OFFLOADED")).toBe(true);
    expect(STOPPABLE_SANDBOX_STATES.has("OFFLOADED")).toBe(false);
    expect(HEALTHY_GUEST_STATES.has("OFFLOADED")).toBe(false);
  });

  it("maps a SYSTEM_DETACH kill to OFFLOADED; every other kill still ends DELETED", () => {
    const kill = (
      intent?: "OWNER_DESTROY" | "SYSTEM_DETACH" | null,
      opState: OperationState = "SUCCEEDED",
    ) =>
      sandboxStateForLifecycleResult(
        "KILL_SANDBOX",
        opState,
        "deleted",
        "STOPPING",
        null,
        undefined,
        intent,
      );
    expect(kill("SYSTEM_DETACH")).toBe("OFFLOADED");
    expect(kill("OWNER_DESTROY")).toBe("DELETED");
    expect(kill(null)).toBe("DELETED");
    expect(kill(undefined)).toBe("DELETED");
    expect(kill("SYSTEM_DETACH", "FAILED")).toBe("ERROR");
    expect(kill("SYSTEM_DETACH", "UNKNOWN_OUTCOME")).toBeUndefined();
    // The intent never changes any other kind's mapping.
    expect(
      sandboxStateForLifecycleResult(
        "STOP_SANDBOX",
        "SUCCEEDED",
        "stopped",
        "STOPPING",
        null,
        undefined,
        "SYSTEM_DETACH",
      ),
    ).toBe("STOPPED");
  });

  it("tracks in-flight work on operation rows, not VM state", () => {
    expect(ACTIVE_OPERATION_STATES.has("QUEUED")).toBe(true);
    expect(ACTIVE_OPERATION_STATES.has("RUNNING")).toBe(true);
    expect(ACTIVE_OPERATION_STATES.has("CANCEL_REQUESTED")).toBe(true);
    expect(ACTIVE_OPERATION_STATES.has("SUCCEEDED")).toBe(false);
    expect(ACTIVE_OPERATION_STATES.has("FAILED")).toBe(false);
    expect(HEALTHY_GUEST_STATES.has("READY")).toBe(true);
  });

  it("treats only READY as a healthy guest", () => {
    expect(HEALTHY_GUEST_STATES.has("READY")).toBe(true);
    expect(HEALTHY_GUEST_STATES.has("ERROR")).toBe(false);
    expect(HEALTHY_GUEST_STATES.has("STOPPED")).toBe(false);
    expect(HEALTHY_GUEST_STATES.has("DELETED")).toBe(false);
    expect(HEALTHY_GUEST_STATES.has("STOPPING")).toBe(false);
  });
});

describe("lifecycle result ownership", () => {
  it("only lifecycle kinds author VM state", () => {
    expect(isLifecycleOperationKind("CREATE_SANDBOX")).toBe(true);
    expect(isLifecycleOperationKind("KILL_SANDBOX")).toBe(true);
    expect(isLifecycleOperationKind("STOP_SANDBOX")).toBe(true);
    expect(isLifecycleOperationKind("RECONNECT_SANDBOX")).toBe(true);
    for (const kind of [
      "RUN_COMMAND",
      "GET_FILE",
      "PUT_FILE",
      "LIST_DIR",
      "STAT_PATH",
      "MKDIR",
      "REMOVE_PATH",
      "MOVE_PATH",
      "LIST_PROCESSES",
      "SIGNAL_PROCESS",
    ]) {
      expect(isLifecycleOperationKind(kind)).toBe(false);
    }
  });

  it("maps lifecycle success and failure, and ignores cancel", () => {
    expect(sandboxStateForLifecycleResult("CREATE_SANDBOX", "SUCCEEDED")).toBe("READY");
    expect(sandboxStateForLifecycleResult("RECONNECT_SANDBOX", "SUCCEEDED")).toBe("READY");
    expect(sandboxStateForLifecycleResult("STOP_SANDBOX", "SUCCEEDED")).toBe("STOPPED");
    expect(sandboxStateForLifecycleResult("KILL_SANDBOX", "SUCCEEDED")).toBe("DELETED");
    expect(sandboxStateForLifecycleResult("CREATE_SANDBOX", "FAILED")).toBe("ERROR");
    expect(sandboxStateForLifecycleResult("STOP_SANDBOX", "CANCELLED")).toBeUndefined();
    expect(sandboxStateForLifecycleResult("KILL_SANDBOX", "UNKNOWN_OUTCOME")).toBeUndefined();
  });

  it("C1: a warm reconnect refused before any effect for its lease keeps READY; other refusals do not", () => {
    expect(
      sandboxStateForLifecycleResult(
        "RECONNECT_SANDBOX",
        "FAILED",
        undefined,
        "READY",
        "lease_exceeds_policy",
      ),
    ).toBeUndefined();
    expect(
      sandboxStateForLifecycleResult(
        "RECONNECT_SANDBOX",
        "FAILED",
        undefined,
        "READY",
        "state_conflict",
      ),
      // An older daemon's dispatch-time lease refusal (round 6).
    ).toBeUndefined();
    expect(
      sandboxStateForLifecycleResult(
        "RECONNECT_SANDBOX",
        "FAILED",
        undefined,
        "READY",
        "guest_unavailable",
      ),
    ).toBe("ERROR");
    expect(
      sandboxStateForLifecycleResult(
        "CREATE_SANDBOX",
        "FAILED",
        undefined,
        "PROVISIONING",
        "lease_exceeds_policy",
      ),
    ).toBe("ERROR");
  });

  it("preserves a stopped disk on definite cold reconnect failure", () => {
    expect(
      sandboxStateForLifecycleResult("RECONNECT_SANDBOX", "FAILED", undefined, "STOPPED"),
    ).toBe("STOPPED");
    expect(
      sandboxStateForLifecycleResult("RECONNECT_SANDBOX", "UNKNOWN_OUTCOME", undefined, "STOPPED"),
    ).toBeUndefined();
    expect(sandboxStateForLifecycleResult("CREATE_SANDBOX", "FAILED", undefined, "STOPPED")).toBe(
      "ERROR",
    );
    expect(sandboxStateForLifecycleResult("RECONNECT_SANDBOX", "FAILED", undefined, "READY")).toBe(
      "ERROR",
    );
  });

  it("maps positive STOP absence to DELETED without changing failed or unknown outcomes", () => {
    expect(sandboxStateForLifecycleResult("STOP_SANDBOX", "SUCCEEDED", "stopped")).toBe("STOPPED");
    expect(sandboxStateForLifecycleResult("STOP_SANDBOX", "SUCCEEDED", "absent")).toBe("DELETED");
    expect(sandboxStateForLifecycleResult("KILL_SANDBOX", "SUCCEEDED", "deleted")).toBe("DELETED");
    expect(sandboxStateForLifecycleResult("STOP_SANDBOX", "FAILED", "absent")).toBe("ERROR");
    expect(
      sandboxStateForLifecycleResult("STOP_SANDBOX", "UNKNOWN_OUTCOME", "absent"),
    ).toBeUndefined();
  });

  it("refuses to resurrect deleted guests even from create/reconnect success", () => {
    expect(canTransitionSandboxState("DELETED", "READY")).toBe(false);
    expect(sandboxStateForLifecycleResult("CREATE_SANDBOX", "SUCCEEDED")).toBe("READY");
    expect(sandboxStateForLifecycleResult("RECONNECT_SANDBOX", "SUCCEEDED")).toBe("READY");
  });
});

describe("credential re-arm branch (CLI-logins §10.3, P3-3)", () => {
  const STATES = [
    "REQUESTED",
    "SCHEDULED",
    "PROVISIONING",
    "READY",
    "STOPPING",
    "STOPPED",
    "RECLAIMING",
    "DELETED",
    "UNREACHABLE",
    "RECOVERED",
    "HOST_LOST",
    "ERROR",
    "WAITING_FOR_CAPACITY",
  ] as const satisfies readonly SandboxState[];
  const OP_STATES = [
    "QUEUED",
    "DISPATCHED",
    "ACCEPTED",
    "RUNNING",
    "CANCEL_REQUESTED",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "UNKNOWN_OUTCOME",
  ] as const satisfies readonly OperationState[];
  const CODES = [undefined, null, "credential_capture_failed", "guest_unavailable", "timeout"];
  const KINDS = ["CREATE_SANDBOX", "KILL_SANDBOX", "STOP_SANDBOX", "RECONNECT_SANDBOX"] as const;
  const PRIORS = [null, ...STATES];

  it("is the only author of READY from STOPPING, over every kind / state / code / prior state", () => {
    for (const kind of KINDS)
      for (const opState of OP_STATES)
        for (const current of STATES)
          for (const code of CODES)
            for (const owns of [false, true])
              for (const prior of PRIORS) {
                const next = sandboxStateForLifecycleResult(
                  kind,
                  opState,
                  undefined,
                  current,
                  code,
                  { ownsReleasingLease: owns, priorState: prior },
                );
                const branch =
                  (kind === "STOP_SANDBOX" || kind === "KILL_SANDBOX") &&
                  opState === "FAILED" &&
                  current === "STOPPING" &&
                  code === "credential_capture_failed" &&
                  owns;
                if (branch)
                  expect(next).toBe(prior === "READY" || prior === "RECOVERED" ? "READY" : "ERROR");
                // Anything else that maps STOPPING to READY (a create/reconnect
                // success) is refused by the transition fence without the re-arm.
                else if (current === "STOPPING" && next === "READY")
                  expect(canTransitionLifecycleResult(current, next, false)).toBe(false);
                // Without the owned lease the branch is identical to no facts at all.
                if (!owns)
                  expect(next).toBe(
                    sandboxStateForLifecycleResult(kind, opState, undefined, current, code),
                  );
              }
  });

  it("maps kill from ERROR / UNREACHABLE / STOPPED to ERROR and from RECOVERED to READY", () => {
    const facts = (priorState: SandboxState) => ({ ownsReleasingLease: true, priorState });
    const kill = (prior: SandboxState) =>
      sandboxStateForLifecycleResult(
        "KILL_SANDBOX",
        "FAILED",
        undefined,
        "STOPPING",
        "credential_capture_failed",
        facts(prior),
      );
    expect(kill("ERROR")).toBe("ERROR");
    expect(kill("UNREACHABLE")).toBe("ERROR");
    expect(kill("STOPPED")).toBe("ERROR");
    expect(kill("PROVISIONING")).toBe("ERROR");
    expect(kill("RECOVERED")).toBe("READY");
    expect(kill("READY")).toBe("READY");
    // A kill with no owned RELEASING lease takes the ordinary FAILED mapping.
    expect(
      sandboxStateForLifecycleResult(
        "KILL_SANDBOX",
        "FAILED",
        undefined,
        "STOPPING",
        "credential_capture_failed",
        { ownsReleasingLease: false, priorState: "READY" },
      ),
    ).toBe("ERROR");
  });
});
