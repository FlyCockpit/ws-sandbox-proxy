import { CANCELLABLE_OPERATION_KINDS } from "@wssp/api/sandbox/state-transitions";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import { describe, expect, it } from "vitest";

import {
  canCancelOperation,
  cancelAnswer,
  cancelProblem,
  durationMs,
  isOperationPending,
  isOutputExpired,
  OPERATION_ERROR_CODES,
  OPERATION_KINDS,
  OPERATION_STATES,
  operationsListInput,
  parseOperationsSearch,
} from "./operation-rules";

describe("canCancelOperation", () => {
  it.each(OPERATION_KINDS)(
    "%s: offered only for the server's cancellable kinds while in flight",
    (kind) => {
      for (const state of OPERATION_STATES) {
        const expected =
          CANCELLABLE_OPERATION_KINDS.has(kind) &&
          ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"].includes(state);
        expect(canCancelOperation(kind, state), `${kind} ${state}`).toBe(expected);
      }
    },
  );

  it("never offers a second cancel while one is waiting for the host", () => {
    expect(canCancelOperation("RUN_COMMAND", "CANCEL_REQUESTED")).toBe(false);
    expect(isOperationPending("CANCEL_REQUESTED")).toBe(true);
  });
});

describe("cancelAnswer", () => {
  it("only the server's CANCELLED reads as cancelled; a finished operation keeps its result", () => {
    expect(cancelAnswer("CANCEL_REQUESTED")).toBe("pending");
    expect(cancelAnswer("CANCELLED")).toBe("cancelled");
    expect(cancelAnswer("SUCCEEDED")).toBe("finishedFirst");
    expect(cancelAnswer("FAILED")).toBe("finishedFirst");
    expect(cancelAnswer("UNKNOWN_OUTCOME")).toBe("unknown");
  });

  it("maps refusals", () => {
    expect(cancelProblem({ code: "NOT_FOUND" })).toBe("notFound");
    expect(cancelProblem({ code: "CONFLICT" })).toBe("notCancellable");
    expect(cancelProblem({ status: 403 })).toBe("forbidden");
    expect(cancelProblem(new Error("network"))).toBe("generic");
  });
});

describe("operations search", () => {
  it("keeps valid filters and drops anything else", () => {
    expect(
      parseOperationsSearch({ sandboxId: "sbx_1-a", state: "active", kind: "RUN_COMMAND" }),
    ).toEqual({ sandboxId: "sbx_1-a", state: "active", kind: "RUN_COMMAND" });
    expect(parseOperationsSearch({ state: "CANCEL_REQUESTED" })).toEqual({
      state: "CANCEL_REQUESTED",
    });
    expect(
      parseOperationsSearch({
        sandboxId: "<script>",
        state: "everything",
        kind: 7,
        extra: "x",
      }),
    ).toEqual({});
    expect(parseOperationsSearch({ sandboxId: "a".repeat(65) })).toEqual({});
  });

  it("sends only the filters that are set", () => {
    expect(operationsListInput({}, 50)).toEqual({ limit: 50 });
    expect(operationsListInput({ sandboxId: "s", state: "settled" }, 50, "c")).toEqual({
      limit: 50,
      cursor: "c",
      sandboxId: "s",
      state: "settled",
    });
  });
});

describe("misc", () => {
  it("recognizes the typed OUTPUT_EXPIRED error", () => {
    expect(isOutputExpired({ code: "GONE", status: 410, data: { code: "OUTPUT_EXPIRED" } })).toBe(
      true,
    );
    expect(isOutputExpired({ code: "NOT_FOUND", status: 404 })).toBe(false);
  });

  it("durations need both ends", () => {
    expect(durationMs("2026-01-01T00:00:00Z", "2026-01-01T00:00:02Z")).toBe(2000);
    expect(durationMs("2026-01-01T00:00:00Z", null)).toBeNull();
  });

  it("every kind, state and public error code has copy in both locales", () => {
    for (const bundle of [enOperations, esOperations]) {
      for (const kind of OPERATION_KINDS) expect(bundle.kind[kind], kind).toBeTruthy();
      for (const state of OPERATION_STATES) expect(bundle.state[state], state).toBeTruthy();
      for (const code of OPERATION_ERROR_CODES) expect(bundle.error[code], code).toBeTruthy();
    }
  });
});
