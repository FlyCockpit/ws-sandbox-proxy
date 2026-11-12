import { READINESS_FAILURE_REASONS } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import {
  readinessFailureDetail,
  readinessFailureRecord,
  readinessReasonOfFailure,
} from "./readiness-detail";

describe("readiness failure detail and record", () => {
  it("writes fixed text and a label-only record for every reason", () => {
    for (const reason of READINESS_FAILURE_REASONS) {
      const detail = readinessFailureDetail(reason);
      expect(detail.startsWith(`Sandbox guest readiness failed (${reason}: `)).toBe(true);
      expect(detail.endsWith("); cleanup queued.")).toBe(true);
      expect(readinessReasonOfFailure(readinessFailureRecord(reason))).toBe(reason);
    }
    expect(readinessFailureDetail(true)).toBe("Sandbox guest readiness failed; cleanup queued.");
  });

  it("derives no reason from any other failure record", () => {
    for (const failure of [
      null,
      undefined,
      { resource: "sandbox", effect: "unknown" },
      { readinessReason: "not_a_reason" },
      { readinessReason: "guest_home", detail: "free text" },
    ])
      expect(readinessReasonOfFailure(failure)).toBeUndefined();
  });
});
