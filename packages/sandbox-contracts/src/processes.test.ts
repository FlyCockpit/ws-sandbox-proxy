import { expect, it } from "vitest";
import { classifyKillOutcome } from "./processes";

it.each([
  ["CANCELLED", null, "killed"],
  ["SUCCEEDED", null, "alreadyExited"],
  ["FAILED", "none", "alreadyExited"],
  ["FAILED", "partial", "alreadyExited"],
  ["FAILED", "unknown", "unknown"],
  ["FAILED", null, "unknown"],
  ["UNKNOWN_OUTCOME", null, "unknown"],
  ["RUNNING", null, "unknown"],
  ["CANCEL_REQUESTED", null, "unknown"],
] as const)("kill target %s with %s effect is %s", (state, effect, outcome) => {
  expect(
    classifyKillOutcome({ state, failure: effect ? { resource: "command", effect } : null }),
  ).toBe(outcome);
});
