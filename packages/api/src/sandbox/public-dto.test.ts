import { expect, it } from "vitest";
import { type OperationRow, toOperationDto } from "./public-dto";

const row: OperationRow = {
  id: "op-1",
  sandboxId: "sandbox-1",
  kind: "CREATE_SANDBOX",
  state: "FAILED",
  generation: 1,
  errorCode: "capacity_wait_timeout",
  failure: { resource: "sandbox", effect: "none", reason: "ram" },
  createdAt: new Date("2026-11-12T00:00:00Z"),
  updatedAt: new Date("2026-11-12T00:00:00Z"),
  dispatchedAt: null,
  completedAt: null,
};

it.each(["host_capacity", "capacity_wait_timeout"])(
  "preserves the %s refusal reason",
  (errorCode) => {
    expect(toOperationDto({ ...row, errorCode }).failure).toEqual(row.failure);
  },
);

it("omits capacity reasons for other errors", () => {
  expect(toOperationDto({ ...row, errorCode: "host_offline" }).failure).toEqual({
    resource: "sandbox",
    effect: "none",
  });
});
