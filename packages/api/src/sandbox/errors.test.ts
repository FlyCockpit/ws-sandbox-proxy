import { inspect } from "node:util";
import { SDK_ERRORS } from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import { vmSizeInvalid, vmSizeMismatch, vmSizeUnsupported } from "./errors";
import { rethrowSensitiveSandboxError, safeOperationError } from "./sensitive-errors";

it.each([
  [vmSizeInvalid, "sandbox.vm_size_invalid"],
  [vmSizeUnsupported, "sandbox.vm_size_unsupported"],
  [vmSizeMismatch, "sandbox.vm_size_mismatch"],
] as const)("reconstructs the safe size failure %s from the catalog", (make, code) => {
  const error = make();
  expect(error).toMatchObject({
    status: SDK_ERRORS[code][0],
    message: SDK_ERRORS[code][1],
    data: { code },
  });
  error.message = "private-input-sentinel";
  try {
    rethrowSensitiveSandboxError(error);
  } catch (safe) {
    expect(safe).toMatchObject({
      status: SDK_ERRORS[code][0],
      message: SDK_ERRORS[code][1],
      data: { code },
    });
    expect(inspect(safe)).not.toContain("private-input-sentinel");
  }
});

it("sanitizes asynchronous mismatches through the operation allowlist", () => {
  expect(safeOperationError("vm_size_mismatch")).toEqual({
    code: "vm_size_mismatch",
    message: SDK_ERRORS["sandbox.vm_size_mismatch"][1],
  });
  expect(safeOperationError("vm_size_mismatch:private-input-sentinel").code).toBe("internal");
});

it("only exposes bounded capacity reasons on safe capacity operation errors", () => {
  expect(safeOperationError("host_capacity", "disk")).toMatchObject({ reason: "disk" });
  expect(safeOperationError("host_capacity", "private/source/path")).not.toHaveProperty("reason");
  expect(safeOperationError("timeout", "disk")).not.toHaveProperty("reason");
});
