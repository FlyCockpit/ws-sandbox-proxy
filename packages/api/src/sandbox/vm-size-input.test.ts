import { ORPCError } from "@orpc/server";
import { expect, it } from "vitest";
import {
  assertDiskFitsImage,
  rethrowLaunchInputValidationError,
  revisionVmSize,
  validateVmSizeOverrides,
} from "./vm-size-input";

it("normalizes a self-contained revision without filling create omission", () => {
  expect(validateVmSizeOverrides({})).toEqual({});
  expect(revisionVmSize({})).toEqual({
    defaultDiskGiB: 32,
    minDiskGiB: 32,
    cpuCount: 1,
    memoryMiB: 1024,
  });
  expect(revisionVmSize({ memoryMiB: 2048, defaultDiskGiB: 16, minDiskGiB: 4 })).toEqual({
    defaultDiskGiB: 16,
    minDiskGiB: 4,
    cpuCount: 1,
    memoryMiB: 2048,
  });
  // A floor above the default is a size error, never a silent clamp.
  expect(() => revisionVmSize({ defaultDiskGiB: 8, minDiskGiB: 16 })).toThrow(
    expect.objectContaining({ data: { code: "sandbox.vm_size_invalid" } }),
  );
});
it.each([
  [["metadata", "egress", "cpuCount"], "sandbox.metadata_invalid"],
  [["egress", "memoryMiB"], "sandbox.egress_policy_invalid"],
  [["cpuCount", "envs"], "sandbox.vm_size_invalid"],
  [["memoryMiB"], "sandbox.vm_size_invalid"],
] as const)("safe input classifier precedence %j", (paths, code) => {
  const sentinel = "private-env-sentinel";
  const error = new ORPCError("BAD_REQUEST", {
    data: { issues: paths.map((path) => ({ path: [path], input: sentinel, message: sentinel })) },
  });
  try {
    rethrowLaunchInputValidationError(error);
    throw new Error("expected rejection");
  } catch (caught) {
    expect(caught).toMatchObject({ data: { code } });
    expect(JSON.stringify(caught)).not.toContain(sentinel);
  }
});

it("refuses a disk below any revision's minDiskGiB, whatever its source (E1-A-04)", () => {
  expect(() => assertDiskFitsImage({ minDiskGiB: 8 }, 4)).toThrow(
    expect.objectContaining({ data: { code: "sandbox.disk_below_image" } }),
  );
  expect(() => assertDiskFitsImage({ minDiskGiB: 8 }, 8)).not.toThrow();
  expect(() => assertDiskFitsImage({ minDiskGiB: 8 }, 64)).not.toThrow();
});

it("maps a top-level `name` issue to sandbox.name_invalid only for a sandbox create", () => {
  const error = new ORPCError("BAD_REQUEST", {
    data: { issues: [{ path: ["name"], input: "Bad_Name", message: "x" }] },
  });
  expect(() => rethrowLaunchInputValidationError(error, { sandboxName: true })).toThrow(
    expect.objectContaining({ data: { code: "sandbox.name_invalid" } }),
  );
  // Another input's `name` (a template, a login) keeps its own error.
  expect(() => rethrowLaunchInputValidationError(error)).not.toThrow();
});
