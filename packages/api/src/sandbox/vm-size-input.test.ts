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
  expect(revisionVmSize({})).toEqual({ diskGiB: 32, cpuCount: 1, memoryMiB: 1024 });
  expect(revisionVmSize({ memoryMiB: 2048 })).toEqual({
    diskGiB: 32,
    cpuCount: 1,
    memoryMiB: 2048,
  });
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

it("refuses a disk below a captured or built image, never below a base default (E1-A-04)", () => {
  for (const sourceKind of ["CAPTURE", "BUILD"] as const) {
    expect(() => assertDiskFitsImage({ sourceKind, diskGiB: 32 }, 16)).toThrow(
      expect.objectContaining({ data: { code: "sandbox.disk_below_image" } }),
    );
    expect(() => assertDiskFitsImage({ sourceKind, diskGiB: 32 }, 32)).not.toThrow();
    expect(() => assertDiskFitsImage({ sourceKind, diskGiB: 32 }, 64)).not.toThrow();
  }
  expect(() => assertDiskFitsImage({ sourceKind: "MANUAL", diskGiB: 32 }, 8)).not.toThrow();
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
