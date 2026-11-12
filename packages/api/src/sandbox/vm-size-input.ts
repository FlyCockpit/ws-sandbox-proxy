import { ORPCError } from "@orpc/server";
import {
  type VmSizeOverrides,
  vmRevisionSizeSchema,
  vmSizeOverridesSchema,
} from "@wssp/sandbox-contracts";
import { diskBelowImage, egressPolicyInvalid, sandboxNameInvalid, vmSizeInvalid } from "./errors";

export function validateVmSizeOverrides(input: VmSizeOverrides): VmSizeOverrides {
  const parsed = vmSizeOverridesSchema.safeParse({
    cpuCount: input.cpuCount,
    memoryMiB: input.memoryMiB,
    diskGiB: input.diskGiB,
  });
  if (!parsed.success) throw vmSizeInvalid();
  return parsed.data;
}

/**
 * A captured or built revision's image carries the source VM's whole root
 * disk (its `diskGiB`), so a sandbox from it needs at least that disk. Refuse
 * a smaller request up front instead of letting the host fail the create. A
 * MANUAL (base) revision's `diskGiB` is only a default.
 */
export function assertDiskFitsImage(
  revision: { sourceKind: "MANUAL" | "CAPTURE" | "BUILD" | "UPSTREAM"; diskGiB: number },
  diskGiB: number,
): void {
  // An UPSTREAM image's declared disk is the catalog default, not a captured
  // root: like a MANUAL registration it does not bound the VM's disk (S6).
  if (
    revision.sourceKind !== "MANUAL" &&
    revision.sourceKind !== "UPSTREAM" &&
    diskGiB < revision.diskGiB
  )
    throw diskBelowImage();
}

export function revisionVmSize(input: VmSizeOverrides) {
  return vmRevisionSizeSchema.parse(validateVmSizeOverrides(input));
}

/** Values-free classification shared by browser input boundaries. `sandboxName`:
 * the input's top-level `name` is a sandbox name (sandbox create only; a
 * template's or login's `name` keeps its own error). */
export function rethrowLaunchInputValidationError(
  error: unknown,
  options: { sandboxName?: boolean } = {},
): void {
  if (
    !(error instanceof ORPCError) ||
    error.code !== "BAD_REQUEST" ||
    !error.data ||
    typeof error.data !== "object" ||
    "code" in error.data ||
    !("issues" in error.data) ||
    !Array.isArray(error.data.issues)
  )
    return;
  const paths = error.data.issues.map((issue: unknown) =>
    issue && typeof issue === "object" && "path" in issue && Array.isArray(issue.path)
      ? issue.path[0]
      : undefined,
  );
  if (options.sandboxName && paths.includes("name")) throw sandboxNameInvalid();
  if (paths.includes("metadata"))
    throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.metadata_invalid" } });
  if (paths.includes("egress")) throw egressPolicyInvalid();
  if (paths.includes("cpuCount") || paths.includes("memoryMiB") || paths.includes("diskGiB"))
    throw vmSizeInvalid();
}
