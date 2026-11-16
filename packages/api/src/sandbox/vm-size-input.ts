import { ORPCError } from "@orpc/server";
import {
  type RevisionSizeOverrides,
  revisionSizeOverridesSchema,
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
 * A revision's `minDiskGiB` is its image's root disk (a captured or built
 * image carries the source VM's whole root; a registered one its declared
 * floor), so a sandbox or build VM from it needs at least that disk. Refuse a
 * smaller request up front instead of letting the host fail the create.
 */
export function assertDiskFitsImage(revision: { minDiskGiB: number }, diskGiB: number): void {
  if (diskGiB < revision.minDiskGiB) throw diskBelowImage();
}

/** A registered revision's size: `minDiskGiB` defaults to, and never exceeds, `defaultDiskGiB`. */
export function revisionVmSize(input: RevisionSizeOverrides) {
  const parsed = revisionSizeOverridesSchema.safeParse({
    cpuCount: input.cpuCount,
    memoryMiB: input.memoryMiB,
    defaultDiskGiB: input.defaultDiskGiB,
    minDiskGiB: input.minDiskGiB,
  });
  const size = parsed.success ? vmRevisionSizeSchema.safeParse(parsed.data) : null;
  if (!size?.success) throw vmSizeInvalid();
  return size.data;
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
  if (
    ["cpuCount", "memoryMiB", "diskGiB", "defaultDiskGiB", "minDiskGiB"].some((field) =>
      paths.includes(field),
    )
  )
    throw vmSizeInvalid();
}
