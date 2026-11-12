import { buildDigest, parseRecipe } from "@wssp/template-recipe";
import { communityImage, UBUNTU_CLOUD_PREP_V1, UBUNTU_CLOUD_PREP_V1_DIGEST } from "./catalog";

/**
 * The `builtWithWsspRecipe` true-writer (guest-sudo-plan DG-12, its review4 U3):
 * the ONLY place that decides the column is true. Every fact is a server
 * fact read in the finalize transaction; none comes from the guest or a
 * request. The revision then keeps `builtWithRoot = true` (disclosed) but its
 * root steps are not a taint (`revisionRootTaint`).
 */
export type WsspRecipeFacts = {
  build: {
    origin: "USER" | "COMMUNITY_PREP";
    verifyRequired: boolean;
    recipeDigest: string;
    buildDigest: string;
    baseRevisionId: string;
    baseFingerprint: string;
    cpuCount: number;
    memoryMiB: number;
    diskGiB: number;
  };
  /** The build VM's revision (the capture's parent). */
  parent: { id: string; sourceKind: string; templateId: string; incusFingerprint: string };
  /** The target template (the capture's template). */
  template: { id: string; communitySource: string | null };
  /** A SandboxUpstreamImage row exists for (parent.templateId, parent fingerprint). */
  upstreamImageRecorded: boolean;
  buildSandboxGuestRoot: boolean;
  capture: { hostOwnerId: string; userId: string };
  builtWithRoot: boolean;
};

/** The full build digest a genuine community prep build of this base has. */
export async function communityPrepBuildDigest(input: {
  baseRevisionId: string;
  baseFingerprint: string;
  resources: { cpuCount: number; memoryMiB: number; diskGiB: number };
}): Promise<string> {
  const parsed = parseRecipe(UBUNTU_CLOUD_PREP_V1, {});
  return buildDigest({
    recipeDigest: UBUNTU_CLOUD_PREP_V1_DIGEST,
    baseRevisionId: input.baseRevisionId,
    baseFingerprint: input.baseFingerprint,
    args: parsed.plan.args,
    contextSha256: null,
    egressRequest: parsed.egress?.request ?? null,
    resources: input.resources,
  });
}

/** All seven facts, or false. */
export async function builtWithWsspRecipe(facts: WsspRecipeFacts): Promise<boolean> {
  const { build, parent, template } = facts;
  // 1. Composed by the community paths only (CHECK-backed origin).
  if (build.origin !== "COMMUNITY_PREP" || build.recipeDigest !== UBUNTU_CLOUD_PREP_V1_DIGEST)
    return false;
  // 2. Parent provenance: the build's own base, an UPSTREAM pin of the same
  // community template with its recorded upstream facts. Only the dedicated
  // insert writes UPSTREAM and no user path can resolve one.
  const entry = template.communitySource ? communityImage(template.communitySource) : null;
  if (
    !entry ||
    parent.sourceKind !== "UPSTREAM" ||
    parent.id !== build.baseRevisionId ||
    parent.templateId !== template.id ||
    parent.incusFingerprint !== build.baseFingerprint ||
    !facts.upstreamImageRecorded
  )
    return false;
  // 3. The full build digest of the constant recipe on that base.
  const expected = await communityPrepBuildDigest({
    baseRevisionId: build.baseRevisionId,
    baseFingerprint: build.baseFingerprint,
    resources: entry.resources,
  });
  if (expected !== build.buildDigest) return false;
  // 4–7.
  return (
    build.verifyRequired &&
    !facts.buildSandboxGuestRoot &&
    facts.capture.hostOwnerId === facts.capture.userId &&
    facts.builtWithRoot
  );
}
