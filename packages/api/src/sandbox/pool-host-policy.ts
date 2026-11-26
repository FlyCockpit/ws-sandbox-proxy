import type { Prisma } from "@wssp/db";
import { hostImageFeatures } from "./image-store/config";

/**
 * What a pool's hosts allow other accounts, from the node-local consent each
 * daemon last reported (display only, never an admission input). Aggregate
 * only: a pool member learns "all", "some" or "none" over the hosts it may
 * use, never which host or whose host says what.
 */
export type HostPolicyLevel = "all" | "some" | "none";

export type PoolHostPolicy = {
  /**
   * `owner`: the caller owns the pool, so this is what the people it is
   * shared with meet (every member host is another account's to them).
   * `member`: what the caller meets on the member hosts it does not own.
   */
  viewer: "owner" | "member";
  /** Switched-on member hosts described (a member's own hosts left out). */
  hosts: number;
  /** Switched-on member hosts the caller owns (they run the caller's work). */
  ownHosts: number;
  /** Runs other accounts' templates (`accept_foreign_images`). */
  images: HostPolicyLevel;
  /** Builds other accounts' templates (builder on, `accept_foreign_builds` and `accept_foreign_images`). */
  builds: HostPolicyLevel;
  /**
   * Open internet for other accounts' sandboxes: `allow_open_egress_for_others`
   * on a host that can serve open mode (`daemonFeatures.egressOpen`), the same
   * two facts `resolveEffectiveEgress` degrades on.
   */
  openEgress: HostPolicyLevel;
  /**
   * Guest root (sudo) for other accounts' sandboxes: `allow_guest_sudo_for_others`
   * on a host that advertises `daemonFeatures.guestSudo`, as `resolveEffectiveGuestSudo`.
   */
  guestSudo: HostPolicyLevel;
  /** Member view only: the caller's own "Run my builds on other people's builder hosts". */
  allowForeignBuilds: boolean | null;
};

/** The only host columns this summary reads. */
export const poolHostPolicyMemberSelect = {
  hostOwnerId: true,
  Host: {
    select: {
      daemonFeatures: true,
      daemonOpenEgressForOthers: true,
      daemonGuestSudoForOthers: true,
    },
  },
} satisfies Prisma.SandboxPoolMemberSelect;

export type PoolHostPolicyMember = Prisma.SandboxPoolMemberGetPayload<{
  select: typeof poolHostPolicyMemberSelect;
}>;

function featureFlag(features: Prisma.JsonValue | null, key: string): boolean {
  return (
    features !== null &&
    typeof features === "object" &&
    !Array.isArray(features) &&
    (features as Record<string, Prisma.JsonValue>)[key] === true
  );
}

function level(
  hosts: readonly PoolHostPolicyMember[],
  allows: (m: PoolHostPolicyMember) => boolean,
) {
  const count = hosts.filter(allows).length;
  if (count === 0) return "none";
  return count === hosts.length ? "all" : "some";
}

/** Pure: the caller's aggregate view over the switched-on member hosts it can use. */
export function summarizePoolHostPolicy(
  callerId: string,
  poolOwnerId: string,
  members: readonly PoolHostPolicyMember[],
  allowForeignBuilds: boolean,
): PoolHostPolicy {
  const viewer = callerId === poolOwnerId ? "owner" : "member";
  const ownHosts = members.filter((member) => member.hostOwnerId === callerId).length;
  const described =
    viewer === "owner" ? members : members.filter((member) => member.hostOwnerId !== callerId);
  const image = (member: PoolHostPolicyMember) => hostImageFeatures(member.Host.daemonFeatures);
  return {
    viewer,
    hosts: described.length,
    ownHosts,
    images: level(described, (member) => image(member)?.acceptForeign === true),
    builds: level(described, (member) => {
      const features = image(member);
      return Boolean(features?.build && features.acceptForeignBuilds && features.acceptForeign);
    }),
    openEgress: level(
      described,
      (member) =>
        member.Host.daemonOpenEgressForOthers &&
        featureFlag(member.Host.daemonFeatures, "egressOpen"),
    ),
    guestSudo: level(
      described,
      (member) =>
        member.Host.daemonGuestSudoForOthers &&
        featureFlag(member.Host.daemonFeatures, "guestSudo"),
    ),
    allowForeignBuilds: viewer === "member" ? allowForeignBuilds : null,
  };
}
