import { describe, expect, it } from "vitest";
import { type PoolHostPolicyMember, summarizePoolHostPolicy } from "./pool-host-policy";

const member = (
  hostOwnerId: string,
  image: Record<string, boolean> | null,
  openEgress = false,
  guestSudo = true,
): PoolHostPolicyMember => ({
  hostOwnerId,
  Host: {
    daemonFeatures: image ? { image } : null,
    daemonOpenEgressForOthers: openEgress,
    daemonGuestSudoForOthers: guestSudo,
  },
});
const closed = { build: true, acceptForeign: false, acceptForeignBuilds: false };
const open = { build: true, acceptForeign: true, acceptForeignBuilds: true };

describe("summarizePoolHostPolicy", () => {
  it("a member on hosts that refuse other accounts sees none for images and builds", () => {
    const policy = summarizePoolHostPolicy(
      "member",
      "owner",
      [member("owner", closed), member("owner", closed)],
      true,
    );
    expect(policy).toEqual({
      viewer: "member",
      hosts: 2,
      ownHosts: 0,
      images: "none",
      builds: "none",
      openEgress: "none",
      guestSudo: "all",
      allowForeignBuilds: true,
    });
  });

  it("leaves a member's own hosts out and counts them separately", () => {
    const policy = summarizePoolHostPolicy(
      "member",
      "owner",
      [member("owner", open, true), member("member", closed), member("owner", closed)],
      false,
    );
    expect(policy).toMatchObject({
      hosts: 2,
      ownHosts: 1,
      images: "some",
      builds: "some",
      openEgress: "some",
      allowForeignBuilds: false,
    });
  });

  it("builds need the builder, foreign builds and foreign images together", () => {
    const policy = summarizePoolHostPolicy(
      "member",
      "owner",
      [
        member("owner", { build: true, acceptForeign: false, acceptForeignBuilds: true }),
        member("owner", { build: false, acceptForeign: true, acceptForeignBuilds: true }),
        member("owner", { build: true, acceptForeign: true, acceptForeignBuilds: false }),
      ],
      true,
    );
    expect(policy.builds).toBe("none");
    expect(policy.images).toBe("some");
  });

  it("the pool owner sees every host, its own included, and no member setting", () => {
    const policy = summarizePoolHostPolicy(
      "owner",
      "owner",
      [member("owner", open, true, false), member("other", open, true, false)],
      true,
    );
    expect(policy).toEqual({
      viewer: "owner",
      hosts: 2,
      ownHosts: 1,
      images: "all",
      builds: "all",
      openEgress: "all",
      guestSudo: "none",
      allowForeignBuilds: null,
    });
  });

  it("a host that never reported image features accepts nothing; no hosts reads as none", () => {
    expect(summarizePoolHostPolicy("m", "o", [member("o", null)], false).images).toBe("none");
    expect(summarizePoolHostPolicy("m", "o", [], false)).toMatchObject({
      hosts: 0,
      images: "none",
      builds: "none",
    });
  });
});
