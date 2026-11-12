import { describe, expect, it } from "vitest";
import { COMMUNITY_IMAGES, UBUNTU_CLOUD_PREP_V1_DIGEST } from "./catalog";
import { builtWithWsspRecipe, communityPrepBuildDigest, type WsspRecipeFacts } from "./wssp-recipe";

const FP = `sha256:${"a".repeat(64)}`;
async function facts(): Promise<WsspRecipeFacts> {
  const resources = COMMUNITY_IMAGES[0]!.resources;
  return {
    build: {
      origin: "COMMUNITY_PREP",
      verifyRequired: true,
      recipeDigest: UBUNTU_CLOUD_PREP_V1_DIGEST,
      buildDigest: await communityPrepBuildDigest({
        baseRevisionId: "up-1",
        baseFingerprint: FP,
        resources,
      }),
      baseRevisionId: "up-1",
      baseFingerprint: FP,
      ...resources,
    },
    parent: { id: "up-1", sourceKind: "UPSTREAM", templateId: "tpl", incusFingerprint: FP },
    template: { id: "tpl", communitySource: "ubuntu-26.04" },
    upstreamImageRecorded: true,
    buildSandboxGuestRoot: false,
    capture: { hostOwnerId: "owner", userId: "owner" },
    builtWithRoot: true,
  };
}

describe("builtWithWsspRecipe writer (guest-sudo-plan DG-12, review4 U3)", () => {
  it("is true only when all seven facts hold", async () => {
    expect(await builtWithWsspRecipe(await facts())).toBe(true);
  });

  const breaks: [string, (f: WsspRecipeFacts) => void][] = [
    [
      "USER origin",
      (f) => {
        f.build.origin = "USER";
      },
    ],
    [
      "another recipe",
      (f) => {
        f.build.recipeDigest = "b".repeat(64);
      },
    ],
    [
      "a BUILD parent",
      (f) => {
        f.parent.sourceKind = "BUILD";
      },
    ],
    [
      "another base",
      (f) => {
        f.parent.id = "up-2";
      },
    ],
    [
      "another template's pin",
      (f) => {
        f.parent.templateId = "other";
      },
    ],
    [
      "a non-community template",
      (f) => {
        f.template.communitySource = null;
      },
    ],
    [
      "no recorded pin",
      (f) => {
        f.upstreamImageRecorded = false;
      },
    ],
    [
      "a forged build digest",
      (f) => {
        f.build.buildDigest = "c".repeat(64);
      },
    ],
    [
      "no verify",
      (f) => {
        f.build.verifyRequired = false;
      },
    ],
    [
      "a guest-root build VM",
      (f) => {
        f.buildSandboxGuestRoot = true;
      },
    ],
    [
      "a foreign builder",
      (f) => {
        f.capture.hostOwnerId = "other";
      },
    ],
    [
      "no root steps",
      (f) => {
        f.builtWithRoot = false;
      },
    ],
  ];
  for (const [name, mutate] of breaks)
    it(`is false with ${name}`, async () => {
      const f = await facts();
      mutate(f);
      expect(await builtWithWsspRecipe(f)).toBe(false);
    });
});
