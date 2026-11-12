import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  guestSudoReasonDto,
  resolveEffectiveGuestSudo,
  revisionRootTaint,
} from "./guest-sudo-policy";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");

function importers(needle: string, self: string) {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (["node_modules", "dist", "generated"].includes(name) || name.startsWith(".")) continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (
        /\.(ts|tsx)$/.test(name) &&
        !/\.test\.tsx?$/.test(name) &&
        !path.endsWith(self) &&
        readFileSync(path, "utf8").includes(needle)
      )
        found.push(relative(root, path));
    }
  };
  for (const dir of ["packages", "apps"]) walk(join(root, dir));
  return found.sort();
}

describe("resolveEffectiveGuestSudo (OD-2, security-relevant)", () => {
  const own = { ownerId: "owner", guestSudo: true, guestSudoForOthers: false };
  it.each([
    ["not requested", false, own, "owner", { effective: false, reason: null }],
    [
      "host without the capability",
      true,
      { ...own, guestSudo: false },
      "owner",
      { effective: false, reason: "HOST_UNSUPPORTED" },
    ],
    [
      "foreign node without consent",
      true,
      own,
      "other",
      { effective: false, reason: "NODE_POLICY" },
    ],
    [
      "foreign node with consent",
      true,
      { ...own, guestSudoForOthers: true },
      "other",
      { effective: true, reason: null },
    ],
    ["own node without consent", true, own, "owner", { effective: true, reason: null }],
  ] as const)("%s", (_name, requested, host, sandboxOwner, expected) => {
    expect(resolveEffectiveGuestSudo(requested, host, sandboxOwner)).toEqual(expected);
  });

  it("the capability check wins over consent (an old daemon never grants)", () => {
    expect(
      resolveEffectiveGuestSudo(
        true,
        { ownerId: "owner", guestSudo: false, guestSudoForOthers: false },
        "other",
      ),
    ).toEqual({ effective: false, reason: "HOST_UNSUPPORTED" });
  });

  it("has exactly one caller outside tests: placement-materialize.ts", () => {
    expect(importers("resolveEffectiveGuestSudo", join("sandbox", "guest-sudo-policy.ts"))).toEqual(
      [join("packages", "api", "src", "sandbox", "placement-materialize.ts")],
    );
  });
});

describe("revisionRootTaint (I15: the only TS definition)", () => {
  it.each([
    [false, false, false, false],
    [true, false, false, true],
    [true, false, true, false],
    [false, true, false, true],
    [false, true, true, true],
    [true, true, true, true],
  ])(
    "builtWithRoot=%s capturedWithGuestRoot=%s builtWithWsspRecipe=%s → %s",
    (built, captured, wssp, taint) => {
      expect(
        revisionRootTaint({
          builtWithRoot: built,
          capturedWithGuestRoot: captured,
          builtWithWsspRecipe: wssp,
        }),
      ).toBe(taint);
    },
  );

  it("is never redefined: only the policy module spells the predicate", () => {
    // A second definition would combine the three flags itself.
    expect(importers("builtWithWsspRecipe &&", join("sandbox", "guest-sudo-policy.ts"))).toEqual(
      [],
    );
    expect(
      importers("!revision.builtWithWsspRecipe", join("sandbox", "guest-sudo-policy.ts")),
    ).toEqual([]);
  });
});

it("public reason spelling", () => {
  expect(guestSudoReasonDto("NODE_POLICY")).toBe("node_policy");
  expect(guestSudoReasonDto("HOST_UNSUPPORTED")).toBe("host_unsupported");
  expect(guestSudoReasonDto(null)).toBeNull();
});
