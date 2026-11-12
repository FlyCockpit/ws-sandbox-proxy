import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  recordedEgressPolicy,
  recordedEgressRequest,
  resolveCreateEgressPolicy,
  resolveEffectiveEgress,
} from "./egress-policy";

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

describe("egress policy hashing", () => {
  it("hashes the canonical JSON text directly, with golden digests", () => {
    const host = { ownerId: "owner", egressOpen: true, openEgressForOthers: false };
    const effective = (request: Parameters<typeof resolveEffectiveEgress>[0]) =>
      resolveEffectiveEgress(request, host, "owner").effective;
    const denyAll = effective(resolveCreateEgressPolicy({ mode: "allowlist" }));
    expect(denyAll.policy).toEqual({ mode: "allowlist", domains: [], cidrs: [] });
    // Stored and dispatched form: byte-identical to the pre-mode wire.
    expect(denyAll.wire).toEqual({ domains: [], cidrs: [] });
    // Independently computed golden digests (sha256 of the exact UTF-8 text).
    expect(denyAll.hash).toBe(sha256('{"cidrs":[],"domains":[]}'));
    expect(denyAll.hash).toBe("cd54f076503987212abf92b598f837d67f1e70de63317600961cf181ef0f7caa");

    const sample = effective(
      resolveCreateEgressPolicy({ domains: ["Example.COM."], cidrs: ["128.66.1.2/24"] }),
    );
    expect(sample.wire).toEqual({ domains: ["example.com"], cidrs: ["128.66.1.0/24"] });
    expect(sample.hash).toBe(sha256('{"cidrs":["128.66.1.0/24"],"domains":["example.com"]}'));
    expect(sample.hash).toBe("876100f52b83a1dd52ab4ec57e4a53190197d9198112af99c14a93650fd9e810");

    const open = effective(resolveCreateEgressPolicy({ mode: "open" }));
    expect(open.wire).toEqual({ mode: "open", domains: [], cidrs: [] });
    expect(open.hash).toBe(sha256('{"cidrs":[],"domains":[],"mode":"open"}'));
  });

  it("an omitted egress requests open; any grant key without mode is allowlist", () => {
    expect(resolveCreateEgressPolicy(undefined)).toEqual({ mode: "open", domains: [], cidrs: [] });
    expect(resolveCreateEgressPolicy({})).toEqual({ mode: "open", domains: [], cidrs: [] });
    expect(resolveCreateEgressPolicy({ domains: [], cidrs: [] }).mode).toBe("allowlist");
    expect(resolveCreateEgressPolicy({ cidrs: [] }).mode).toBe("allowlist");
  });

  it("stored rows read back from the wire form; a second spelling fails closed", () => {
    const hash = "a".repeat(64);
    expect(
      recordedEgressPolicy({ egressPolicy: { domains: [], cidrs: [] }, egressPolicyHash: hash }),
    ).toEqual({
      policy: { mode: "allowlist", domains: [], cidrs: [] },
      wire: { domains: [], cidrs: [] },
      hash,
    });
    expect(
      recordedEgressPolicy({
        egressPolicy: { mode: "open", domains: [], cidrs: [] },
        egressPolicyHash: hash,
      }).policy.mode,
    ).toBe("open");
    expect(() =>
      recordedEgressPolicy({
        egressPolicy: { mode: "allowlist", domains: [], cidrs: [] },
        egressPolicyHash: hash,
      }),
    ).toThrow();
  });

  it("pre-policy rows read back as deny-all with the same golden digest", () => {
    expect(recordedEgressPolicy({ egressPolicy: null, egressPolicyHash: null })).toEqual({
      policy: { mode: "allowlist", domains: [], cidrs: [] },
      wire: { domains: [], cidrs: [] },
      hash: "cd54f076503987212abf92b598f837d67f1e70de63317600961cf181ef0f7caa",
    });
  });

  it("normalization failures are the typed catalog error", () => {
    for (const egress of [{ cidrs: ["10.0.0.0/8"] }, { cidrs: ["2001:4860::/32"] }])
      expect(() => resolveCreateEgressPolicy(egress)).toThrowError(
        expect.objectContaining({ data: { code: "sandbox.egress_policy_invalid" } }),
      );
    expect(() => resolveCreateEgressPolicy({ domains: ["*.example.com"] })).toThrowError(
      expect.objectContaining({
        code: "BAD_REQUEST",
        data: { code: "sandbox.egress_policy_invalid" },
      }),
    );
  });
});

describe("resolveEffectiveEgress (§1.2, security-critical)", () => {
  const OWNER = "owner-a";
  const FOREIGN = "owner-b";
  const fallback = { domains: ["pypi.org"], cidrs: ["128.66.0.0/16"] };
  const openRequest = resolveCreateEgressPolicy({ mode: "open", ...fallback });
  const allowRequest = resolveCreateEgressPolicy(fallback);
  const host = (ownerId: string, egressOpen: boolean, openEgressForOthers: boolean) => ({
    ownerId,
    egressOpen,
    openEgressForOthers,
  });

  it("row 1: an allowlist request is the effective policy everywhere, no reason", () => {
    for (const h of [
      host(OWNER, true, false),
      host(FOREIGN, true, true),
      host(FOREIGN, false, false),
    ]) {
      const { effective, reason } = resolveEffectiveEgress(allowRequest, h, OWNER);
      expect(effective.policy).toEqual({ mode: "allowlist", ...allowRequest });
      expect(reason).toBeNull();
    }
  });

  it("row 2: a host that cannot serve open → allowlist with the fallback grants, HOST_UNSUPPORTED", () => {
    for (const h of [host(OWNER, false, false), host(FOREIGN, false, true)]) {
      const { effective, reason } = resolveEffectiveEgress(openRequest, h, OWNER);
      expect(effective.policy).toEqual({
        mode: "allowlist",
        domains: ["pypi.org"],
        cidrs: ["128.66.0.0/16"],
      });
      expect(effective.wire).not.toHaveProperty("mode");
      expect(reason).toBe("HOST_UNSUPPORTED");
    }
  });

  it("row 3: a foreign node without consent → allowlist with the fallback grants, NODE_POLICY", () => {
    const { effective, reason } = resolveEffectiveEgress(
      openRequest,
      host(FOREIGN, true, false),
      OWNER,
    );
    expect(effective.policy).toEqual({
      mode: "allowlist",
      domains: ["pypi.org"],
      cidrs: ["128.66.0.0/16"],
    });
    expect(reason).toBe("NODE_POLICY");
    // An open request with no fallback grants becomes deny-all.
    expect(
      resolveEffectiveEgress(
        resolveCreateEgressPolicy(undefined),
        host(FOREIGN, true, false),
        OWNER,
      ).effective.hash,
    ).toBe("cd54f076503987212abf92b598f837d67f1e70de63317600961cf181ef0f7caa");
  });

  it("row 4: own capable node, or a consenting foreign node → open with no grants", () => {
    for (const h of [
      host(OWNER, true, false),
      host(OWNER, true, true),
      host(FOREIGN, true, true),
    ]) {
      const { effective, reason } = resolveEffectiveEgress(openRequest, h, OWNER);
      expect(effective.policy).toEqual({ mode: "open", domains: [], cidrs: [] });
      expect(effective.wire).toEqual({ mode: "open", domains: [], cidrs: [] });
      expect(effective.hash).toBe(sha256('{"cidrs":[],"domains":[],"mode":"open"}'));
      expect(reason).toBeNull();
    }
  });

  it("the stored request reads back only in canonical normalized form", () => {
    expect(recordedEgressRequest(openRequest)).toEqual(openRequest);
    expect(recordedEgressRequest(null)).toBeNull();
    expect(recordedEgressRequest({ domains: [], cidrs: [] })).toBeNull();
    expect(recordedEgressRequest({ mode: "open", domains: ["B.example"], cidrs: [] })).toBeNull();
  });

  it("has exactly one importer outside tests: placement-materialize.ts (fixed at materialization)", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
    const roots = ["packages", "apps"].map((dir) => join(root, dir));
    const importers: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        if (name === "node_modules" || name === "dist" || name.startsWith(".")) continue;
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (
          /\.(ts|tsx)$/.test(name) &&
          !/\.test\.tsx?$/.test(name) &&
          !path.endsWith(join("sandbox", "egress-policy.ts")) &&
          readFileSync(path, "utf8").includes("resolveEffectiveEgress")
        )
          importers.push(relative(root, path));
      }
    };
    for (const dir of roots) walk(dir);
    expect(importers).toEqual([
      join("packages", "api", "src", "sandbox", "placement-materialize.ts"),
    ]);
  });
});
