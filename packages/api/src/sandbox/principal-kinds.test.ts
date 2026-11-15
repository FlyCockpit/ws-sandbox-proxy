import { describe, expect, it } from "vitest";
import type { ServicePrincipal } from "../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../lib/service-scopes";
import type { BuildPrincipal } from "../template-builds/principal";
import { type AuthorizingPrincipal, sessionPrincipal } from "./contracts";
import {
  assertNever,
  attributionOf,
  budgetSubjectOf,
  buildIdOf,
  controlAllowed,
  credentialExpiryOf,
  dispatchClassOf,
  grantOf,
  isBrowserSession,
  recordedKeyIdOf,
  systemAttribution,
  viewerOf,
} from "./principal-kinds";

const expiresAt = new Date("2026-12-01T00:00:00.000Z");
const key: ServicePrincipal = {
  kind: "sdkKey",
  expiresAt,
  keyId: "key-1",
  ownerId: "user-1",
  resourceMode: "ALLOWLIST",
  scopes: new Set(["sandboxes:read"]),
  allowedHostIds: new Set(["host-1"]),
  allowedRevisionIds: new Set(["rev-1"]),
  allowedPoolIds: new Set(["pool-1"]),
};
const session = sessionPrincipal("user-1");
const keyAttribution: AuthorizingPrincipal = { kind: "sdkKey", keyId: "key-1" };
const sessionAttribution: AuthorizingPrincipal = { kind: "session" };
const system = systemAttribution();
// Test-only stand-ins: the brand is type-only, so the runtime shape is all a
// helper sees (real build principals come from loadBuildPrincipal).
const buildWithKey = {
  kind: "build",
  ownerId: "user-1",
  buildId: "build-1",
  keyId: "key-1",
  key,
} as unknown as BuildPrincipal;
const buildKeyLost = { ...buildWithKey, key: null } as BuildPrincipal;
const buildNoKey = { ...buildWithKey, keyId: null, key: null } as BuildPrincipal;
const buildAttribution: AuthorizingPrincipal = {
  kind: "build",
  buildId: "build-1",
  keyId: "key-1",
};
const keylessBuildAttribution: AuthorizingPrincipal = {
  kind: "build",
  buildId: "build-1",
  keyId: null,
};

describe("principal-kinds helper mapping", () => {
  it("attributes live principals without reconstructing from a nullable key", () => {
    expect(attributionOf(session)).toEqual({ kind: "session" });
    expect(attributionOf(key)).toEqual({ kind: "sdkKey", keyId: "key-1" });
    expect(system).toEqual({ kind: "system" });
    // Fresh objects: a caller mutating one attribution cannot alter another.
    expect(systemAttribution()).not.toBe(system);
  });

  it.each([
    ["session principal", session, null],
    ["SDK key principal", key, "key-1"],
    ["session attribution", sessionAttribution, null],
    ["SDK key attribution", keyAttribution, "key-1"],
    ["system attribution", system, null],
    ["keyed build principal", buildWithKey, "key-1"],
    ["keyless build principal", buildNoKey, null],
    ["keyed build attribution", buildAttribution, "key-1"],
    ["keyless build attribution", keylessBuildAttribution, null],
    ["absent attribution", null, null],
    ["undefined attribution", undefined, null],
  ] as const)("recordedKeyIdOf(%s)", (_name, principal, expected) => {
    expect(recordedKeyIdOf(principal)).toBe(expected);
  });

  it("views a session over every owned and usable resource", () => {
    expect(viewerOf(session)).toEqual({
      ownerId: "user-1",
      ownSandboxesOnly: false,
      resourceMode: "ALL_OWNED",
      allowedHostIds: "allOwned",
      allowedPoolIds: "allUsable",
      allowedRevisionIds: "allOwned",
    });
  });

  it("views an SDK key through its live allowlists", () => {
    const viewer = viewerOf(key);
    expect(viewer).toBe(key);
    expect(viewer.resourceMode).toBe("ALLOWLIST");
    expect(viewer.allowedHostIds).toEqual(new Set(["host-1"]));
    expect(viewer.allowedPoolIds).toEqual(new Set(["pool-1"]));
    expect(viewer.allowedRevisionIds).toEqual(new Set(["rev-1"]));
  });

  it("attributes a build with its real key and exposes its build id", () => {
    expect(attributionOf(buildWithKey)).toEqual(buildAttribution);
    expect(attributionOf(buildNoKey)).toEqual(keylessBuildAttribution);
    expect(buildIdOf(buildWithKey)).toBe("build-1");
    expect(buildIdOf(buildAttribution)).toBe("build-1");
    for (const other of [session, key, sessionAttribution, keyAttribution, system])
      expect(buildIdOf(other)).toBeNull();
  });

  it("views a keyed build through its key's allowlists (r2 N1), never wider", () => {
    expect(viewerOf(buildWithKey)).toBe(key);
    expect(viewerOf(buildNoKey)).toEqual(viewerOf(sessionPrincipal("user-1")));
    // A key that no longer revalidates sees nothing, not the session view.
    expect(viewerOf(buildKeyLost)).toEqual({
      ownerId: "user-1",
      ownSandboxesOnly: true,
      resourceMode: "ALLOWLIST",
      allowedHostIds: new Set(),
      allowedPoolIds: new Set(),
      allowedRevisionIds: new Set(),
    });
  });

  it("grants a build read-class scopes only, and no browser or budget identity", () => {
    const grant = grantOf(buildWithKey);
    expect([...grant].every((scope) => scope.endsWith(":read"))).toBe(true);
    expect(grant.has("sandboxes:create")).toBe(false);
    expect(grant.has("commands:execute")).toBe(false);
    expect(isBrowserSession(buildWithKey)).toBe(false);
    expect(budgetSubjectOf(buildWithKey)).toBeNull();
    expect(budgetSubjectOf(session)).toEqual({ ownerId: "user-1" });
    expect(budgetSubjectOf(key)).toEqual({ ownerId: "user-1" });
    expect(credentialExpiryOf(buildWithKey)).toBe(expiresAt);
    expect(credentialExpiryOf(buildNoKey)).toBeNull();
    expect(credentialExpiryOf(buildKeyLost)?.getTime()).toBe(0);
  });

  it("dispatches build cleanup as system and other build work as build; no relay control", () => {
    for (const attribution of [buildAttribution, keylessBuildAttribution]) {
      expect(controlAllowed(attribution)).toBe(false);
      expect(dispatchClassOf(attribution, "sandbox.kill")).toBe("system");
      expect(dispatchClassOf(attribution, "sandbox.stop")).toBe("system");
      for (const kind of ["command.run", "sandbox.create", "sandbox.capture", "file.put"])
        expect(dispatchClassOf(attribution, kind)).toBe("build");
    }
  });

  it("grants a session every scope and a key only its own", () => {
    expect([...grantOf(session)]).toEqual([...SERVICE_SCOPES]);
    expect(grantOf(key)).toBe(key.scopes);
    expect(grantOf(key).has("hosts:read")).toBe(false);
  });

  it("distinguishes browser sessions and credential expiry", () => {
    expect(isBrowserSession(session)).toBe(true);
    expect(isBrowserSession(key)).toBe(false);
    expect(credentialExpiryOf(session)).toBeNull();
    expect(credentialExpiryOf(key)).toBe(expiresAt);
  });

  it.each([
    ["session", sessionAttribution, true, "principal"],
    ["sdkKey", keyAttribution, true, "principal"],
    ["system", system, false, "system"],
  ] as const)("%s: controlAllowed and dispatchClassOf", (_name, principal, control, klass) => {
    expect(controlAllowed(principal)).toBe(control);
    for (const kind of ["sandbox.kill", "sandbox.stop", "command.run", "sandbox.lease.renew"])
      expect(dispatchClassOf(principal, kind)).toBe(klass);
  });

  it("assertNever refuses an unknown kind, with the caller's error when given", () => {
    const unknown = { kind: "unknown" } as never;
    expect(() => assertNever(unknown)).toThrow("Unhandled principal kind: unknown");
    const refusal = new Error("forbidden");
    expect(() => assertNever(unknown, refusal)).toThrow(refusal);
  });
});
