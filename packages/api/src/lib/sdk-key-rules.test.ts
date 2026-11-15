import { describe, expect, it } from "vitest";
import {
  credentialsUseNeedsLogins,
  isTemplateOnSelectedHosts,
  templatesOffSelectedHosts,
  unusableScopes,
  webhooksScopeNeedsAllOwned,
} from "./sdk-key-rules";
import { SERVICE_SCOPES } from "./service-scopes";

describe("SDK-key mint rules shared by the server and the web form", () => {
  it("every scope alone or with its dependencies is usable; cancel and output need partners", () => {
    expect(unusableScopes([...SERVICE_SCOPES])).toEqual([]);
    expect(unusableScopes(["operations:cancel"])).toEqual(["operations:cancel"]);
    expect(unusableScopes(["commands:read"])).toEqual([]);
    expect(unusableScopes(["commands:read", "operations:read"])).toEqual([]);
    expect(
      unusableScopes([
        "operations:cancel",
        "sandboxes:create",
        "sandboxes:manage",
        "sandboxes:destroy",
      ]),
    ).toEqual([]);
    // `credentials:use` puts a login into a sandbox: it needs `sandboxes:manage`.
    expect(unusableScopes(["credentials:use"])).toEqual(["credentials:use"]);
    expect(
      unusableScopes([
        "credentials:use",
        "sandboxes:create",
        "sandboxes:manage",
        "sandboxes:destroy",
      ]),
    ).toEqual([]);
    for (const scope of SERVICE_SCOPES) {
      if (scope === "operations:cancel" || scope === "commands:read" || scope === "credentials:use")
        continue;
      expect(unusableScopes([scope])).toEqual([]);
    }
  });

  it("credentials:use on an allowlist key needs at least one allowlisted login", () => {
    const scopes = [
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "credentials:use",
    ] as const;
    expect(credentialsUseNeedsLogins(scopes, "ALLOWLIST", [])).toBe(true);
    expect(credentialsUseNeedsLogins(scopes, "ALLOWLIST", ["cred-1"])).toBe(false);
    expect(credentialsUseNeedsLogins(scopes, "ALL_OWNED", [])).toBe(false);
    expect(
      credentialsUseNeedsLogins(
        ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
        "ALLOWLIST",
        [],
      ),
    ).toBe(false);
  });

  it("webhooks:write is mintable only on ALL_OWNED + ALL_USABLE keys", () => {
    expect(webhooksScopeNeedsAllOwned(["webhooks:write"], "ALL_OWNED", undefined)).toBe(false);
    expect(webhooksScopeNeedsAllOwned(["webhooks:write"], "ALL_OWNED", "ALL_USABLE")).toBe(false);
    expect(webhooksScopeNeedsAllOwned(["webhooks:write"], "ALL_OWNED", "SELECTED")).toBe(true);
    expect(webhooksScopeNeedsAllOwned(["webhooks:write"], "ALLOWLIST", undefined)).toBe(true);
    expect(webhooksScopeNeedsAllOwned(["webhooks:write"], "ALLOWLIST", "ALL_USABLE")).toBe(true);
    expect(webhooksScopeNeedsAllOwned(["sandboxes:read"], "ALLOWLIST", "SELECTED")).toBe(false);
  });

  it("a template must be active and on a selected host", () => {
    const active = {
      id: "t1",
      availability: [{ hostId: "h1", status: "AVAILABLE" as const }],
      retiredAt: null,
    };
    const elsewhere = {
      id: "t2",
      availability: [{ hostId: "h2", status: "AVAILABLE" as const }],
      retiredAt: null,
    };
    const retired = { id: "t3", availability: [], retiredAt: "2026-09-01T00:00:00Z" };
    expect(isTemplateOnSelectedHosts(active, ["h1"])).toBe(true);
    expect(isTemplateOnSelectedHosts(active, new Set(["h1"]))).toBe(true);
    expect(isTemplateOnSelectedHosts(elsewhere, ["h1"])).toBe(false);
    expect(isTemplateOnSelectedHosts(retired, ["h1"])).toBe(false);
    expect(templatesOffSelectedHosts([active, elsewhere, retired], ["h1"])).toEqual(["t2", "t3"]);
    expect(templatesOffSelectedHosts([active, elsewhere], ["h1", "h2"])).toEqual([]);
  });
});

it("host execution/file scopes need a directly owned host grant, not only a pool", async () => {
  const { hostScopesNeedHostGrant } = await import("./sdk-key-rules");
  for (const scope of ["hosts:execute", "hosts:files"] as const) {
    expect(hostScopesNeedHostGrant([scope], "ALLOWLIST", [])).toBe(true);
    expect(hostScopesNeedHostGrant([scope], "ALLOWLIST", ["owned-host"])).toBe(false);
    expect(hostScopesNeedHostGrant([scope], "ALL_OWNED", [])).toBe(false);
  }
  expect(hostScopesNeedHostGrant(["hosts:read"], "ALLOWLIST", [])).toBe(false);
});
