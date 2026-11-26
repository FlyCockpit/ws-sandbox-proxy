import enSdkKeys from "@wssp/locales/src/en-US/sdkKeys.json";
import esSdkKeys from "@wssp/locales/src/es-MX/sdkKeys.json";
import { describe, expect, it } from "vitest";

import {
  credentialProblem,
  credentialsUseRevealsValues,
  EXPIRY_PRESETS,
  expiresAtFor,
  hostTokenDraftProblems,
  hostTokenMintInput,
  isTwoFactorRequiredError,
  offeredScopeGroups,
  SCOPE_GROUPS,
  type SdkKeyDraft,
  SERVICE_SCOPES,
  scopeKey,
  sdkKeyDraftProblems,
  sdkKeyMintInput,
  selectableTemplates,
  unusableScopes,
} from "./credential-rules";

const hosts = [
  { id: "h1", deletionRequestedAt: null },
  { id: "h2", deletionRequestedAt: null },
  { id: "gone", deletionRequestedAt: new Date() },
];
const templates = [
  { id: "t1", availability: [{ hostId: "h1", status: "AVAILABLE" as const }], retiredAt: null },
  { id: "t2", availability: [{ hostId: "h2", status: "AVAILABLE" as const }], retiredAt: null },
  {
    id: "old",
    availability: [{ hostId: "h1", status: "AVAILABLE" as const }],
    retiredAt: new Date(),
  },
];
const draft = (overrides: Partial<SdkKeyDraft> = {}): SdkKeyDraft => ({
  name: "ci",
  scopes: ["sandboxes:read"],
  resourceMode: "ALL_OWNED",
  hostIds: [],
  templateRevisionIds: [],
  expiry: "never",
  ...overrides,
});

describe("scope dependencies", () => {
  it("commands:read permits discovery; operations:cancel needs a mutation scope", () => {
    expect(unusableScopes(["commands:read"])).toEqual([]);
    expect(unusableScopes(["commands:read", "operations:read"])).toEqual([]);
    expect(unusableScopes(["operations:cancel"])).toEqual(["operations:cancel"]);
    expect(unusableScopes(["operations:cancel", "operations:read"])).toEqual(["operations:cancel"]);
    for (const mutation of [
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "commands:execute",
      "files:read",
      "files:write",
    ]) {
      expect(unusableScopes(["operations:cancel", mutation as never])).toEqual([]);
    }
    expect(unusableScopes([...SERVICE_SCOPES])).toEqual([]);
  });

  it("every scope is shown once, and each one that can be unusable has a translated hint", () => {
    const shown = SCOPE_GROUPS.flatMap((group) => group.scopes);
    expect([...shown].sort()).toEqual([...SERVICE_SCOPES].sort());
    const aloneUnusable = SERVICE_SCOPES.filter((scope) => unusableScopes([scope]).length > 0);
    for (const bundle of [enSdkKeys, esSdkKeys]) {
      const needs = Object.entries(bundle.scopeNeeds).flatMap(([group, entries]) =>
        Object.keys(entries).map((action) => `${group}:${action}`),
      );
      expect(needs.sort()).toEqual([...aloneUnusable].sort());
      for (const scope of SERVICE_SCOPES) {
        const [group, action] = scopeKey(scope).split(".") as [string, string];
        expect((bundle.scope as Record<string, Record<string, string>>)[group]?.[action]).toEqual(
          expect.any(String),
        );
      }
    }
  });
});

describe("credentials:use login allowlist", () => {
  const allowlist = {
    scopes: [
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "credentials:use",
    ] as SdkKeyDraft["scopes"],
    resourceMode: "ALLOWLIST" as const,
    hostIds: ["h1"],
    templateRevisionIds: ["t1"],
  };
  it("needs at least one login on an allowlist key with credentials:use", () => {
    expect(sdkKeyDraftProblems(draft(allowlist), { hosts, templates })).toEqual([
      "credentialsUseNeedsLogins",
    ]);
    expect(
      sdkKeyDraftProblems(draft({ ...allowlist, credentialIds: ["cred_1"] }), { hosts, templates }),
    ).toEqual([]);
    expect(
      sdkKeyDraftProblems(
        draft({
          scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy", "credentials:use"],
        }),
        {
          hosts,
          templates,
        },
      ),
    ).toEqual([]);
  });

  it("sends the login allowlist only for allowlist keys", () => {
    expect(
      sdkKeyMintInput(draft({ ...allowlist, credentialIds: ["c1", "c1", "c2"] }), 0).credentialIds,
    ).toEqual(["c1", "c2"]);
    expect(sdkKeyMintInput(draft({ credentialIds: ["c1"] }), 0)).not.toHaveProperty(
      "credentialIds",
    );
  });

  it("maps the server's mint refusal and discloses use with execute or files:read", () => {
    expect(
      credentialProblem({ status: 400, data: { code: "sdk_key.credentials_use_needs_logins" } }),
    ).toBe("credentialsUseNeedsLogins");
    expect(credentialProblem({ status: 400, data: { code: "agent_token.expiry_policy" } })).toBe(
      "agentExpiryPolicy",
    );
    expect(credentialsUseRevealsValues(["credentials:use", "commands:execute"])).toBe(true);
    expect(credentialsUseRevealsValues(["credentials:use", "files:read"])).toBe(true);
    expect(
      credentialsUseRevealsValues([
        "credentials:use",
        "sandboxes:create",
        "sandboxes:manage",
        "sandboxes:destroy",
      ]),
    ).toBe(false);
    expect(credentialsUseRevealsValues(["commands:execute", "files:read"])).toBe(false);
  });
});

describe("sdk key drafts", () => {
  it("accepts a valid all-owned draft and rejects empty or unusable scopes and names", () => {
    expect(sdkKeyDraftProblems(draft(), { hosts, templates })).toEqual([]);
    expect(sdkKeyDraftProblems(draft({ name: "  ", scopes: [] }), { hosts, templates })).toEqual([
      "nameRequired",
      "noScopes",
    ]);
    expect(
      sdkKeyDraftProblems(draft({ name: "x".repeat(121), scopes: ["commands:read"] }), {
        hosts,
        templates,
      }),
    ).toEqual(["nameTooLong"]);
  });

  it("refuses webhooks:write unless the key covers all owned resources and usable pools", () => {
    expect(
      sdkKeyDraftProblems(draft({ scopes: ["webhooks:write"] }), { hosts, templates }),
    ).toEqual([]);
    expect(
      sdkKeyDraftProblems(
        draft({ scopes: ["webhooks:write"], poolMode: "SELECTED", poolIds: [] }),
        {
          hosts,
          templates,
        },
      ),
    ).toContain("webhooksRequireAllOwned");
    expect(
      credentialProblem({
        code: "BAD_REQUEST",
        data: { code: "sdk_key.webhooks_requires_all_owned" },
      }),
    ).toBe("webhooksRequireAllOwned");
  });

  it("allowlists need hosts and templates, selectable ones, with each template on a selected host", () => {
    const allow = (hostIds: string[], templateRevisionIds: string[]) =>
      sdkKeyDraftProblems(draft({ resourceMode: "ALLOWLIST", hostIds, templateRevisionIds }), {
        hosts,
        templates,
      });
    expect(allow([], [])).toEqual(["noHosts", "noTemplates"]);
    expect(allow(["h1"], ["t1"])).toEqual([]);
    expect(allow(["h1"], ["t2"])).toEqual(["unknownTemplate"]);
    expect(allow(["h1"], ["old"])).toEqual(["unknownTemplate"]);
    expect(allow(["gone"], ["t1"])).toEqual(["unknownHost", "unknownTemplate"]);
    expect(allow(["foreign"], ["t1"])).toEqual(["unknownHost", "unknownTemplate"]);
    expect(selectableTemplates(templates, ["h1", "h2"]).map((t) => t.id)).toEqual(["t1", "t2"]);
  });

  it("builds the exact mint input: canonical scopes, trimmed name, allowlists only when restricted", () => {
    const now = Date.UTC(2026, 0, 1);
    expect(
      sdkKeyMintInput(
        draft({
          name: " ci ",
          scopes: ["operations:read", "commands:read"],
          hostIds: ["h1"],
          templateRevisionIds: ["t1"],
          expiry: "7d",
        }),
        now,
      ),
    ).toEqual({
      name: "ci",
      scopes: ["commands:read", "operations:read"],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      expiresAt: new Date(now + 7 * 86_400_000),
    });
    expect(
      sdkKeyMintInput(
        draft({ resourceMode: "ALLOWLIST", hostIds: ["h1", "h1"], templateRevisionIds: ["t1"] }),
        now,
      ),
    ).toMatchObject({ hostIds: ["h1"], templateRevisionIds: ["t1"], expiresAt: null });
  });
});

describe("host token drafts", () => {
  it("needs a name and a selectable host", () => {
    expect(hostTokenDraftProblems({ name: "", hostId: "", expiry: "never" }, hosts)).toEqual([
      "nameRequired",
      "noHost",
    ]);
    expect(hostTokenDraftProblems({ name: "a", hostId: "gone", expiry: "never" }, hosts)).toEqual([
      "unknownHost",
    ]);
    expect(hostTokenDraftProblems({ name: "a", hostId: "h1", expiry: "never" }, hosts)).toEqual([]);
    expect(hostTokenMintInput({ name: " a ", hostId: "h1", expiry: "never" }, 0)).toEqual({
      name: "a",
      hostId: "h1",
      expiresAt: null,
    });
  });

  it("expiry presets are absolute times from submit", () => {
    expect(EXPIRY_PRESETS).toEqual(["never", "7d", "30d", "90d", "365d"]);
    expect(expiresAtFor("never", 5)).toBeNull();
    expect(expiresAtFor("365d", 0)?.getTime()).toBe(365 * 86_400_000);
  });
});

describe("errors", () => {
  it("recognizes only the structured forced-2FA refusal", () => {
    expect(
      isTwoFactorRequiredError({ code: "FORBIDDEN", data: { code: "auth.two_factor_required" } }),
    ).toBe(true);
    expect(isTwoFactorRequiredError({ code: "FORBIDDEN", message: "Two-factor" })).toBe(false);
    expect(
      isTwoFactorRequiredError({ code: "NOT_FOUND", data: { code: "auth.two_factor_required" } }),
    ).toBe(false);
    expect(isTwoFactorRequiredError(null)).toBe(false);
  });

  it("maps server refusals to explanations", () => {
    expect(credentialProblem({ code: "NOT_FOUND" })).toBe("notFound");
    expect(credentialProblem({ code: "CONFLICT" })).toBe("changed");
    expect(credentialProblem({ code: "FORBIDDEN" })).toBe("forbidden");
    expect(credentialProblem({ code: "BAD_REQUEST" })).toBe("invalid");
    expect(credentialProblem({ status: 429 })).toBe("rateLimited");
    expect(credentialProblem(new Error("x"))).toBe("generic");
    // The server's own mint-rule codes (shared definitions in @wssp/api).
    expect(
      credentialProblem({ code: "BAD_REQUEST", data: { code: "sdk_key.unusable_scopes" } }),
    ).toBe("unusableScopes");
    expect(
      credentialProblem({
        code: "BAD_REQUEST",
        data: { code: "sdk_key.template_not_on_selected_host" },
      }),
    ).toBe("templateOffHost");
  });
});

it("pool grants are independent, loaded owner choices; pending revision associations remain mintable", () => {
  const pending = {
    id: "pending",
    retiredAt: null,
    availability: [{ hostId: "h1", status: "PENDING" as const }],
  };
  const input = draft({
    resourceMode: "ALLOWLIST",
    hostIds: ["h1"],
    templateRevisionIds: ["pending"],
    poolIds: ["pool-a"],
  });
  const choices = { hosts, templates: [pending], pools: [{ id: "pool-a" }] };
  expect(sdkKeyDraftProblems(input, choices)).toEqual([]);
  expect(sdkKeyDraftProblems({ ...input, poolIds: ["foreign"] }, choices)).toEqual(["unknownPool"]);
  expect(sdkKeyDraftProblems({ ...input, hostIds: [], poolMode: "SELECTED" }, choices)).toEqual([]);
  expect(sdkKeyDraftProblems({ ...input, templateRevisionIds: [] }, choices)).toEqual([
    "noTemplates",
  ]);
  expect(sdkKeyMintInput(input, 0)).toMatchObject({
    poolIds: ["pool-a"],
    hostIds: ["h1"],
    templateRevisionIds: ["pending"],
  });
});

describe("sandboxes:connect scope", () => {
  it("stands alone in its own described group, offered only on the SDK key form", () => {
    const connect = SCOPE_GROUPS.filter((group) => group.scopes.includes("sandboxes:connect"));
    expect(connect).toEqual([{ id: "connect", scopes: ["sandboxes:connect"] }]);
    const scopesOf = (groups: ReturnType<typeof offeredScopeGroups>) =>
      groups.flatMap((group) => group.scopes);
    expect(scopesOf(offeredScopeGroups("sdk"))).toContain("sandboxes:connect");
    for (const form of ["agent", "consent"] as const) {
      expect(scopesOf(offeredScopeGroups(form))).not.toContain("sandboxes:connect");
      expect(scopesOf(offeredScopeGroups(form, ["sandboxes:read", "sandboxes:connect"]))).toEqual([
        "sandboxes:read",
      ]);
      expect(offeredScopeGroups(form).some((group) => group.id === "connect")).toBe(false);
    }
    for (const bundle of [enSdkKeys, esSdkKeys]) {
      expect(bundle.scopeGroup.connect).toEqual(expect.any(String));
      expect(bundle.scopeGroupHint.connect).toEqual(expect.any(String));
    }
  });
});
