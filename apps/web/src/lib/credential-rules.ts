import {
  API_KEY_ONLY_SCOPES,
  credentialsUseNeedsLogins,
  hostScopesNeedHostGrant,
  isTemplateOnSelectedHosts,
  SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE,
  SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE,
  SDK_KEY_UNUSABLE_SCOPES_CODE,
  SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE,
  unusableScopes,
  webhooksScopeNeedsAllOwned,
} from "@wssp/api/lib/sdk-key-rules";
import { SERVICE_SCOPES, type ServiceScope } from "@wssp/api/lib/service-scopes";
import { TWO_FACTOR_REQUIRED_ERROR_CODE } from "@wssp/auth/two-factor-policy";

/**
 * Pure rules for the Host credentials and SDK keys pages (C45). They decide
 * what the browser may submit; the server still decides every mint and
 * revoke (owned resources, known scopes, 2FA policy). The scope-dependency
 * and template-on-selected-host rules are the server's own functions
 * (`@wssp/api/lib/sdk-key-rules`): the server refuses the same drafts.
 */

export { API_KEY_ONLY_SCOPES, SERVICE_SCOPES, type ServiceScope, unusableScopes };

/**
 * Scope groups in the order the mint form shows them. `connect` stands alone
 * with its own description: only the SDK key form
 * offers it, never preselected; agent tokens and OAuth consent never do.
 */
export const SCOPE_GROUPS: readonly { id: string; scopes: readonly ServiceScope[] }[] = [
  { id: "hosts", scopes: ["hosts:read", "hosts:execute", "hosts:files"] },
  { id: "pools", scopes: ["pools:read"] },
  { id: "templates", scopes: ["templates:read", "templates:write", "templates:build"] },
  {
    id: "sandboxes",
    scopes: [
      "sandboxes:read",
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "sandboxes:tunnel",
    ],
  },
  { id: "connect", scopes: ["sandboxes:connect"] },
  { id: "commands", scopes: ["commands:read", "commands:execute"] },
  { id: "files", scopes: ["files:read", "files:write"] },
  { id: "operations", scopes: ["operations:read", "operations:cancel"] },
  { id: "webhooks", scopes: ["webhooks:write"] },
  { id: "credentials", scopes: ["credentials:read", "credentials:write", "credentials:use"] },
];

/** Groups shown with a description under their title (`sdkKeys:scopeGroupHint.<id>`). */
export const DESCRIBED_SCOPE_GROUPS: ReadonlySet<string> = new Set(["connect"]);

/**
 * The scope groups a mint form offers: `sandboxes:connect` (and any other
 * API-key-only scope) only on the dashboard SDK key form.
 */
export function offeredScopeGroups(
  form: "sdk" | "agent" | "consent",
  offered?: readonly ServiceScope[],
): { id: string; scopes: ServiceScope[] }[] {
  return SCOPE_GROUPS.map((group) => ({
    id: group.id,
    scopes: group.scopes.filter(
      (scope) =>
        (form === "sdk" || !API_KEY_ONLY_SCOPES.includes(scope)) &&
        (!offered || offered.includes(scope)),
    ),
  })).filter((group) => group.scopes.length > 0);
}

/** i18n-safe key for a scope: `commands:read` → `commands.read`. */
export function scopeKey(scope: ServiceScope): string {
  return scope.replace(":", ".");
}

export const EXPIRY_PRESETS = ["never", "7d", "30d", "90d", "365d"] as const;
export type ExpiryPreset = (typeof EXPIRY_PRESETS)[number];

const DAY_MS = 86_400_000;
const PRESET_DAYS: Record<Exclude<ExpiryPreset, "never">, number> = {
  "7d": 7,
  "30d": 30,
  "90d": 90,
  "365d": 365,
};

export function isExpiryPreset(value: string): value is ExpiryPreset {
  return (EXPIRY_PRESETS as readonly string[]).includes(value);
}

/** The absolute expiry sent to the server for a preset, computed at submit time. */
export function expiresAtFor(preset: ExpiryPreset, now: number): Date | null {
  return preset === "never" ? null : new Date(now + PRESET_DAYS[preset] * DAY_MS);
}

export type ResourceMode = "ALL_OWNED" | "ALLOWLIST";

export type SelectableHost = { id: string; deletionRequestedAt: Date | string | null };
export type SelectableTemplate = {
  id: string;
  availability: readonly {
    hostId: string;
    status: "AVAILABLE" | "PENDING" | "MISSING" | "REJECTED";
  }[];
  retiredAt: Date | string | null;
};

/** Hosts a new credential or allowlist may name: owned and not pending deletion. */
export function selectableHosts<H extends SelectableHost>(hosts: readonly H[]): H[] {
  return hosts.filter((host) => host.deletionRequestedAt == null);
}

/** Active exact revisions with verified or pending associations on a selected host. */
export function selectableTemplates<T extends SelectableTemplate>(
  templates: readonly T[],
  hostIds: readonly string[],
): T[] {
  const hosts = new Set(hostIds);
  return templates.filter((template) => isTemplateOnSelectedHosts(template, hosts));
}

export type SdkKeyDraft = {
  name: string;
  scopes: readonly ServiceScope[];
  resourceMode: ResourceMode;
  ownSandboxesOnly?: boolean;
  hostIds: readonly string[];
  templateRevisionIds: readonly string[];
  poolIds?: readonly string[];
  poolMode?: "ALL_USABLE" | "SELECTED";
  /** ALLOWLIST keys: the CLI logins the key reaches (required with credentials:use). */
  credentialIds?: readonly string[];
  expiry: ExpiryPreset;
};

export type SdkKeyDraftProblem =
  | "nameRequired"
  | "nameTooLong"
  | "noScopes"
  | "unusableScopes"
  | "webhooksRequireAllOwned"
  | "noHosts"
  | "noTemplates"
  | "unknownHost"
  | "unknownTemplate"
  | "unknownPool"
  | "credentialsUseNeedsLogins";

export const CREDENTIAL_NAME_MAX = 120;

function nameProblem(name: string): "nameRequired" | "nameTooLong" | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return "nameRequired";
  if (trimmed.length > CREDENTIAL_NAME_MAX) return "nameTooLong";
  return null;
}

/**
 * Every reason the draft cannot be minted. Resources are checked against the
 * owner's loaded, selectable hosts/templates, so a stale or foreign ID (or a
 * template on an unselected host) cannot be submitted.
 */
export function sdkKeyDraftProblems(
  draft: SdkKeyDraft,
  options: {
    hosts: readonly SelectableHost[];
    templates: readonly SelectableTemplate[];
    pools?: readonly { id: string }[];
  },
): SdkKeyDraftProblem[] {
  const problems: SdkKeyDraftProblem[] = [];
  const name = nameProblem(draft.name);
  if (name) problems.push(name);
  if (draft.scopes.length === 0) problems.push("noScopes");
  else if (unusableScopes(draft.scopes).length > 0) problems.push("unusableScopes");
  if (webhooksScopeNeedsAllOwned(draft.scopes, draft.resourceMode, draft.poolMode))
    problems.push("webhooksRequireAllOwned");
  if (credentialsUseNeedsLogins(draft.scopes, draft.resourceMode, draft.credentialIds ?? []))
    problems.push("credentialsUseNeedsLogins");
  if (hostScopesNeedHostGrant(draft.scopes, draft.resourceMode, draft.hostIds))
    problems.push("noHosts");
  if (draft.resourceMode === "ALLOWLIST") {
    const hostIds = new Set(selectableHosts(options.hosts).map((host) => host.id));
    const templateRevisionIds = new Set(
      (draft.hostIds.length
        ? selectableTemplates(options.templates, draft.hostIds)
        : options.templates.filter((item) => item.retiredAt == null)
      ).map((template) => template.id),
    );
    const poolIds = new Set(options.pools?.map((pool) => pool.id) ?? []);
    if (draft.poolMode !== "ALL_USABLE" && draft.poolIds?.some((id) => !poolIds.has(id)))
      problems.push("unknownPool");
    if (draft.hostIds.length === 0 && draft.poolMode !== "ALL_USABLE" && !draft.poolIds?.length)
      problems.push("noHosts");
    if (
      draft.scopes.some((scope) => !scope.startsWith("hosts:")) &&
      draft.templateRevisionIds.length === 0
    )
      problems.push("noTemplates");
    if (draft.hostIds.some((id) => !hostIds.has(id))) problems.push("unknownHost");
    if (draft.templateRevisionIds.some((id) => !templateRevisionIds.has(id)))
      problems.push("unknownTemplate");
  }
  if (
    draft.resourceMode === "ALL_OWNED" &&
    draft.poolMode === "SELECTED" &&
    draft.poolIds?.some((id) => !options.pools?.some((p) => p.id === id))
  )
    problems.push("unknownPool");
  return problems;
}

/** The exact `sdkKeys.create` input for a valid draft (allowlists only in ALLOWLIST mode). */
export function sdkKeyMintInput(draft: SdkKeyDraft, now: number) {
  const allowlist = draft.resourceMode === "ALLOWLIST";
  return {
    name: draft.name.trim(),
    scopes: SERVICE_SCOPES.filter((scope) => draft.scopes.includes(scope)),
    resourceMode: draft.resourceMode,
    hostIds: allowlist ? [...new Set(draft.hostIds)] : [],
    templateRevisionIds: allowlist ? [...new Set(draft.templateRevisionIds)] : [],
    ...(draft.poolMode
      ? {
          poolMode: draft.poolMode,
          poolIds: draft.poolMode === "SELECTED" ? [...new Set(draft.poolIds ?? [])] : [],
        }
      : draft.poolIds?.length
        ? { poolIds: allowlist ? [...new Set(draft.poolIds)] : [] }
        : {}),
    ...(allowlist && draft.credentialIds?.length
      ? { credentialIds: [...new Set(draft.credentialIds)] }
      : {}),
    ...(draft.ownSandboxesOnly !== undefined ? { ownSandboxesOnly: draft.ownSandboxesOnly } : {}),
    expiresAt: expiresAtFor(draft.expiry, now),
  };
}

/**
 * `credentials:use` puts a login's value into a guest; with `commands:execute`
 * or `files:read` the key holder can read it back out. The mint form says so.
 */
export function credentialsUseRevealsValues(scopes: readonly ServiceScope[]): boolean {
  return (
    scopes.includes("credentials:use") &&
    (scopes.includes("commands:execute") || scopes.includes("files:read"))
  );
}

export type HostTokenDraft = { name: string; hostId: string; expiry: ExpiryPreset };
export type HostTokenDraftProblem = "nameRequired" | "nameTooLong" | "noHost" | "unknownHost";

export function hostTokenDraftProblems(
  draft: HostTokenDraft,
  hosts: readonly SelectableHost[],
): HostTokenDraftProblem[] {
  const problems: HostTokenDraftProblem[] = [];
  const name = nameProblem(draft.name);
  if (name) problems.push(name);
  if (!draft.hostId) problems.push("noHost");
  else if (!selectableHosts(hosts).some((host) => host.id === draft.hostId))
    problems.push("unknownHost");
  return problems;
}

export function hostTokenMintInput(draft: HostTokenDraft, now: number) {
  return {
    hostId: draft.hostId,
    name: draft.name.trim(),
    expiresAt: expiresAtFor(draft.expiry, now),
  };
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

/** The server refused because the caller must enroll in 2FA first. */
export function isTwoFactorRequiredError(error: unknown): boolean {
  const shape = shapeOf(error);
  if (shape.code !== "FORBIDDEN" && shape.status !== 403) return false;
  const data = shape.data;
  return (
    data != null &&
    typeof data === "object" &&
    (data as { code?: unknown }).code === TWO_FACTOR_REQUIRED_ERROR_CODE
  );
}

export type CredentialProblem =
  | "unusableScopes"
  | "templateOffHost"
  | "webhooksRequireAllOwned"
  | "credentialsUseNeedsLogins"
  | "notFound"
  | "agentLimit"
  | "agentExpiryPolicy"
  | "changed"
  | "forbidden"
  | "invalid"
  | "rateLimited"
  | "generic";

/** Map a failed credential mint/revoke to the explanation shown next to it. */
export function credentialProblem(error: unknown): CredentialProblem {
  const shape = shapeOf(error);
  const code =
    shape.data != null && typeof shape.data === "object"
      ? (shape.data as { code?: unknown }).code
      : undefined;
  if (code === "agent_token.limit") return "agentLimit";
  if (code === "agent_token.expiry_policy") return "agentExpiryPolicy";
  if (code === SDK_KEY_UNUSABLE_SCOPES_CODE) return "unusableScopes";
  if (code === SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE) return "templateOffHost";
  if (code === SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE) return "webhooksRequireAllOwned";
  if (code === SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE) return "credentialsUseNeedsLogins";
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "CONFLICT" || shape.status === 409) return "changed";
  if (shape.code === "FORBIDDEN" || shape.status === 403) return "forbidden";
  if (shape.code === "BAD_REQUEST" || shape.status === 400) return "invalid";
  if (shape.code === "TOO_MANY_REQUESTS" || shape.status === 429) return "rateLimited";
  return "generic";
}
