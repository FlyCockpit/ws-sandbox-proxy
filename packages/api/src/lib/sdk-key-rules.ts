import {
  CANCEL_MUTATION_SCOPES,
  SERVICE_ACTION_REQUIREMENTS,
  type ServiceScope,
} from "./service-scopes";

/**
 * THE SDK-key mint rules beyond shape (C45 carry-in, C46). Pure: the server's
 * `createSdkKey` refuses a key that breaks them with a stable 400 code, and
 * the web mint form imports these same functions to explain the problem
 * before submitting. There is no second definition.
 */

/** A selected scope that authorizes no service action given the rest. */
export const SDK_KEY_UNUSABLE_SCOPES_CODE = "sdk_key.unusable_scopes";
/** An exact revision without an eligible association on a selected owned host. */
export const SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE = "sdk_key.template_not_on_selected_host";
/** `webhooks:write` on a key restricted to some hosts, templates or pools. */
export const SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE = "sdk_key.webhooks_requires_all_owned";

/** `credentials:use` on an allowlist key that names no login: a grant that can never be used. */
export const SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE = "sdk_key.credentials_use_needs_logins";

/**
 * `credentials:use` lets a key put a login's value into a guest (attach, or
 * a create naming it), and with `commands:execute` / `files:read` read it
 * back out — the mint form discloses that. On an `ALLOWLIST` key it reaches
 * only the logins named in the key's login allowlist, so at least one must
 * be named. True when the selection breaks that rule.
 */
export function credentialsUseNeedsLogins(
  scopes: readonly ServiceScope[],
  resourceMode: "ALL_OWNED" | "ALLOWLIST",
  credentialIds: readonly string[],
): boolean {
  return (
    scopes.includes("credentials:use") && resourceMode === "ALLOWLIST" && credentialIds.length === 0
  );
}

/**
 * A webhook endpoint receives events for every sandbox on the account, so a
 * key restricted to some hosts or pools must not be able to set one up:
 * `webhooks:write` is mintable only on `ALL_OWNED` + `ALL_USABLE` keys. True
 * when the selection breaks that rule.
 */
export function webhooksScopeNeedsAllOwned(
  scopes: readonly ServiceScope[],
  resourceMode: "ALL_OWNED" | "ALLOWLIST",
  poolMode: "ALL_USABLE" | "SELECTED" | undefined,
): boolean {
  if (!scopes.includes("webhooks:write")) return false;
  const effectivePoolMode = poolMode ?? (resourceMode === "ALL_OWNED" ? "ALL_USABLE" : "SELECTED");
  return resourceMode !== "ALL_OWNED" || effectivePoolMode !== "ALL_USABLE";
}

/**
 * Selected scopes that authorize no service action given the rest of the
 * selection — derived from the server's own action table, so a new action or
 * a changed requirement moves this rule with it. `commands:read` alone supports process discovery/connect; output also needs
 * `operations:read`.
 * `operations:cancel` needs a scope for the work it cancels.
 */
export function unusableScopes(selected: readonly ServiceScope[]): ServiceScope[] {
  const set = new Set(selected);
  const requirements = Object.values(SERVICE_ACTION_REQUIREMENTS);
  return [...set].filter(
    (scope) =>
      !requirements.some(
        (requirement) =>
          requirement.scopes.includes(scope) &&
          requirement.scopes.every((needed) => set.has(needed)) &&
          (!requirement.cancelMutationScope ||
            CANCEL_MUTATION_SCOPES.some((mutation) => set.has(mutation))),
      ),
  );
}

export type AllowlistTemplate = {
  id: string;
  availability: readonly {
    hostId: string;
    status: "AVAILABLE" | "PENDING" | "MISSING" | "REJECTED";
  }[];
  retiredAt: Date | string | null;
};

/**
 * A template can start sandboxes only on its own host, and only while it is
 * active. An allowlisted revision must have pending or available evidence on one of
 * the allowlisted hosts; anything else would be a grant that can never be used.
 */
export function isTemplateOnSelectedHosts(
  template: AllowlistTemplate,
  hostIds: ReadonlySet<string> | readonly string[],
): boolean {
  const hosts = hostIds instanceof Set ? hostIds : new Set(hostIds);
  return (
    template.retiredAt == null &&
    template.availability.some(
      (entry) =>
        hosts.has(entry.hostId) && (entry.status === "AVAILABLE" || entry.status === "PENDING"),
    )
  );
}

/** IDs of the given templates that break {@link isTemplateOnSelectedHosts}. */
export function templatesOffSelectedHosts(
  templates: readonly AllowlistTemplate[],
  hostIds: readonly string[],
): string[] {
  const hosts = new Set(hostIds);
  return templates
    .filter((template) => !isTemplateOnSelectedHosts(template, hosts))
    .map((t) => t.id);
}

/** Host tools need a directly owned host grant; shared pool access is insufficient. */
export function hostScopesNeedHostGrant(
  scopes: readonly ServiceScope[],
  resourceMode: "ALL_OWNED" | "ALLOWLIST",
  hostIds: readonly string[],
): boolean {
  return (
    resourceMode === "ALLOWLIST" &&
    hostIds.length === 0 &&
    scopes.some((scope) => scope === "hosts:execute" || scope === "hosts:files")
  );
}
export const SDK_KEY_HOST_SCOPES_NEED_HOST_CODE = "sdk_key.host_scopes_need_host";
