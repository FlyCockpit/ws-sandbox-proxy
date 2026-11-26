import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { isKnownServiceScope } from "@wssp/api/lib/service-scopes";
import type { AppRouterClient } from "@wssp/api/routers/index";
import type { AgentTokenExpiryPolicy } from "@wssp/config/agent-token-limits";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@wssp/ui/components/dialog";
import { AdvancedSection, FormSection } from "@wssp/ui/components/form-page";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { TextField } from "@wssp/ui/components/text-field";
import { FIRST_INVALID_SELECTOR, focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { ChevronRight, Plus } from "lucide-react";
import { type ReactNode, useId, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import {
  CredentialDates,
  ExpirySelect,
  OneTimeSecretPanel,
  OrphanedCredentialsAlert,
  SecretLeaveGuard,
  useRevoke,
} from "@/components/credentials/credential-parts";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { ResourceIdentity } from "@/components/resource-identity";
import { SegmentedControl } from "@/components/segmented-control";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { type OneTimeSecret, useOneTimeSecret } from "@/hooks/use-one-time-secret";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { agentTokenExpiry, agentTokenExpiryPresets } from "@/lib/agent-token-expiry";
import {
  type AccessChoice,
  API_KEY_ONLY_SCOPES,
  accessChoiceFor,
  CREDENTIAL_NAME_MAX,
  type CredentialProblem,
  credentialProblem,
  credentialsUseRevealsValues,
  DESCRIBED_SCOPE_GROUPS,
  draftProblemField,
  offeredScopeGroups,
  presetScopes,
  type ResourceMode,
  SCOPE_PRESETS,
  type SdkKeyDraft,
  type ServiceScope,
  scopeKey,
  sdkKeyDraftProblems,
  sdkKeyMintInput,
  selectableHosts,
  selectableTemplates,
  unusableScopes,
} from "@/lib/credential-rules";
import { toMs } from "@/lib/host-status";
import { isQueryAccessError } from "@/lib/query-access-error";
import { orpc } from "@/utils/orpc";
import { AgentTokenExpirySelect } from "./agent-token-expiry-select";
import { UseSdkKey } from "./use-sdk-key";

/**
 * SDK keys (C45): owner-scoped `wssp_sdk_` keys for the /v1 API, with scopes,
 * optional host/template allowlists and expiry. The raw key is shown once from
 * transient component state (useOneTimeSecret); the list carries metadata and
 * the lookup prefix only. The browser refuses scope sets where a scope grants
 * nothing and allowlists naming anything but the owner's selectable hosts and
 * their active templates; the server re-checks ownership and scopes.
 */

/**
 * The create form's allowlist pickers page hosts and templates with Load more,
 * the same cursor paging as the lists (the procedure maximum per page).
 */
const PICKER_LIMIT = 100;
const pickerPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

type KeyPage = Awaited<ReturnType<AppRouterClient["sdkKeys"]["list"]>>;
type KeyItem = KeyPage["items"][number];
type ListFilter = "active" | "all";

export function SdkKeysPage({ lang, agent = false }: { lang: string; agent?: boolean }) {
  const api = agent ? orpc.agentTokens : orpc.sdkKeys;
  const ns = agent ? "agents" : "sdkKeys";
  const { t, i18n } = useTranslation(["sdkKeys", "agents", "credentials", "dashboard", "common"]);
  const [filter, setFilter] = useState<ListFilter>("active");
  const includeRevoked = filter === "all";
  const keys = useInfiniteQuery({
    ...api.list.infiniteOptions({
      input: (cursor: string | undefined) => ({
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
        includeRevoked,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [keys.error]);
  const [minting, setMinting] = useState(false);
  // Page-level, not dialog-level: the minted key is shown inline and stays
  // until the owner dismisses it (M7-S4).
  const queryClient = useQueryClient();
  const oneTime = useOneTimeSecret<{ id: string }>({
    scope: agent ? "agentToken" : "sdkKey",
    revoke: (id) =>
      api.revoke
        .call({ id })
        .finally(() => void queryClient.invalidateQueries({ queryKey: api.list.key() })),
  });
  const now = Date.now();
  const rows = keys.data?.pages.flatMap((page) => page.items);
  // An empty active list may still hide revoked keys: one bounded probe tells
  // "nothing yet" from "nothing active".
  const revokedProbe = useQuery({
    ...api.list.queryOptions({ input: { limit: 1, includeRevoked: true } }),
    enabled: !includeRevoked && rows?.length === 0,
    meta: { skipGlobalErrorToast: true },
  });
  const hasRevoked = (revokedProbe.data?.items.length ?? 0) > 0;
  const revealed = oneTime.revealed;

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t(`${ns}:title`)}
        description={t(`${ns}:description`)}
        actions={
          <Button
            type="button"
            size="touch"
            disabled={revealed != null}
            onClick={() => setMinting(true)}
          >
            <Plus aria-hidden="true" />
            {t(`${ns}:mint.action`)}
          </Button>
        }
      />
      <SecretLeaveGuard active={revealed != null} />
      {revealed ? (
        <>
          <OneTimeSecretPanel
            secret={revealed.secret}
            label={t(`${ns}:mint.secretLabel`)}
            onDone={oneTime.clear}
          >
            <p className="text-sm text-muted-foreground">{t(`${ns}:mint.usageHint`)}</p>
          </OneTimeSecretPanel>
          {agent ? null : <UseSdkKey />}
        </>
      ) : null}
      <OrphanedCredentialsAlert orphans={oneTime.orphans} onRetry={oneTime.retryOrphan} />
      <SegmentedControl
        value={filter}
        onChange={setFilter}
        ariaLabel={t("credentials:filter.label")}
        items={[
          { value: "active", label: t("credentials:filter.active") },
          { value: "all", label: t("credentials:filter.all") },
        ]}
      />
      <QueryBoundary
        query={{
          data: rows,
          isPending: keys.isPending,
          isError: keys.isError,
          error: keys.error,
          refetch: keys.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t(hasRevoked ? `${ns}:emptyActive.title` : `${ns}:empty.title`)}
            description={t(
              hasRevoked ? `${ns}:emptyActive.description` : `${ns}:empty.description`,
            )}
          />
        }
      >
        {(items) => (
          <>
            <ul aria-label={t(`${ns}:title`)} className="flex min-w-0 flex-col gap-3">
              {items.map((key) => (
                <SdkKeyRow
                  agent={agent}
                  key={key.id}
                  sdkKey={key}
                  now={now}
                  lang={lang}
                  locale={i18n.language}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={keys.hasNextPage}
              isFetchingNextPage={keys.isFetchingNextPage}
              onLoadMore={() => void keys.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {agent || revealed ? null : <UseSdkKey />}
      {minting ? (
        <CredentialGrantEditor
          mode={agent ? "agent" : "sdk"}
          lang={lang}
          oneTime={oneTime}
          onClose={() => setMinting(false)}
        />
      ) : null}
    </div>
  );
}

function SdkKeyRow({
  sdkKey,
  agent = false,
  now,
  lang,
  locale,
}: {
  sdkKey: KeyItem;
  agent?: boolean;
  now: number;
  lang: string;
  locale: string;
}) {
  const { t } = useTranslation(["sdkKeys", "agents", "credentials"]);
  const api = agent ? orpc.agentTokens : orpc.sdkKeys;
  const revoke = useRevoke(
    lang,
    (id) => api.revoke.call({ id }),
    t("sdkKeys:revoke.done"),
    (client) => void client.invalidateQueries({ queryKey: api.list.key() }),
  );
  const expires = toMs(sdkKey.expiresAt);
  const expired = expires != null && expires <= now;
  const revoked = sdkKey.revokedAt != null;
  const blockedByPolicy = agent && !revoked && sdkKey.blockedByPolicy === true;
  // A scope this page does not know never folds into a preset name.
  const knownScopes = sdkKey.scopes.filter(isKnownServiceScope);
  const access =
    knownScopes.length === sdkKey.scopes.length ? accessChoiceFor(knownScopes) : "custom";
  const scopeChips = (
    <ul aria-label={t("sdkKeys:list.scopes")} className="flex min-w-0 flex-wrap gap-1.5">
      {sdkKey.scopes.map((scope) => (
        <li
          key={scope}
          data-scope={scope}
          title={scope}
          className="inline-flex items-center rounded-sm border px-2 py-0.5 text-xs"
        >
          {t(`sdkKeys:scopeTitle.${scope.replace(":", ".")}`)}
        </li>
      ))}
    </ul>
  );
  return (
    <li
      data-credential-id={sdkKey.id}
      data-expired={expired ? "true" : undefined}
      data-revoked={revoked ? "true" : undefined}
      data-blocked-by-policy={blockedByPolicy ? "true" : undefined}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <p className="min-w-0 text-sm font-medium [overflow-wrap:anywhere]">{sdkKey.name}</p>
            {sdkKey.origin === "CLI_LOGIN" ? (
              <Badge data-origin={sdkKey.origin} className="shrink-0">
                {t("sdkKeys:list.cliLogin")}
              </Badge>
            ) : null}
            {revoked ? (
              <Badge variant="outline" data-revoked-badge="" className="shrink-0">
                {t("sdkKeys:list.revoked")}
              </Badge>
            ) : null}
          </div>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {t("credentials:prefix", { prefix: sdkKey.lookupPrefix })}
          </p>
        </div>
        {revoked ? null : (
          <Button
            type="button"
            variant="destructive"
            size="touch"
            aria-label={t("credentials:revoke.actionNamed", { name: sdkKey.name })}
            disabled={revoke.mutation.isPending}
            onClick={() => revoke.setConfirming(true)}
          >
            {t("credentials:revoke.action")}
          </Button>
        )}
      </div>
      {/* Design review #14: lead with what the key can do. A preset key folds
          its chips (the preset names exactly that set); a Custom key keeps
          every permission in view, so host access or CLI shells never hide. */}
      <div className="flex min-w-0 flex-col gap-1" data-scope-summary={access}>
        <p className="text-sm font-medium">
          {t(`sdkKeys:form.preset.${access}.title`)} ·{" "}
          {t("sdkKeys:form.scopeCount", { count: sdkKey.scopes.length })}
        </p>
        {access === "custom" ? null : (
          <p className="text-sm text-muted-foreground">
            {t(`sdkKeys:form.preset.${access}.description`)}
          </p>
        )}
      </div>
      {access === "custom" ? (
        scopeChips
      ) : (
        <details data-scope-details="" className="group/scopes min-w-0 text-sm">
          <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 font-medium text-muted-foreground [&::-webkit-details-marker]:hidden">
            <ChevronRight
              aria-hidden="true"
              className="size-4 shrink-0 transition-transform duration-150 group-open/scopes:rotate-90 motion-reduce:transition-none"
            />
            {t("sdkKeys:list.showScopes", { count: sdkKey.scopes.length })}
          </summary>
          {scopeChips}
        </details>
      )}
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-3">
        <div className="min-w-0" data-resource-mode={sdkKey.resourceMode}>
          <dt className="text-xs text-muted-foreground">{t("sdkKeys:form.resources")}</dt>
          {sdkKey.resourceMode === "ALL_OWNED" ? (
            <dd>{t("sdkKeys:list.allOwned")}</dd>
          ) : (
            <dd className="min-w-0">
              <p>{t("sdkKeys:list.allowlistTitle")}</p>
              <p data-allowlist="hosts" className="break-words text-muted-foreground">
                {t("sdkKeys:list.allowlistHosts", {
                  names: listNames(
                    sdkKey.hostAllowlist.map((host) =>
                      translateText(t, "credentials:host.label", {
                        label: host.label,
                        slug: host.slug,
                      }),
                    ),
                    locale,
                  ),
                })}
              </p>
              <p data-allowlist="templates" className="break-words text-muted-foreground">
                {t("sdkKeys:list.allowlistTemplates", {
                  names: listNames(
                    sdkKey.revisionAllowlist.map((revision) =>
                      translateText(t, "sdkKeys:resourceIdentity", {
                        label: revision.label,
                        id: revision.id,
                      }),
                    ),
                    locale,
                  ),
                })}
              </p>
              {(sdkKey.credentialAllowlist ?? []).length > 0 ? (
                <p data-allowlist="logins" className="break-words text-muted-foreground">
                  {translateText(t, "sdkKeys:list.allowlistLogins", {
                    names: listNames(
                      (sdkKey.credentialAllowlist ?? []).map((login) => login.name),
                      locale,
                    ),
                  })}
                </p>
              ) : null}
            </dd>
          )}
        </div>
        <div className="min-w-0" data-pool-mode={sdkKey.poolMode}>
          <dt className="text-xs text-muted-foreground">{t("sdkKeys:form.pools")}</dt>
          <dd>
            {t(
              sdkKey.poolMode === "ALL_USABLE"
                ? "sdkKeys:poolMode.ALL_USABLE"
                : "sdkKeys:poolMode.SELECTED",
            )}
            {sdkKey.poolMode === "SELECTED" ? (
              <span data-allowlist="pools" className="block break-words text-muted-foreground">
                {t("sdkKeys:list.allowlistPools", {
                  names: listNames(
                    (sdkKey.poolAllowlist ?? []).map((pool) =>
                      translateText(t, "sdkKeys:resourceIdentity", {
                        label: pool.label,
                        id: pool.id,
                      }),
                    ),
                    locale,
                  ),
                })}
              </span>
            ) : null}
          </dd>
        </div>
        <div className="min-w-0" data-own-sandboxes-only={sdkKey.ownSandboxesOnly ? "on" : "off"}>
          <dt className="text-xs text-muted-foreground">{t("sdkKeys:list.sandboxes")}</dt>
          <dd>
            {t(
              sdkKey.ownSandboxesOnly
                ? "sdkKeys:form.ownSandboxesOnly"
                : "sdkKeys:list.otherSandboxes",
            )}
          </dd>
        </div>
      </dl>
      {sdkKey.maxLiveSandboxes != null ? (
        <p className="text-sm" data-max-live-sandboxes={sdkKey.maxLiveSandboxes}>
          {t("sdkKeys:list.maxLiveSandboxes", { count: sdkKey.maxLiveSandboxes })}
        </p>
      ) : null}
      <CredentialDates
        createdAt={sdkKey.createdAt}
        lastUsedAt={sdkKey.lastUsedAt}
        expiresAt={sdkKey.expiresAt}
        // CLI connections: dashboard/CLI-login API keys only, once it can or did connect.
        lastConnectAt={
          !agent && (sdkKey.lastConnectAt != null || sdkKey.scopes.includes("sandboxes:connect"))
            ? sdkKey.lastConnectAt
            : undefined
        }
        now={now}
        locale={locale}
      />
      {blockedByPolicy ? (
        <p data-policy-notice="" className="text-sm text-destructive">
          {t("agents:expiry.blockedByPolicy")}
        </p>
      ) : null}
      {revoke.problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`credentials:problem.${revoke.problem}`)}
        </p>
      ) : null}
      {revoked ? null : (
        <ConfirmDeleteDialog
          open={revoke.confirming}
          onOpenChange={revoke.setConfirming}
          title={t("sdkKeys:revoke.title", { name: sdkKey.name })}
          description={t("sdkKeys:revoke.description")}
          confirmToken={sdkKey.name}
          typePrompt={t(agent ? "agents:revoke.typePrompt" : "sdkKeys:revoke.typePrompt")}
          copyAriaLabel={t(agent ? "agents:revoke.copyName" : "sdkKeys:revoke.copyName")}
          confirmLabel={t("credentials:revoke.confirm")}
          pendingLabel={t("credentials:revoke.pending")}
          isPending={revoke.mutation.isPending}
          onConfirm={() => revoke.mutation.mutate(sdkKey.id)}
        />
      )}
    </li>
  );
}

/** "A, B and C" in the UI locale. */
function listNames(names: string[], locale: string): string {
  return new Intl.ListFormat(locale, { style: "long", type: "conjunction" }).format(names);
}

function toggle<T>(list: readonly T[], value: T, on: boolean): T[] {
  return on
    ? [...list.filter((item) => item !== value), value]
    : list.filter((item) => item !== value);
}

/** The preset a new key starts from: enough to run sandboxes, no host access. */
const DEFAULT_ACCESS = "runSandboxes" as const;

const DEFAULT_DRAFT: SdkKeyDraft = {
  name: "",
  scopes: presetScopes(DEFAULT_ACCESS),
  resourceMode: "ALL_OWNED",
  hostIds: [],
  templateRevisionIds: [],
  poolIds: [],
  poolMode: "ALL_USABLE",
  credentialIds: [],
  expiry: "90d",
  ownSandboxesOnly: false,
};

type CredentialGrantEditorProps = {
  lang: string;
  mode?: "sdk" | "agent" | "consent";
  requestedScopes?: readonly ServiceScope[];
  consentName?: string;
  onConsent?: (input: ReturnType<typeof sdkKeyMintInput>) => Promise<void>;
  oneTime?: OneTimeSecret<{ id: string }>;
  onClose: () => void;
};

export function CredentialGrantEditor(props: CredentialGrantEditorProps) {
  return props.mode === "agent" ? <AgentTokenGrantEditor {...props} /> : <GrantEditor {...props} />;
}

function AgentTokenGrantEditor(props: CredentialGrantEditorProps) {
  const { t } = useTranslation(["agents"]);
  const policy = useQuery({
    ...orpc.agentTokens.expiryPolicy.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(props.lang, [policy.error]);
  if (policy.data && !isQueryAccessError(policy.error))
    return (
      <>
        {policy.isError ? <InlineRetry onRetry={() => void policy.refetch()} /> : null}
        <GrantEditor {...props} expiryPolicy={policy.data} />
      </>
    );
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) props.onClose();
      }}
    >
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("agents:mint.title")}</DialogTitle>
        </DialogHeader>
        <QueryBoundary query={policy} skeleton={<SkeletonList />}>
          {() => null}
        </QueryBoundary>
        <Button type="button" size="touch" variant="outline" onClick={props.onClose}>
          {t("agents:expiry.close")}
        </Button>
      </DialogContent>
    </Dialog>
  );
}

/** Inline field errors, shown after the first submit attempt. */
function FieldProblems({ id, messages }: { id: string; messages: readonly string[] }) {
  if (messages.length === 0) return null;
  return (
    <div id={id} role="alert" className="flex flex-col gap-1">
      {messages.map((message) => (
        <p key={message} className="text-sm text-destructive">
          {message}
        </p>
      ))}
    </div>
  );
}

/** Consent renders the same fields without the create sheet's section columns. */
function PlainSection({
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  gridClassName?: string;
  children: ReactNode;
}) {
  return <div className="flex min-w-0 flex-col gap-4">{children}</div>;
}

function GrantEditor({
  lang,
  oneTime,
  onClose,
  mode = "sdk",
  requestedScopes,
  consentName = "",
  onConsent,
  expiryPolicy,
}: CredentialGrantEditorProps & { expiryPolicy?: AgentTokenExpiryPolicy }) {
  const { t } = useTranslation(["sdkKeys", "agents", "credentials", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const formRef = useRef<HTMLFormElement>(null);
  const expiryId = useId();
  const errorIds = {
    scopes: useId(),
    resources: useId(),
    pools: useId(),
  };
  const ns = mode === "agent" ? "agents" : "sdkKeys";
  const api = mode === "agent" ? orpc.agentTokens : orpc.sdkKeys;
  const [agentExpiryChoice, setAgentExpiryChoice] = useState(() => {
    const presets = agentTokenExpiryPresets(Math.min(90, expiryPolicy?.maxLifetimeDays ?? 90));
    return presets.at(-1) ?? "custom";
  });
  const [agentCustomDate, setAgentCustomDate] = useState("");
  const [revisionPoolId, setRevisionPoolId] = useState("");
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const [attempted, setAttempted] = useState(false);
  // Consent picks from the requested scopes; the create forms start from a preset.
  const [access, setAccess] = useState<AccessChoice>(
    mode === "consent" ? "custom" : DEFAULT_ACCESS,
  );
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...pickerPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = selectableHosts(hostsQuery.data?.pages.flatMap((page) => page.items) ?? []);

  const initialDraft: SdkKeyDraft = {
    ...DEFAULT_DRAFT,
    name: consentName,
    ownSandboxesOnly: mode !== "sdk",
    // Never preselected: host scopes, and API-key-only scopes outside the SDK key form.
    scopes:
      mode === "consent"
        ? (requestedScopes?.filter(
            (scope) => !scope.startsWith("hosts:") && !API_KEY_ONLY_SCOPES.includes(scope),
          ) ?? [])
        : DEFAULT_DRAFT.scopes,
  };
  const agentExpiryInvalid = () =>
    mode === "agent" &&
    (!expiryPolicy ||
      agentTokenExpiry(agentExpiryChoice, agentCustomDate, Date.now(), expiryPolicy) === undefined);
  // No form-level validators: a pathless schema issue lands on a field named ""
  // that no field ever revalidates, so one failed submit blocked every later
  // one (design-review2 #1). The draft rules run here, at submit, instead.
  const form = useForm({
    defaultValues: initialDraft,
    onSubmit: async ({ value }) => {
      if (sdkKeyDraftProblems(value, options).length > 0 || agentExpiryInvalid()) return;
      setProblem(null);
      try {
        if (mode === "consent" && onConsent) {
          await onConsent(sdkKeyMintInput(value, Date.now()));
          return;
        }
        if (!oneTime) return;
        const outcome = await oneTime.run(
          () => {
            const input = sdkKeyMintInput(value, Date.now());
            if (mode === "agent") {
              const expiresAt =
                expiryPolicy &&
                agentTokenExpiry(agentExpiryChoice, agentCustomDate, Date.now(), expiryPolicy);
              if (expiresAt === undefined) throw new Error("Invalid agent token expiry");
              return orpc.agentTokens.create.call({ ...input, expiresAt });
            }
            return orpc.sdkKeys.create.call(input);
          },
          (result) => ({ secret: result.secret, meta: { id: result.key.id } }),
          // Closed while creating: nobody saw this key, so revoke the orphan.
          (result) => ({ id: result.key.id, label: result.key.name }),
        );
        // The page now shows the key inline; the sheet's job is done.
        if (outcome === "revealed") onClose();
      } catch (error) {
        if (!redirect(error)) {
          const next = credentialProblem(error);
          setProblem(next);
          // The server saw a different host/template picture: reload the pickers.
          if (next === "templateOffHost" || next === "changed") {
            void hostsQuery.refetch();
            void templatesQuery.refetch();
          }
          // The deployment's expiry policy changed under the open sheet: reload it.
          if (next === "agentExpiryPolicy")
            void queryClient.invalidateQueries({
              queryKey: orpc.agentTokens.expiryPolicy.queryKey(),
            });
        }
      } finally {
        void queryClient.invalidateQueries({ queryKey: api.list.key() });
      }
    },
  });

  const values = useStore(form.store, (state) => state.values);
  // Only active templates can be allowlisted (the server refuses the rest).
  const templatesQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listRevisionChoices.infiniteOptions({
      ...pickerPages,
      input: (cursor: string | undefined) => ({
        limit: PICKER_LIMIT,
        cursor,
        hostIds: [...values.hostIds],
        ...(values.hostIds.length === 0 && revisionPoolId ? { poolId: revisionPoolId } : {}),
      }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const templates =
    !values.hostIds.length && !revisionPoolId
      ? []
      : (templatesQuery.data?.pages.flatMap((page) => page.items) ?? []);
  const poolsQuery = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      ...pickerPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    enabled: true,
    meta: { skipGlobalErrorToast: true },
  });
  const pools = poolsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const options = { hosts, templates, pools };
  useTwoFactorRedirectOnError(lang, [hostsQuery.error, templatesQuery.error, poolsQuery.error]);

  const problems = attempted ? sdkKeyDraftProblems(values, options) : [];
  const messagesFor = (field: ReturnType<typeof draftProblemField>) =>
    problems
      .filter((item) => draftProblemField(item) === field)
      .map((item) => t(`credentials:draft.${item}`));
  const errors = {
    name: messagesFor("name"),
    scopes: messagesFor("scopes"),
    resources: messagesFor("resources"),
    pools: messagesFor("pools"),
  };
  const expiryInvalid = attempted && agentExpiryInvalid();
  // Cancelling discards a create still in flight (it is revoked, never shown).
  const close = () => {
    oneTime?.discardPending();
    onClose();
  };
  const chooseAccess = (next: AccessChoice) => {
    setAccess(next);
    if (next !== "custom") form.setFieldValue("scopes", presetScopes(next));
  };
  const submit = () => {
    flushSync(() => setAttempted(true));
    // The first invalid field gets focus (its Advanced section opens); a
    // valid draft goes to the server.
    const root = formRef.current;
    if (root?.querySelector(FIRST_INVALID_SELECTOR)) focusFirstInvalidField(root);
    else void form.handleSubmit();
  };

  const Section = mode === "consent" ? PlainSection : FormSection;
  const resourceSummary =
    values.resourceMode === "ALL_OWNED"
      ? t("sdkKeys:form.mode.ALL_OWNED")
      : t("sdkKeys:form.summary.allowlist", {
          count:
            values.hostIds.length +
            values.templateRevisionIds.length +
            (values.credentialIds?.length ?? 0),
        });
  const poolSummary =
    values.poolMode === "SELECTED"
      ? t("sdkKeys:form.summary.pools", { count: values.poolIds?.length ?? 0 })
      : t("sdkKeys:poolMode.ALL_USABLE");
  const sandboxSummary = values.ownSandboxesOnly
    ? t("sdkKeys:form.ownSandboxesOnly")
    : t("sdkKeys:form.summary.allSandboxes");
  const presetInvalid = errors.scopes.length > 0 && access !== "custom";

  const fields = (
    <>
      <Section
        title={t("sdkKeys:form.sections.key")}
        description={t("sdkKeys:form.sections.keyHint")}
        gridClassName="lg:grid-cols-1"
      >
        {mode !== "consent" ? (
          <form.Field name="name">
            {(field) => (
              <TextField
                inputClassName="min-h-11"
                field={{
                  name: field.name,
                  state: { value: field.state.value, meta: { errors: errors.name } },
                  handleBlur: field.handleBlur,
                  handleChange: field.handleChange,
                }}
                label={t("credentials:form.name")}
                description={t("credentials:form.nameHint", {
                  max: CREDENTIAL_NAME_MAX,
                  count: field.state.value.trim().length,
                })}
                autoComplete="off"
                inputMode="text"
              />
            )}
          </form.Field>
        ) : null}
        {mode !== "consent" ? (
          <fieldset className="flex min-w-0 flex-col gap-1" data-access={access}>
            <legend className="mb-1 text-sm font-medium">{t("sdkKeys:form.access")}</legend>
            <RadioGroup
              aria-label={t("sdkKeys:form.access")}
              name="access"
              value={access}
              onValueChange={(value: AccessChoice) => chooseAccess(value)}
            >
              {([...SCOPE_PRESETS, "custom"] as const).map((choice) => (
                <label key={choice} className="flex min-h-11 items-start gap-3 py-1 text-sm">
                  <RadioGroupItem
                    value={choice}
                    className="mt-1"
                    aria-invalid={(presetInvalid && choice === access) || undefined}
                    aria-describedby={
                      presetInvalid && choice === access ? errorIds.scopes : undefined
                    }
                  />
                  <span className="min-w-0">
                    <span className="block font-medium">
                      {t(`sdkKeys:form.preset.${choice}.title`)}
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      {t(`sdkKeys:form.preset.${choice}.description`)}
                      {choice === "custom"
                        ? null
                        : ` ${t("sdkKeys:form.scopeCount", { count: presetScopes(choice).length })}`}
                    </span>
                  </span>
                </label>
              ))}
            </RadioGroup>
          </fieldset>
        ) : null}
        {access === "custom" ? (
          <form.Field name="scopes">
            {(field) => (
              <ScopePicker
                form={mode}
                offered={requestedScopes}
                value={field.state.value}
                onChange={field.handleChange}
                invalid={errors.scopes.length > 0}
                errorId={errors.scopes.length > 0 ? errorIds.scopes : undefined}
              />
            )}
          </form.Field>
        ) : null}
        <FieldProblems id={errorIds.scopes} messages={errors.scopes} />
        {credentialsUseRevealsValues(values.scopes) ? (
          <p
            role="note"
            data-credentials-use-disclosure=""
            className="rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
          >
            {t("sdkKeys:form.credentialsUseDisclosure")}
          </p>
        ) : null}
        {/* The consent page already shows this warning above the form. */}
        {mode !== "consent" &&
        values.scopes.some((scope) => scope === "hosts:execute" || scope === "hosts:files") ? (
          <p
            role="note"
            className="rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
          >
            {t("sdkKeys:form.hostScopeWarning")}
          </p>
        ) : null}
        {mode === "agent" && expiryPolicy ? (
          <AgentTokenExpirySelect
            id={expiryId}
            policy={expiryPolicy}
            value={agentExpiryChoice}
            onChange={setAgentExpiryChoice}
            customDate={agentCustomDate}
            onCustomDateChange={setAgentCustomDate}
            invalid={expiryInvalid}
          />
        ) : mode !== "consent" ? (
          <form.Field name="expiry">
            {(field) => (
              <ExpirySelect id={expiryId} value={field.state.value} onChange={field.handleChange} />
            )}
          </form.Field>
        ) : null}
      </Section>
      <Section
        title={t("sdkKeys:form.sections.limits")}
        description={t("sdkKeys:form.sections.limitsHint")}
        gridClassName="lg:grid-cols-1"
      >
        {/* One cell: consecutive sections join into one ruled list. */}
        <div className="min-w-0 space-y-8">
          <AdvancedSection
            title={t("sdkKeys:form.sections.resources")}
            summary={resourceSummary}
            data-section="resources"
          >
            <form.Field name="resourceMode">
              {(field) => (
                <div className="flex min-w-0 flex-col gap-1">
                  <p className="text-sm font-medium">{t("sdkKeys:form.resources")}</p>
                  <RadioGroup
                    aria-label={t("sdkKeys:form.resources")}
                    name="resourceMode"
                    value={field.state.value}
                    onValueChange={(value: ResourceMode) => field.handleChange(value)}
                  >
                    {(["ALL_OWNED", "ALLOWLIST"] as const satisfies readonly ResourceMode[]).map(
                      (resourceMode) => (
                        <label
                          key={resourceMode}
                          className="flex min-h-11 items-start gap-3 text-sm"
                        >
                          <RadioGroupItem
                            value={resourceMode}
                            className="mt-1"
                            aria-invalid={
                              (errors.resources.length > 0 && resourceMode === field.state.value) ||
                              undefined
                            }
                            aria-describedby={
                              errors.resources.length > 0 && resourceMode === field.state.value
                                ? errorIds.resources
                                : undefined
                            }
                          />
                          <span className="min-w-0">
                            <span className="block">{t(`sdkKeys:form.mode.${resourceMode}`)}</span>
                            <span className="block text-xs text-muted-foreground">
                              {t(`sdkKeys:form.modeHint.${resourceMode}`)}
                            </span>
                          </span>
                        </label>
                      ),
                    )}
                  </RadioGroup>
                </div>
              )}
            </form.Field>
            {values.resourceMode === "ALLOWLIST" && !values.hostIds.length ? (
              <label className="flex min-h-11 flex-col gap-2 text-sm">
                {t("sdkKeys:poolMode.revisionContext")}
                <select
                  className="min-h-11 rounded border bg-background"
                  autoComplete="off"
                  value={revisionPoolId}
                  onChange={(e) => setRevisionPoolId(e.target.value)}
                >
                  <option value="">{t("sdkKeys:form.pools")}</option>
                  {pools.map((pool) => (
                    <option key={pool.id} value={pool.id}>
                      {pool.label} ·{" "}
                      {"owner" in pool ? pool.owner?.name : t("sdkKeys:form.ownedPool")} · {pool.id}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            {values.resourceMode === "ALLOWLIST" ? (
              <AllowlistPicker
                hosts={hosts}
                templates={templates}
                hostIds={values.hostIds}
                templateRevisionIds={values.templateRevisionIds}
                hostsFailed={hostsQuery.isError}
                templatesFailed={templatesQuery.isError}
                loading={hostsQuery.isPending || templatesQuery.isPending}
                onRetry={() => {
                  void hostsQuery.refetch();
                  void templatesQuery.refetch();
                }}
                moreHosts={{
                  hasNextPage: hostsQuery.hasNextPage,
                  isFetchingNextPage: hostsQuery.isFetchingNextPage,
                  onLoadMore: () => void hostsQuery.fetchNextPage(),
                }}
                moreTemplates={{
                  hasNextPage: templatesQuery.hasNextPage,
                  isFetchingNextPage: templatesQuery.isFetchingNextPage,
                  onLoadMore: () => void templatesQuery.fetchNextPage(),
                }}
                onHosts={(hostIds) => {
                  form.setFieldValue("hostIds", hostIds);
                  // A template runs only on its own host: drop templates
                  // whose host is no longer selected.
                  const allowed = new Set(
                    selectableTemplates(templates, hostIds).map((template) => template.id),
                  );
                  form.setFieldValue(
                    "templateRevisionIds",
                    values.templateRevisionIds.filter((id) => allowed.has(id)),
                  );
                }}
                onTemplates={(templateRevisionIds) =>
                  form.setFieldValue("templateRevisionIds", templateRevisionIds)
                }
              />
            ) : null}
            {values.resourceMode === "ALLOWLIST" ? (
              <form.Field name="credentialIds">
                {(field) => (
                  <LoginAllowlistPicker
                    lang={lang}
                    selected={field.state.value ?? []}
                    required={values.scopes.includes("credentials:use")}
                    onChange={field.handleChange}
                  />
                )}
              </form.Field>
            ) : null}
            <FieldProblems id={errorIds.resources} messages={errors.resources} />
          </AdvancedSection>
          <AdvancedSection
            title={t("sdkKeys:form.sections.pools")}
            summary={poolSummary}
            data-section="pools"
          >
            <form.Field name="poolMode">
              {(field) => (
                <fieldset className="flex min-w-0 flex-col">
                  <legend className="text-sm font-medium">{t("sdkKeys:poolMode.title")}</legend>
                  {(["ALL_USABLE", "SELECTED"] as const).map((poolMode) => (
                    <label key={poolMode} className="flex min-h-11 items-center gap-3 text-sm">
                      <input
                        type="radio"
                        name="poolMode"
                        autoComplete="off"
                        checked={field.state.value === poolMode}
                        aria-invalid={
                          (errors.pools.length > 0 && field.state.value === poolMode) || undefined
                        }
                        aria-describedby={
                          errors.pools.length > 0 && field.state.value === poolMode
                            ? errorIds.pools
                            : undefined
                        }
                        onChange={() => field.handleChange(poolMode)}
                      />
                      {t(`sdkKeys:poolMode.${poolMode}`)}
                    </label>
                  ))}
                </fieldset>
              )}
            </form.Field>
            <p className="text-xs text-muted-foreground">{t("sdkKeys:poolMode.immutable")}</p>
            {values.poolMode === "SELECTED" ? (
              <form.Field name="poolIds">
                {(field) => (
                  <PoolGrantPicker
                    pools={pools}
                    query={poolsQuery}
                    selected={field.state.value ?? []}
                    onChange={field.handleChange}
                  />
                )}
              </form.Field>
            ) : null}
            <FieldProblems id={errorIds.pools} messages={errors.pools} />
          </AdvancedSection>
          <AdvancedSection
            title={t("sdkKeys:form.sections.sandboxes")}
            summary={sandboxSummary}
            data-section="sandboxes"
          >
            <form.Field name="ownSandboxesOnly">
              {(field) => (
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Checkbox
                    checked={field.state.value ?? false}
                    onCheckedChange={(value) => field.handleChange(value === true)}
                  />
                  <span>{t("sdkKeys:form.ownSandboxesOnly")}</span>
                </label>
              )}
            </form.Field>
            <p className="text-xs text-muted-foreground">
              {t("sdkKeys:form.ownSandboxesOnlyHint")}
            </p>
          </AdvancedSection>
        </div>
      </Section>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`credentials:problem.${problem}`)}
        </p>
      ) : null}
    </>
  );
  const actions = (
    <>
      <Button type="button" variant="outline" size="touch" onClick={close}>
        {t(mode === "consent" ? "agents:consent.deny" : "common:actions.cancel")}
      </Button>
      <form.Subscribe selector={(state) => state.isSubmitting}>
        {(submitting) => (
          <Button type="submit" size="touch" disabled={submitting}>
            {submitting
              ? t("credentials:form.minting")
              : t(mode === "consent" ? "agents:consent.allow" : `${ns}:mint.submit`)}
          </Button>
        )}
      </form.Subscribe>
    </>
  );
  const onSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    event.stopPropagation();
    submit();
  };
  if (mode === "consent")
    return (
      <form ref={formRef} noValidate className="flex min-w-0 flex-col gap-4" onSubmit={onSubmit}>
        {fields}
        <div className="flex flex-wrap gap-2">{actions}</div>
      </form>
    );
  const invalidCount =
    errors.name.length + errors.scopes.length + errors.resources.length + errors.pools.length;
  return (
    <Sheet
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <SheetContent
        side="right"
        size="wide"
        closeLabel={t("common:actions.close")}
        className="gap-0 overflow-hidden"
      >
        <form ref={formRef} noValidate className="flex min-h-0 flex-1 flex-col" onSubmit={onSubmit}>
          <SheetHeader className="border-b pt-[max(1rem,var(--safe-area-top))]">
            <SheetTitle className="text-base">{t(`${ns}:mint.title`)}</SheetTitle>
            <SheetDescription className="text-sm">{t(`${ns}:mint.description`)}</SheetDescription>
          </SheetHeader>
          <SheetBody className="space-y-8 pt-4">{fields}</SheetBody>
          {/* Status first, then the actions with the primary last (shell rules). */}
          <SheetFooter className="min-w-0 flex-row flex-wrap items-center gap-x-4 gap-y-2">
            <p className="min-w-0 flex-1 text-sm text-muted-foreground" data-sheet-status="">
              {attempted && (invalidCount > 0 || expiryInvalid)
                ? t("common:form.fixErrors")
                : `${t(`sdkKeys:form.preset.${accessChoiceFor(values.scopes)}.title`)} · ${t(
                    "sdkKeys:form.scopeCount",
                    { count: values.scopes.length },
                  )}`}
            </p>
            <div className="flex flex-wrap gap-2">{actions}</div>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

export function ScopePicker({
  value,
  onChange,
  offered,
  form = "consent",
  invalid = false,
  errorId,
}: {
  /** Which form: only `sdk` offers API-key-only scopes (`sandboxes:connect`). */
  form?: "sdk" | "agent" | "consent";
  offered?: readonly ServiceScope[];
  value: readonly ServiceScope[];
  onChange: (next: ServiceScope[]) => void;
  /** After a failed submit: the scope set is refused (marks the offending boxes). */
  invalid?: boolean;
  errorId?: string;
}) {
  const { t } = useTranslation(["sdkKeys"]);
  const unusable = new Set(unusableScopes(value));
  const groups = offeredScopeGroups(form, offered);
  // Which boxes carry the error: the unusable ones, webhooks:write when it is
  // the refused one, else the first box (nothing chosen).
  const flagged = new Set<ServiceScope>(unusable);
  if (invalid && value.includes("webhooks:write") && flagged.size === 0)
    flagged.add("webhooks:write");
  const first = groups[0]?.scopes[0];
  if (invalid && flagged.size === 0 && first) flagged.add(first);
  return (
    <fieldset className="flex min-w-0 flex-col gap-3" data-scope-picker="">
      <legend className="text-sm font-medium">{t("sdkKeys:form.scopes")}</legend>
      <p className="text-xs text-muted-foreground">{t("sdkKeys:form.scopesHint")}</p>
      {groups.map((group) => (
        <div key={group.id} data-scope-group={group.id} className="flex min-w-0 flex-col gap-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t(`sdkKeys:scopeGroup.${group.id}`)}
          </p>
          {DESCRIBED_SCOPE_GROUPS.has(group.id) ? (
            <p data-scope-group-hint={group.id} className="text-xs text-muted-foreground">
              {t(`sdkKeys:scopeGroupHint.${group.id}`)}
            </p>
          ) : null}
          {group.scopes.map((scope) => {
            const key = scopeKey(scope);
            const base = `scope-${key.replace(".", "-")}`;
            const describedBy = [
              `${base}-text`,
              unusable.has(scope) ? `${base}-hint` : null,
              flagged.has(scope) && errorId ? errorId : null,
            ]
              .filter(Boolean)
              .join(" ");
            return (
              <div key={scope} className="flex min-w-0 flex-col">
                <label className="flex min-h-11 items-start gap-3 text-sm">
                  <Checkbox
                    name="scopes"
                    value={scope}
                    checked={value.includes(scope)}
                    aria-labelledby={`${base}-name ${base}-id`}
                    aria-describedby={describedBy}
                    aria-invalid={flagged.has(scope) || undefined}
                    onCheckedChange={(checked) => onChange(toggle(value, scope, checked))}
                    className="mt-1"
                  />
                  <span className="min-w-0">
                    <span className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                      <span id={`${base}-name`} className="font-medium">
                        {t(`sdkKeys:scopeTitle.${key}`)}
                      </span>
                      <span id={`${base}-id`} className="font-mono text-xs text-muted-foreground">
                        {scope}
                      </span>
                    </span>
                    <span id={`${base}-text`} className="block text-xs text-muted-foreground">
                      {t(`sdkKeys:scope.${key}`)}
                    </span>
                  </span>
                </label>
                {unusable.has(scope) ? (
                  <p
                    id={`${base}-hint`}
                    data-scope-needs={scope}
                    className="text-xs text-destructive"
                  >
                    {t(`sdkKeys:scopeNeeds.${key}`)}
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>
      ))}
    </fieldset>
  );
}

type PickerHost = { id: string; slug: string; label: string };
type PickerMore = { hasNextPage: boolean; isFetchingNextPage: boolean; onLoadMore: () => void };
type PickerTemplate = {
  id: string;
  slug: string;
  label: string;
  availability: readonly {
    hostId: string;
    status: "AVAILABLE" | "PENDING" | "MISSING" | "REJECTED";
  }[];
  retiredAt: Date | string | null;
};

function AllowlistPicker({
  hosts,
  templates,
  hostIds,
  templateRevisionIds,
  hostsFailed,
  templatesFailed,
  loading,
  onRetry,
  moreHosts,
  moreTemplates,
  onHosts,
  onTemplates,
}: {
  hosts: readonly PickerHost[];
  templates: readonly PickerTemplate[];
  hostIds: readonly string[];
  templateRevisionIds: readonly string[];
  hostsFailed: boolean;
  templatesFailed: boolean;
  loading: boolean;
  onRetry: () => void;
  moreHosts: PickerMore;
  moreTemplates: PickerMore;
  onHosts: (next: string[]) => void;
  onTemplates: (next: string[]) => void;
}) {
  const { t } = useTranslation(["sdkKeys", "credentials"]);
  if (hostsFailed || templatesFailed) {
    return (
      <InlineRetry
        variant="destructive"
        message={t("sdkKeys:form.resourcesFailed")}
        onRetry={onRetry}
      />
    );
  }
  if (loading) return <SkeletonList count={2} className="rounded-xl border" />;
  const offered = hostIds.length
    ? selectableTemplates(templates, hostIds)
    : templates.filter((item) => item.retiredAt == null);
  const selectedHosts = new Set(hostIds);
  const hostLabels = new Map(hosts.map((host) => [host.id, host.label]));
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <fieldset className="flex min-w-0 flex-col gap-1">
        <legend className="text-sm font-medium">{t("sdkKeys:form.hosts")}</legend>
        {hosts.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("sdkKeys:form.noHosts")}</p>
        ) : (
          hosts.map((host) => (
            <label key={host.id} className="flex min-h-11 items-center gap-3 text-sm">
              <Checkbox
                name="hostIds"
                value={host.id}
                checked={hostIds.includes(host.id)}
                onCheckedChange={(checked) => onHosts(toggle(hostIds, host.id, checked))}
              />
              <span className="min-w-0 truncate">
                <ResourceIdentity label={host.label} slug={host.slug} />
              </span>
            </label>
          ))
        )}
        <LoadMore {...moreHosts} label={t("sdkKeys:form.moreHosts")} />
      </fieldset>
      <fieldset className="flex min-w-0 flex-col gap-1">
        <legend className="text-sm font-medium">{t("sdkKeys:form.templates")}</legend>
        {offered.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {hostIds.length === 0 ? t("sdkKeys:form.pickHostFirst") : t("sdkKeys:form.noTemplates")}
          </p>
        ) : (
          offered.map((template) => (
            <label key={template.id} className="flex min-h-11 items-center gap-3 text-sm">
              <Checkbox
                name="templateRevisionIds"
                value={template.id}
                checked={templateRevisionIds.includes(template.id)}
                onCheckedChange={(checked) =>
                  onTemplates(toggle(templateRevisionIds, template.id, checked))
                }
              />
              <span className="min-w-0 break-words">
                <ResourceIdentity label={template.label} slug={template.slug} />
                <span className="block break-all font-mono text-xs">{template.id}</span>
                {template.availability.flatMap((entry) =>
                  selectedHosts.has(entry.hostId)
                    ? [
                        <span
                          key={entry.hostId}
                          className="block break-words text-xs text-muted-foreground"
                        >
                          {translateText(t, "sdkKeys:form.association", {
                            host: hostLabels.get(entry.hostId) ?? entry.hostId,
                            status: t(`sdkKeys:form.availability.${entry.status}`),
                          })}
                        </span>,
                      ]
                    : [],
                )}
              </span>
            </label>
          ))
        )}
        <LoadMore {...moreTemplates} label={t("sdkKeys:form.moreTemplates")} />
      </fieldset>
    </div>
  );
}

function PoolGrantPicker({
  pools,
  query,
  selected,
  onChange,
}: {
  pools: readonly {
    id: string;
    label: string;
    slug: string;
    owner?: { id: string; name: string };
  }[];
  query: {
    isPending: boolean;
    isError: boolean;
    refetch: () => unknown;
    hasNextPage: boolean;
    isFetchingNextPage: boolean;
    fetchNextPage: () => unknown;
  };
  selected: readonly string[];
  onChange: (value: readonly string[]) => void;
}) {
  const { t } = useTranslation(["sdkKeys", "common"]);
  return (
    <fieldset className="flex flex-col gap-2">
      <legend>{t("sdkKeys:form.pools")}</legend>
      <p className="text-xs text-muted-foreground">{t("sdkKeys:form.poolsHint")}</p>
      {query.isPending ? <SkeletonList count={1} /> : null}
      {query.isError ? (
        <InlineRetry
          message={t("sdkKeys:form.resourcesFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : null}
      {pools.map((pool) => (
        <label key={pool.id} className="flex min-h-11 items-center gap-3">
          <Checkbox
            checked={selected.includes(pool.id)}
            onCheckedChange={(checked) => onChange(toggle(selected, pool.id, checked))}
          />
          <span className="min-w-0 break-words">
            <ResourceIdentity label={pool.label} slug={pool.slug} />
            <span className="block">{pool.owner?.name ?? t("sdkKeys:form.ownedPool")}</span>
            <span className="block break-all font-mono text-xs">{pool.id}</span>
          </span>
        </label>
      ))}
      <LoadMore
        hasNextPage={query.hasNextPage}
        isFetchingNextPage={query.isFetchingNextPage}
        onLoadMore={() => void query.fetchNextPage()}
      />
    </fieldset>
  );
}

/** The CLI logins an allowlist key reaches (paged; required with credentials:use). */
function LoginAllowlistPicker({
  lang,
  selected,
  required,
  onChange,
}: {
  lang: string;
  selected: readonly string[];
  required: boolean;
  onChange: (next: string[]) => void;
}) {
  const { t } = useTranslation(["sdkKeys"]);
  const logins = useInfiniteQuery({
    ...orpc.logins.listLogins.infiniteOptions({
      ...pickerPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [logins.error]);
  const rows = logins.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <fieldset className="flex min-w-0 flex-col gap-1" data-login-allowlist="">
      <legend className="text-sm font-medium">{t("sdkKeys:form.logins")}</legend>
      <p className="text-xs text-muted-foreground">
        {required ? t("sdkKeys:form.loginsRequired") : t("sdkKeys:form.loginsHint")}
      </p>
      {logins.isPending ? (
        <SkeletonList count={1} className="rounded-xl border" />
      ) : logins.isError ? (
        <InlineRetry
          variant="destructive"
          message={t("sdkKeys:form.loginsFailed")}
          onRetry={() => void logins.refetch()}
        />
      ) : rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("sdkKeys:form.noLogins")}</p>
      ) : (
        rows.map((login) => (
          <label key={login.id} className="flex min-h-11 items-center gap-3 text-sm">
            <Checkbox
              name="credentialIds"
              value={login.id}
              checked={selected.includes(login.id)}
              onCheckedChange={(checked) => onChange(toggle(selected, login.id, checked === true))}
            />
            <span className="min-w-0 break-words">{login.name}</span>
          </label>
        ))
      )}
      <LoadMore
        hasNextPage={logins.hasNextPage}
        isFetchingNextPage={logins.isFetchingNextPage}
        onLoadMore={() => void logins.fetchNextPage()}
        label={t("sdkKeys:form.moreLogins")}
      />
    </fieldset>
  );
}
