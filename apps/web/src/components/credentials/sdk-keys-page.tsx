import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import type { AgentTokenExpiryPolicy } from "@wssp/config/agent-token-limits";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import { TextField } from "@wssp/ui/components/text-field";
import { Plus } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import {
  CredentialDates,
  ExpirySelect,
  OneTimeSecretPanel,
  OrphanedCredentialsAlert,
  useRevoke,
} from "@/components/credentials/credential-parts";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { ResourceIdentity } from "@/components/resource-identity";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { type OneTimeSecret, useOneTimeSecret } from "@/hooks/use-one-time-secret";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { agentTokenExpiry, agentTokenExpiryPresets } from "@/lib/agent-token-expiry";
import {
  CREDENTIAL_NAME_MAX,
  type CredentialProblem,
  credentialProblem,
  credentialsUseRevealsValues,
  type ResourceMode,
  SCOPE_GROUPS,
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

/**
 * SDK keys (C45): owner-scoped `wssp_sdk_` keys for the /v1 API, with scopes,
 * optional host/template allowlists and expiry. The raw key is shown once from
 * transient component state (useOneTimeSecret); the list carries metadata and
 * the lookup prefix only. The browser refuses scope sets where a scope grants
 * nothing and allowlists naming anything but the owner's selectable hosts and
 * their active templates; the server re-checks ownership and scopes.
 */

/**
 * The mint form's allowlist pickers page hosts and templates with Load more,
 * the same cursor paging as the lists (the procedure maximum per page).
 */
const PICKER_LIMIT = 100;
const pickerPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

type KeyPage = Awaited<ReturnType<AppRouterClient["sdkKeys"]["list"]>>;
type KeyItem = KeyPage["items"][number];

export function SdkKeysPage({ lang, agent = false }: { lang: string; agent?: boolean }) {
  const api = agent ? orpc.agentTokens : orpc.sdkKeys;
  const ns = agent ? "agents" : "sdkKeys";
  const { t, i18n } = useTranslation(["sdkKeys", "agents", "credentials", "dashboard", "common"]);
  const keys = useInfiniteQuery({
    ...api.list.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor }),
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
            disabled={oneTime.revealed != null}
            onClick={() => setMinting(true)}
          >
            <Plus aria-hidden="true" />
            {t(`${ns}:mint.action`)}
          </Button>
        }
      />
      {oneTime.revealed ? (
        <OneTimeSecretPanel
          secret={oneTime.revealed.secret}
          label={t(`${ns}:mint.secretLabel`)}
          onDone={oneTime.clear}
        >
          <p className="text-sm text-muted-foreground">{t(`${ns}:mint.usageHint`)}</p>
        </OneTimeSecretPanel>
      ) : null}
      <OrphanedCredentialsAlert orphans={oneTime.orphans} onRetry={oneTime.retryOrphan} />
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
            title={t(`${ns}:empty.title`)}
            description={t(`${ns}:empty.description`)}
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
  const blockedByPolicy = agent && sdkKey.blockedByPolicy === true;
  return (
    <li
      data-credential-id={sdkKey.id}
      data-expired={expired ? "true" : undefined}
      data-blocked-by-policy={blockedByPolicy ? "true" : undefined}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-2">
            <p className="truncate text-sm font-medium">{sdkKey.name}</p>
            {sdkKey.origin === "CLI_LOGIN" ? (
              <Badge data-origin={sdkKey.origin} className="shrink-0">
                {t("sdkKeys:list.cliLogin")}
              </Badge>
            ) : null}
          </div>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {t("credentials:prefix", { prefix: sdkKey.lookupPrefix })}
          </p>
        </div>
        <Button
          type="button"
          variant="destructive"
          size="touch"
          disabled={revoke.mutation.isPending}
          onClick={() => revoke.setConfirming(true)}
        >
          {t("credentials:revoke.action")}
        </Button>
      </div>
      <ul aria-label={t("sdkKeys:list.scopes")} className="flex min-w-0 flex-wrap gap-1.5">
        {sdkKey.scopes.map((scope) => (
          <li
            key={scope}
            data-scope={scope}
            className="inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-xs"
          >
            {scope}
          </li>
        ))}
      </ul>
      {sdkKey.resourceMode === "ALL_OWNED" ? (
        <p className="text-sm" data-resource-mode={sdkKey.resourceMode}>
          {t("sdkKeys:list.allOwned")}
        </p>
      ) : (
        <div className="min-w-0 text-sm" data-resource-mode={sdkKey.resourceMode}>
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
        </div>
      )}
      <p className="text-sm" data-pool-mode={sdkKey.poolMode}>
        {t(
          sdkKey.poolMode === "ALL_USABLE"
            ? "sdkKeys:poolMode.ALL_USABLE"
            : "sdkKeys:poolMode.SELECTED",
        )}
      </p>
      {sdkKey.resourceMode === "ALLOWLIST" && (sdkKey.credentialAllowlist ?? []).length > 0 ? (
        <p data-allowlist="logins" className="break-words text-muted-foreground">
          {translateText(t, "sdkKeys:list.allowlistLogins", {
            names: listNames(
              (sdkKey.credentialAllowlist ?? []).map((login) => login.name),
              locale,
            ),
          })}
        </p>
      ) : null}
      {sdkKey.poolMode === "SELECTED" ? (
        <p data-allowlist="pools" className="break-words text-muted-foreground">
          {t("sdkKeys:list.allowlistPools", {
            names: listNames(
              (sdkKey.poolAllowlist ?? []).map((pool) =>
                translateText(t, "sdkKeys:resourceIdentity", { label: pool.label, id: pool.id }),
              ),
              locale,
            ),
          })}
        </p>
      ) : null}
      <p className="text-sm">
        {t(
          sdkKey.ownSandboxesOnly ? "sdkKeys:form.ownSandboxesOnly" : "sdkKeys:list.otherSandboxes",
        )}
      </p>
      {sdkKey.maxLiveSandboxes != null ? (
        <p className="text-sm" data-max-live-sandboxes={sdkKey.maxLiveSandboxes}>
          {t("sdkKeys:list.maxLiveSandboxes", { count: sdkKey.maxLiveSandboxes })}
        </p>
      ) : null}
      <CredentialDates
        createdAt={sdkKey.createdAt}
        lastUsedAt={sdkKey.lastUsedAt}
        expiresAt={sdkKey.expiresAt}
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

const DEFAULT_DRAFT: SdkKeyDraft = {
  name: "",
  scopes: [],
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
  const expiryId = useId();
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
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...pickerPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = selectableHosts(hostsQuery.data?.pages.flatMap((page) => page.items) ?? []);

  const draftValidator = z.custom<SdkKeyDraft>().superRefine((draft, context) => {
    for (const issue of sdkKeyDraftProblems(draft, options))
      context.addIssue({ code: "custom", message: t(`credentials:draft.${issue}`) });
  });
  const initialDraft: SdkKeyDraft = {
    ...DEFAULT_DRAFT,
    name: consentName,
    ownSandboxesOnly: mode !== "sdk",
    scopes: requestedScopes?.filter((scope) => !scope.startsWith("hosts:")) ?? [],
  };
  const form = useForm({
    defaultValues: initialDraft,
    validators: { onChange: draftValidator, onSubmit: draftValidator },
    onSubmit: async ({ value }) => {
      setAttempted(true);
      if (sdkKeyDraftProblems(value, options).length > 0) return;
      if (
        mode === "agent" &&
        (!expiryPolicy ||
          agentTokenExpiry(agentExpiryChoice, agentCustomDate, Date.now(), expiryPolicy) ===
            undefined)
      )
        return;
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
          // Closed while minting: nobody saw this key, so revoke the orphan.
          (result) => ({ id: result.key.id, label: result.key.name }),
        );
        // The page now shows the key inline; the dialog's job is done.
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
          // The deployment's expiry policy changed under the open dialog: reload it.
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
  // Cancelling discards a mint still in flight (it is revoked, never shown).
  const close = () => {
    oneTime?.discardPending();
    onClose();
  };

  const content = (
    <form
      noValidate
      className="flex min-w-0 flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        event.stopPropagation();
        setAttempted(true);
        void form.handleSubmit();
      }}
    >
      {mode !== "consent" ? (
        <form.Field name="name">
          {(field) => (
            <TextField
              inputClassName="min-h-11"
              field={field}
              label={t("credentials:form.name")}
              autoComplete="off"
              inputMode="text"
              maxLength={CREDENTIAL_NAME_MAX}
            />
          )}
        </form.Field>
      ) : null}
      <form.Field name="scopes">
        {(field) => (
          <ScopePicker
            offered={requestedScopes}
            value={field.state.value}
            onChange={field.handleChange}
          />
        )}
      </form.Field>
      <form.Field name="poolMode">
        {(field) => (
          <fieldset>
            <legend>{t("sdkKeys:poolMode.title")}</legend>
            {(["ALL_USABLE", "SELECTED"] as const).map((mode) => (
              <label key={mode} className="flex min-h-11 items-center gap-3">
                <input
                  type="radio"
                  name="poolMode"
                  autoComplete="off"
                  checked={field.state.value === mode}
                  onChange={() => field.handleChange(mode)}
                />
                {t(`sdkKeys:poolMode.${mode}`)}
              </label>
            ))}
          </fieldset>
        )}
      </form.Field>
      <p>{t("sdkKeys:poolMode.immutable")}</p>
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
      {values.resourceMode === "ALLOWLIST" && !values.hostIds.length ? (
        <label className="flex min-h-11 flex-col gap-2">
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
                {pool.label} · {"owner" in pool ? pool.owner?.name : t("sdkKeys:form.ownedPool")} ·{" "}
                {pool.id}
              </option>
            ))}
          </select>
        </label>
      ) : null}
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
                (mode) => (
                  <label key={mode} className="flex min-h-11 items-start gap-3 text-sm">
                    <RadioGroupItem value={mode} className="mt-1" />
                    <span className="min-w-0">
                      <span className="block">{t(`sdkKeys:form.mode.${mode}`)}</span>
                      <span className="block text-xs text-muted-foreground">
                        {t(`sdkKeys:form.modeHint.${mode}`)}
                      </span>
                    </span>
                  </label>
                ),
              )}
            </RadioGroup>
          </div>
        )}
      </form.Field>
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
      {credentialsUseRevealsValues(values.scopes) ? (
        <p
          role="note"
          data-credentials-use-disclosure=""
          className="rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
        >
          {t("sdkKeys:form.credentialsUseDisclosure")}
        </p>
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
      <p className="text-xs text-muted-foreground">{t("sdkKeys:form.ownSandboxesOnlyHint")}</p>
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
        <>
          <AgentTokenExpirySelect
            id={expiryId}
            policy={expiryPolicy}
            value={agentExpiryChoice}
            onChange={setAgentExpiryChoice}
            customDate={agentCustomDate}
            onCustomDateChange={setAgentCustomDate}
          />
          {attempted &&
          agentTokenExpiry(agentExpiryChoice, agentCustomDate, Date.now(), expiryPolicy) ===
            undefined ? (
            <p role="alert" className="text-sm text-destructive">
              {t("agents:expiry.invalid")}
            </p>
          ) : null}
        </>
      ) : mode !== "consent" ? (
        <form.Field name="expiry">
          {(field) => (
            <ExpirySelect id={expiryId} value={field.state.value} onChange={field.handleChange} />
          )}
        </form.Field>
      ) : null}
      {problems.length > 0 ? (
        <ul role="alert" className="list-disc pl-5 text-sm text-destructive">
          {problems.map((item) => (
            <li key={item}>{t(`credentials:draft.${item}`)}</li>
          ))}
        </ul>
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`credentials:problem.${problem}`)}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <form.Subscribe selector={(state) => state.isSubmitting}>
          {(submitting) => (
            <Button type="submit" size="touch" disabled={submitting}>
              {submitting
                ? t("credentials:form.minting")
                : t(mode === "consent" ? "agents:consent.allow" : `${ns}:mint.submit`)}
            </Button>
          )}
        </form.Subscribe>
        <Button type="button" variant="outline" size="touch" onClick={close}>
          {t(mode === "consent" ? "agents:consent.deny" : "common:actions.cancel")}
        </Button>
      </div>
    </form>
  );
  if (mode === "consent") return content;
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t(`${ns}:mint.title`)}</DialogTitle>
          <DialogDescription>{t(`${ns}:mint.description`)}</DialogDescription>
        </DialogHeader>
        {content}
      </DialogContent>
    </Dialog>
  );
}

export function ScopePicker({
  value,
  onChange,
  offered,
}: {
  offered?: readonly ServiceScope[];
  value: readonly ServiceScope[];
  onChange: (next: ServiceScope[]) => void;
}) {
  const { t } = useTranslation(["sdkKeys"]);
  const unusable = new Set(unusableScopes(value));
  return (
    <fieldset className="flex min-w-0 flex-col gap-3">
      <legend className="text-sm font-medium">{t("sdkKeys:form.scopes")}</legend>
      <p className="text-xs text-muted-foreground">{t("sdkKeys:form.scopesHint")}</p>
      {SCOPE_GROUPS.map((group) => ({
        ...group,
        scopes: group.scopes.filter((scope) => !offered || offered.includes(scope)),
      }))
        .filter((group) => group.scopes.length > 0)
        .map((group) => (
          <div key={group.id} className="flex min-w-0 flex-col gap-1">
            <p className="text-xs font-medium text-muted-foreground">
              {t(`sdkKeys:scopeGroup.${group.id}`)}
            </p>
            {group.scopes.map((scope) => {
              const key = scopeKey(scope);
              const base = `scope-${key.replace(".", "-")}`;
              return (
                <div key={scope} className="flex min-w-0 flex-col">
                  <label className="flex min-h-11 items-start gap-3 text-sm">
                    <Checkbox
                      name="scopes"
                      value={scope}
                      checked={value.includes(scope)}
                      aria-labelledby={`${base}-name`}
                      aria-describedby={
                        unusable.has(scope) ? `${base}-text ${base}-hint` : `${base}-text`
                      }
                      aria-invalid={unusable.has(scope) || undefined}
                      onCheckedChange={(checked) => onChange(toggle(value, scope, checked))}
                      className="mt-1"
                    />
                    <span className="min-w-0">
                      <span id={`${base}-name`} className="block font-mono text-xs">
                        {scope}
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
