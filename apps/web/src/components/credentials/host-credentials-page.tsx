import { useForm, useStore } from "@tanstack/react-form";
import { type QueryClient, useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import { CopyField } from "@wssp/ui/components/copy-field";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { TextField } from "@wssp/ui/components/text-field";
import { FIRST_INVALID_SELECTOR, focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { Plus } from "lucide-react";
import { useId, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Trans, useTranslation } from "react-i18next";
import {
  CredentialDates,
  CredentialHostLine,
  ExpirySelect,
  OneTimeSecretPanel,
  OrphanedCredentialsAlert,
  RevokeCredentialDialog,
  SecretLeaveGuard,
  useRevoke,
} from "@/components/credentials/credential-parts";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { HostsTabs } from "@/components/hosts/hosts-tabs";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { ResourceIdentity } from "@/components/resource-identity";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { type OneTimeSecret, useOneTimeSecret } from "@/hooks/use-one-time-secret";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  CREDENTIAL_NAME_MAX,
  type CredentialProblem,
  credentialProblem,
  type HostTokenDraft,
  type HostTokenDraftProblem,
  hostTokenDraftProblems,
  hostTokenMintInput,
  selectableHosts,
} from "@/lib/credential-rules";
import { hostCommands } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/**
 * Host credentials (C45): dashboard-minted host tokens and the device
 * credentials `wssp host enroll` created. A minted token's secret is shown once,
 * from transient component state (see useOneTimeSecret); lists carry only
 * metadata and the lookup prefix. Revoking closes any live connection that
 * used the credential, so the host's status is refetched after every revoke.
 */

/** Same cadence as the Hosts page: a revoked live host's status catches up. */
const CREDENTIALS_REFETCH_MS = 15_000;
/** One read of hosts for the mint form's picker (the procedure's maximum). */
const HOST_PICKER_LIMIT = 100;

type TokenPage = Awaited<ReturnType<AppRouterClient["sandboxHosts"]["listHostTokens"]>>;
type TokenItem = TokenPage["items"][number];
type DevicePage = Awaited<ReturnType<AppRouterClient["sandboxHosts"]["listDeviceCredentials"]>>;
type DeviceItem = DevicePage["items"][number];

const cursorPage = {
  input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor }),
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

function invalidateHostCredentials(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listHostTokens.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listDeviceCredentials.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listHosts.key() });
}

export function HostCredentialsPage({ lang }: { lang: string }) {
  const { t, i18n } = useTranslation(["hostCredentials", "credentials", "dashboard", "common"]);
  const tokens = useInfiniteQuery({
    ...orpc.sandboxHosts.listHostTokens.infiniteOptions(cursorPage),
    refetchInterval: CREDENTIALS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const devices = useInfiniteQuery({
    ...orpc.sandboxHosts.listDeviceCredentials.infiniteOptions(cursorPage),
    refetchInterval: CREDENTIALS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [tokens.error, devices.error]);
  const [minting, setMinting] = useState(false);
  // Page-level, not dialog-level: the minted secret is shown inline below and
  // stays until the owner dismisses it (M7-S4).
  const queryClient = useQueryClient();
  const oneTime = useOneTimeSecret<MintedToken>({
    scope: "hostToken",
    revoke: (id) =>
      orpc.sandboxHosts.revokeHostToken
        .call({ id })
        .finally(() => invalidateHostCredentials(queryClient)),
  });
  const now = Date.now();
  const tokenRows = tokens.data?.pages.flatMap((page) => page.items);
  const deviceRows = devices.data?.pages.flatMap((page) => page.items);

  return (
    <div className="flex min-w-0 flex-col gap-8">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("hostCredentials:title")}
        description={t("hostCredentials:description")}
      />
      <HostsTabs lang={lang} />
      <section aria-labelledby="host-tokens-title" className="flex min-w-0 flex-col gap-3">
        <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h2 id="host-tokens-title" className="text-base font-medium">
              {t("hostCredentials:tokens.title")}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t("hostCredentials:tokens.description")}
            </p>
          </div>
          <Button
            type="button"
            size="touch"
            disabled={oneTime.revealed != null}
            onClick={() => setMinting(true)}
          >
            <Plus aria-hidden="true" />
            {t("hostCredentials:mint.action")}
          </Button>
        </div>
        <SecretLeaveGuard active={oneTime.revealed != null} />
        {oneTime.revealed ? (
          <OneTimeSecretPanel
            secret={oneTime.revealed.secret}
            label={t("hostCredentials:mint.secretLabel")}
            onDone={oneTime.clear}
          >
            {oneTime.revealed.meta.connect ? (
              <div className="flex min-w-0 flex-col gap-2">
                <p className="text-sm text-muted-foreground">
                  {t("hostCredentials:mint.connectHint")}
                  <span className="block">
                    <Trans
                      t={t}
                      i18nKey="hostCredentials:mint.vmCapacityHint"
                      components={{ code: <code className="whitespace-nowrap" /> }}
                    />
                  </span>
                </p>
                <CopyField
                  value={oneTime.revealed.meta.connect}
                  copyLabel={t("hostCredentials:mint.copyCommand")}
                />
              </div>
            ) : null}
          </OneTimeSecretPanel>
        ) : null}
        <OrphanedCredentialsAlert orphans={oneTime.orphans} onRetry={oneTime.retryOrphan} />
        <QueryBoundary
          query={{
            data: tokenRows,
            isPending: tokens.isPending,
            isError: tokens.isError,
            error: tokens.error,
            refetch: tokens.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              className="rounded-xl border px-4"
              title={t("hostCredentials:empty.title")}
              description={t("hostCredentials:empty.description")}
            />
          }
        >
          {(rows) => (
            <>
              <ul
                aria-label={t("hostCredentials:tokens.title")}
                className="flex min-w-0 flex-col gap-3"
              >
                {rows.map((token) => (
                  <HostTokenRow
                    key={token.id}
                    token={token}
                    now={now}
                    lang={lang}
                    locale={i18n.language}
                  />
                ))}
              </ul>
              <LoadMore
                hasNextPage={tokens.hasNextPage}
                isFetchingNextPage={tokens.isFetchingNextPage}
                onLoadMore={() => void tokens.fetchNextPage()}
              />
            </>
          )}
        </QueryBoundary>
      </section>
      <section aria-labelledby="device-credentials-title" className="flex min-w-0 flex-col gap-3">
        <div className="min-w-0">
          <h2 id="device-credentials-title" className="text-base font-medium">
            {t("hostCredentials:devices.title")}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t("hostCredentials:devices.description")}
          </p>
        </div>
        <QueryBoundary
          query={{
            data: deviceRows,
            isPending: devices.isPending,
            isError: devices.isError,
            error: devices.error,
            refetch: devices.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              className="rounded-xl border px-4"
              title={t("hostCredentials:devices.emptyTitle")}
              description={t("hostCredentials:devices.emptyDescription")}
            />
          }
        >
          {(rows) => (
            <>
              <ul
                aria-label={t("hostCredentials:devices.title")}
                className="flex min-w-0 flex-col gap-3"
              >
                {rows.map((device) => (
                  <DeviceCredentialRow
                    key={device.id}
                    device={device}
                    now={now}
                    lang={lang}
                    locale={i18n.language}
                  />
                ))}
              </ul>
              <LoadMore
                hasNextPage={devices.hasNextPage}
                isFetchingNextPage={devices.isFetchingNextPage}
                onLoadMore={() => void devices.fetchNextPage()}
              />
            </>
          )}
        </QueryBoundary>
      </section>
      {minting ? (
        <MintHostTokenDialog lang={lang} oneTime={oneTime} onClose={() => setMinting(false)} />
      ) : null}
    </div>
  );
}

function HostTokenRow({
  token,
  now,
  lang,
  locale,
}: {
  token: TokenItem;
  now: number;
  lang: string;
  locale: string;
}) {
  const { t } = useTranslation(["hostCredentials", "credentials"]);
  const revoke = useRevoke(
    lang,
    (id) => orpc.sandboxHosts.revokeHostToken.call({ id }),
    t("hostCredentials:revoke.tokenDone"),
    invalidateHostCredentials,
  );
  return (
    <li
      data-credential-id={token.id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium [overflow-wrap:anywhere]">{token.name}</p>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {t("credentials:prefix", { prefix: token.lookupPrefix })}
          </p>
        </div>
        <Button
          type="button"
          variant="destructive"
          size="touch"
          aria-label={t("credentials:revoke.actionNamed", { name: token.name })}
          disabled={revoke.mutation.isPending}
          onClick={() => revoke.setConfirming(true)}
        >
          {t("credentials:revoke.action")}
        </Button>
      </div>
      <CredentialHostLine host={token.host} now={now} />
      <CredentialDates
        createdAt={token.createdAt}
        lastUsedAt={token.lastUsedAt}
        expiresAt={token.expiresAt}
        now={now}
        locale={locale}
      />
      {revoke.problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`credentials:problem.${revoke.problem}`)}
        </p>
      ) : null}
      <RevokeCredentialDialog
        open={revoke.confirming}
        onOpenChange={revoke.setConfirming}
        title={t("hostCredentials:revoke.tokenTitle", { name: token.name })}
        description={t("hostCredentials:revoke.tokenDescription")}
        isPending={revoke.mutation.isPending}
        onConfirm={() => revoke.mutation.mutate(token.id)}
      />
    </li>
  );
}

function DeviceCredentialRow({
  device,
  now,
  lang,
  locale,
}: {
  device: DeviceItem;
  now: number;
  lang: string;
  locale: string;
}) {
  const { t } = useTranslation(["hostCredentials", "credentials"]);
  const revoke = useRevoke(
    lang,
    (id) => orpc.sandboxHosts.revokeDeviceCredential.call({ id }),
    t("hostCredentials:revoke.deviceDone"),
    invalidateHostCredentials,
  );
  return (
    <li
      data-credential-id={device.id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">
            {t("hostCredentials:devices.name", { slug: device.host.slug })}
          </p>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {t("credentials:prefix", { prefix: device.lookupPrefix })}
          </p>
        </div>
        <Button
          type="button"
          variant="destructive"
          size="touch"
          aria-label={t("credentials:revoke.actionNamed", {
            name: t("hostCredentials:devices.name", { slug: device.host.slug }),
          })}
          disabled={revoke.mutation.isPending}
          onClick={() => revoke.setConfirming(true)}
        >
          {t("credentials:revoke.action")}
        </Button>
      </div>
      <CredentialHostLine host={device.host} now={now} />
      <CredentialDates
        createdAt={device.createdAt}
        lastUsedAt={device.lastUsedAt}
        now={now}
        locale={locale}
      />
      {revoke.problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`credentials:problem.${revoke.problem}`)}
        </p>
      ) : null}
      <RevokeCredentialDialog
        open={revoke.confirming}
        onOpenChange={revoke.setConfirming}
        title={t("hostCredentials:revoke.deviceTitle", { slug: device.host.slug })}
        description={t("hostCredentials:revoke.deviceDescription")}
        isPending={revoke.mutation.isPending}
        onConfirm={() => revoke.mutation.mutate(device.id)}
      />
    </li>
  );
}

/** What the inline reveal needs besides the secret: the nonsecret connect command. */
type MintedToken = { id: string; connect: string | null };

function MintHostTokenDialog({
  lang,
  oneTime,
  onClose,
}: {
  lang: string;
  oneTime: OneTimeSecret<MintedToken>;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hostCredentials", "credentials", "common", "dashboard"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const hostId = useId();
  const hostErrorId = useId();
  const expiryId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const [attempted, setAttempted] = useState(false);
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) => ({ limit: HOST_PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = selectableHosts(hostsQuery.data?.pages.flatMap((page) => page.items) ?? []);

  const form = useForm({
    defaultValues: { name: "", hostId: "", expiry: "never" } as HostTokenDraft,
    onSubmit: async ({ value }) => {
      if (hostTokenDraftProblems(value, hosts).length > 0) return;
      setProblem(null);
      try {
        const outcome = await oneTime.run(
          () => orpc.sandboxHosts.createHostToken.call(hostTokenMintInput(value, Date.now())),
          (result) => {
            const host = hosts.find((item) => item.id === result.token.sandboxHostId);
            return {
              secret: result.secret,
              meta: {
                id: result.token.id,
                connect: host ? hostCommands(env.VITE_SERVER_URL, host).tokenConnect : null,
              },
            };
          },
          // Closed while minting: the secret was never shown, so nobody can
          // use this token. Revoke it rather than leave an orphan active.
          (result) => ({ id: result.token.id, label: result.token.name }),
        );
        // The page now shows the secret inline; the dialog's job is done.
        if (outcome === "revealed") onClose();
      } catch (error) {
        if (!redirect(error)) setProblem(credentialProblem(error));
      } finally {
        invalidateHostCredentials(queryClient);
      }
    },
  });

  const values = useStore(form.store, (state) => state.values);
  const problems = attempted ? hostTokenDraftProblems(values, hosts) : [];
  const NAME_PROBLEMS: readonly HostTokenDraftProblem[] = ["nameRequired", "nameTooLong"];
  const nameErrors = problems
    .filter((item) => NAME_PROBLEMS.includes(item))
    .map((item) => t(`credentials:draft.${item}`));
  const hostErrors = problems
    .filter((item) => !NAME_PROBLEMS.includes(item))
    .map((item) => t(`credentials:draft.${item}`));
  // Cancelling discards a mint still in flight (it is revoked, never shown).
  const close = () => {
    oneTime.discardPending();
    onClose();
  };

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : close())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("hostCredentials:mint.title")}</DialogTitle>
          <DialogDescription>{t("hostCredentials:mint.description")}</DialogDescription>
        </DialogHeader>
        <form
          ref={formRef}
          noValidate
          className="flex min-w-0 flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            flushSync(() => setAttempted(true));
            // Errors sit under their fields; the first invalid one gets focus.
            const root = formRef.current;
            if (root?.querySelector(FIRST_INVALID_SELECTOR)) focusFirstInvalidField(root);
            else void form.handleSubmit();
          }}
        >
          <form.Field name="name">
            {(field) => (
              <TextField
                field={{
                  name: field.name,
                  state: { value: field.state.value, meta: { errors: nameErrors } },
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
          {hostsQuery.isError ? (
            <InlineRetry
              variant="destructive"
              message={t("hostCredentials:mint.hostsFailed")}
              onRetry={() => void hostsQuery.refetch()}
            />
          ) : hosts.length === 0 && !hostsQuery.isPending && !hostsQuery.hasNextPage ? (
            <p className="text-sm text-muted-foreground">
              {t("hostCredentials:mint.noHosts")}{" "}
              <Link
                to="/$lang/settings/hosts"
                params={{ lang }}
                className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
              >
                {t("hostCredentials:mint.hostsLink")}
              </Link>
            </p>
          ) : (
            <form.Field name="hostId">
              {(field) => (
                <div className="flex min-w-0 flex-col gap-2">
                  <Label htmlFor={hostId}>{t("hostCredentials:mint.host")}</Label>
                  <FormSelect
                    id={hostId}
                    optionsSettled={
                      hostsQuery.isSuccess && !hostsQuery.isFetching && !hostsQuery.hasNextPage
                    }
                    value={field.state.value}
                    disabled={hostsQuery.isPending}
                    aria-invalid={hostErrors.length > 0 || undefined}
                    aria-describedby={hostErrors.length > 0 ? hostErrorId : undefined}
                    onValueChange={(value) => field.handleChange(value)}
                  >
                    <SelectItem value="">{t("hostCredentials:mint.chooseHost")}</SelectItem>
                    {hosts.map((host) => (
                      <SelectItem key={host.id} value={host.id}>
                        <ResourceIdentity label={host.label} slug={host.slug} />
                      </SelectItem>
                    ))}
                  </FormSelect>
                  {hostErrors.length > 0 ? (
                    <div id={hostErrorId} role="alert">
                      {hostErrors.map((message) => (
                        <p key={message} className="text-sm text-destructive">
                          {message}
                        </p>
                      ))}
                    </div>
                  ) : null}
                  <LoadMore
                    hasNextPage={hostsQuery.hasNextPage}
                    isFetchingNextPage={hostsQuery.isFetchingNextPage}
                    onLoadMore={() => void hostsQuery.fetchNextPage()}
                    label={t("hostCredentials:mint.moreHosts")}
                  />
                </div>
              )}
            </form.Field>
          )}
          <form.Field name="expiry">
            {(field) => (
              <ExpirySelect id={expiryId} value={field.state.value} onChange={field.handleChange} />
            )}
          </form.Field>
          {/* No host to choose: the host problem has no field to sit under. */}
          {hostErrors.length > 0 &&
          (hostsQuery.isError ||
            (hosts.length === 0 && !hostsQuery.isPending && !hostsQuery.hasNextPage)) ? (
            <p role="alert" className="text-sm text-destructive">
              {hostErrors.join(" ")}
            </p>
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
                  {submitting ? t("credentials:form.minting") : t("hostCredentials:mint.submit")}
                </Button>
              )}
            </form.Subscribe>
            <Button type="button" variant="outline" size="touch" onClick={close}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
