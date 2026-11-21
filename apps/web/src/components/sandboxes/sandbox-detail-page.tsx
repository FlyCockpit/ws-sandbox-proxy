import { type QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@wssp/ui/components/alert-dialog";
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { toast } from "@wssp/ui/components/sileo";
import { cn } from "@wssp/ui/lib/utils";
import { ArrowLeft, Trash2 } from "lucide-react";
import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CopyableId } from "@/components/copyable-id";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { PageHeader } from "@/components/page-shell";
import { SandboxConnectHint, SandboxConnections } from "@/components/sandboxes/sandbox-connections";
import { SandboxCredentials } from "@/components/sandboxes/sandbox-credentials";
import { DiskCard, OffloadPolicyText } from "@/components/sandboxes/sandbox-disk";
import { SandboxFiles } from "@/components/sandboxes/sandbox-files";
import {
  CapacityWaitLine,
  DiskLocationBadge,
  HostText,
  LifetimeFields,
  ReceiptLine,
  type SandboxView,
  StatePill,
  TemplateText,
} from "@/components/sandboxes/sandbox-parts";
import { SandboxTerminal } from "@/components/sandboxes/sandbox-terminal";
import {
  isSandboxBusy,
  SANDBOX_BUSY_REFETCH_MS,
  SANDBOX_IDLE_REFETCH_MS,
} from "@/components/sandboxes/sandboxes-page";
import { SkeletonList } from "@/components/skeleton-list";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useSharingRestoration } from "@/hooks/use-sharing-restoration";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { dateTimeTitle, formatDateTime } from "@/lib/format-date-time";
import { formatGraceDuration } from "@/lib/format-duration";
import { hostConnectionState, nextHostStateChangeAt } from "@/lib/host-status";
import { isQueryAccessError } from "@/lib/query-access-error";
import {
  DEFAULT_LIFETIME_MINUTES,
  hasStoredCopy,
  IntentKeys,
  isNotFound,
  isUnlimitedLeaseEnd,
  LEASE_DEFAULT_MS,
  type LeaseTerm,
  type LifetimeLimit,
  leaseView,
  lifetimeMs,
  offersRestoreOverride,
  renewalInput,
  restoreLoginWait,
  type SandboxProblem,
  sandboxActions,
  sandboxHostView,
  sandboxLabels,
  sandboxPhase,
  sandboxProblem,
  sandboxTitle,
} from "@/lib/sandbox-rules";
import { revisionLabel } from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";
import { RenameSandboxSheet } from "./rename-sandbox-sheet";
import { SandboxProcesses } from "./sandbox-processes";
import { SaveAsTemplateDialog } from "./save-as-template-dialog";

/**
 * One sandbox (C47): its server-reported state, host, template revision
 * (read through `getTemplate`, so an archived revision still shows), labels,
 * lifetime (requested versus host-acknowledged), latest lifecycle receipt,
 * lifecycle actions and file transfers. Every action is a request: the page
 * shows the server's answer and then whatever the next read reports — never
 * an assumed READY, STOPPED or DELETED. Another owner's sandbox is a plain
 * "not found" (the server's NOT_FOUND).
 */

type Action = "stop" | "startCold" | "restoreOverride" | "reconnectWarm" | "destroy" | "renew";

/** Problems after which the same request cannot succeed: the next click gets a new key. */
const DEFINITE: ReadonlySet<SandboxProblem> = new Set([
  "notFound",
  "stateChanged",
  "keyReused",
  "hostCapacity",
  "sizeInvalid",
  "diskBelowImage",
  "sizeUnsupported",
  "sizeMismatch",
  "hostUnavailable",
  "hostDraining",
  "restoreNoAllowedHost",
  "diskUnavailable",
  "hostDeleting",
  "templateMissing",
  "hostNoEgress",
  "egressGuardUnavailable",
  "openEgressNotPermitted",
  "labels",
  "invalid",
  "forbidden",
]);

function invalidateSandboxes(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
}

export function SandboxDetailPage({ lang, sandboxId }: { lang: string; sandboxId: string }) {
  const { t, i18n } = useTranslation(["sandboxes", "dashboard", "common", "hosts"]);
  const query = useQuery({
    ...orpc.sandboxes.getSandbox.queryOptions({ input: { id: sandboxId } }),
    refetchInterval: (current) =>
      current.state.data && isSandboxBusy(current.state.data)
        ? SANDBOX_BUSY_REFETCH_MS
        : SANDBOX_IDLE_REFETCH_MS,
    // A 404 is an answer (missing, or not yours); anything else is retried once.
    retry: (count, error) => !isNotFound(error) && count < 1,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const now = Date.now();
  useRerenderAt(nextHostStateChangeAt(query.data?.host ? [query.data.host] : [], now));

  const back = (
    <Link
      to="/$lang/dashboard/sandboxes"
      params={{ lang }}
      className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("sandboxes:detail.back")}
    </Link>
  );

  if (query.isPending)
    return (
      <section className="flex min-w-0 flex-col gap-6">
        {back}
        <SkeletonList count={3} className="rounded-xl border" />
      </section>
    );
  if (query.data === undefined || (query.isError && isQueryAccessError(query.error))) {
    return (
      <section className="flex min-w-0 flex-col gap-6">
        {back}
        {isNotFound(query.error) ? (
          <div role="status" data-sandbox-missing="">
            <EmptyState
              className="rounded-xl border px-4"
              title={t("sandboxes:detail.notFoundTitle")}
              description={t("sandboxes:detail.notFoundDescription")}
            />
          </div>
        ) : (
          <InlineRetry
            message={t("sandboxes:detail.loadFailed")}
            onRetry={() => void query.refetch()}
          />
        )}
      </section>
    );
  }
  return (
    <section className="flex min-w-0 max-w-full flex-col gap-6">
      {back}
      {query.isError && !isNotFound(query.error) ? (
        <InlineRetry
          message={t("sandboxes:detail.loadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : null}
      <SandboxDetail sandbox={query.data} lang={lang} locale={i18n.language} now={now} />
    </section>
  );
}

function SandboxDetail({
  sandbox,
  lang,
  locale,
  now,
}: {
  sandbox: SandboxView;
  lang: string;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["sandboxes", "hosts", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const restored = useSharingRestoration(sandbox.id, sandbox.accessGraceUntil);
  const intents = useRef(new IntentKeys());
  const [open, setOpen] = useState<Action | null>(null);
  const [problem, setProblem] = useState<SandboxProblem | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [renaming, setRenaming] = useState(false);
  // The destroy confirmation types the name shown when the dialog opened (F8):
  // a rename refetched while it is open never changes the token under the user.
  const [destroyToken, setDestroyToken] = useState(sandbox.name);
  const imagePolicy = useQuery({
    ...orpc.settings.imagePolicy.queryOptions(),
    staleTime: 60_000,
    meta: { skipGlobalErrorToast: true },
  });
  const canCapture =
    imagePolicy.data !== undefined &&
    imagePolicy.data.mode !== "off" &&
    (sandbox.state === "READY" || sandbox.state === "STOPPED");
  const limits = useQuery({
    ...orpc.sandboxes.getLimits.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  // This sandbox's own lease path (deployment, host, pool and membership),
  // read for display; the server re-checks it under its locks.
  const lifetimeLimit: LifetimeLimit = {
    maxTimeoutMs: sandbox.leaseLimit.finiteMaxMs,
    allowUnlimited: sandbox.leaseLimit.unlimited,
  };
  useTwoFactorRedirectOnError(lang, [limits.error]);
  const [minutes, setMinutes] = useState(String(DEFAULT_LIFETIME_MINUTES));
  const onExpire = sandbox.leaseExpireAction === "DESTROY" ? "destroy" : "stop";
  const actions = sandboxActions(sandbox.state, sandbox.lastLifecycleOperation);
  const hostView = sandboxHostView(sandbox.host, now);
  const labels = sandboxLabels(sandbox.metadata);
  const phase = sandboxPhase(sandbox.state);
  const waiting = sandbox.state === "WAITING_FOR_CAPACITY";
  // A start of an OFFLOADED sandbox restores its stored disk.
  const offloaded = sandbox.state === "OFFLOADED";
  const override = offersRestoreOverride(sandbox.state, problem, sandbox.lastLifecycleOperation);
  const loginWait = restoreLoginWait(sandbox.state, sandbox.lastLifecycleOperation);

  const handlers = (done: string) => ({
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => {
      intents.current.settle();
      setOpen(null);
      toast.success(done);
    },
    onError: (error: unknown) => {
      setOpen(null);
      if (redirect(error)) return;
      const next = sandboxProblem(error);
      setProblem(next);
      if (DEFINITE.has(next)) intents.current.settle();
    },
    onSettled: () => invalidateSandboxes(queryClient),
  });
  const stop = useMutation({
    ...orpc.sandboxes.stopSandbox.mutationOptions(),
    ...handlers(t("sandboxes:stop.done")),
  });
  const reconnect = useMutation({
    ...orpc.sandboxes.reconnectSandbox.mutationOptions(),
    ...handlers(t("sandboxes:reconnect.done")),
  });
  const start = useMutation({
    ...orpc.sandboxes.reconnectSandbox.mutationOptions(),
    ...handlers(t(offloaded ? "sandboxes:start.restoreDone" : "sandboxes:start.done")),
  });
  const destroy = useMutation({
    ...orpc.sandboxes.killSandbox.mutationOptions(),
    ...handlers(t("sandboxes:destroy.done")),
  });
  const renew = useMutation({
    ...orpc.sandboxes.setSandboxTimeout.mutationOptions(),
    ...handlers(t("sandboxes:renew.done")),
  });
  // Re-queue the cleanup of a failed restore.
  const retryCleanup = useMutation({
    ...orpc.sandboxes.retryCleanup.mutationOptions(),
    ...handlers(t("sandboxes:retryCleanup.done")),
  });
  const cleanupPending =
    sandbox.state === "ERROR" && sandbox.lastErrorCode === "restore_cleanup_pending";
  const pending =
    stop.isPending ||
    reconnect.isPending ||
    start.isPending ||
    destroy.isPending ||
    renew.isPending ||
    retryCleanup.isPending;
  // An intent is kept only while its outcome is uncertain (success and every
  // definite refusal settle it), so a retry must replay it even though the
  // refetch after a lost response shows the generation or lease revision that
  // request itself produced. Binding the key to those would mint a second
  // request instead. The sandbox ID stays in it: this component survives
  // navigation to another cached sandbox, and A's intent must never replay on B.
  const signature = (body: unknown) => JSON.stringify({ sandboxId: sandbox.id, body });
  // `0` is an explicit "no time limit"; never a fallback for an empty value.
  const timeoutMs = lifetimeMs(minutes, lifetimeLimit);
  const lifetimeValid = timeoutMs !== null;

  return (
    <>
      <PageHeader
        title={sandboxTitle(sandbox)}
        actions={
          <div
            role="group"
            aria-label={t("sandboxes:actionsLabel")}
            className="flex min-w-0 flex-wrap gap-2"
          >
            {actions.has("renew") ? (
              <Button
                type="button"
                size="touch"
                variant="ghost"
                disabled={pending}
                onClick={() => setOpen("renew")}
              >
                {t("sandboxes:renew.action")}
              </Button>
            ) : null}
            {actions.has("reconnectWarm") ? (
              <Button
                type="button"
                size="touch"
                variant="secondary"
                disabled={pending}
                onClick={() =>
                  reconnect.mutate(
                    intents.current.for("reconnect", signature("warm"), (idempotencyKey) => ({
                      id: sandbox.id,
                      mode: "warm" as const,
                      idempotencyKey,
                    })),
                  )
                }
              >
                {reconnect.isPending
                  ? t("sandboxes:reconnect.pending")
                  : t("sandboxes:reconnect.action")}
              </Button>
            ) : null}
            {actions.has("startCold") ? (
              <Button
                type="button"
                size="touch"
                disabled={pending}
                onClick={() => setOpen("startCold")}
              >
                {t(offloaded ? "sandboxes:start.restoreAction" : "sandboxes:start.action")}
              </Button>
            ) : null}
            {override ? (
              <Button
                type="button"
                size="touch"
                variant="secondary"
                data-restore-override=""
                disabled={pending}
                onClick={() => setOpen("restoreOverride")}
              >
                {t("sandboxes:restoreOverride.action")}
              </Button>
            ) : null}
            {actions.has("stop") ? (
              <Button
                type="button"
                size="touch"
                variant="secondary"
                disabled={pending}
                onClick={() => setOpen("stop")}
              >
                {t("sandboxes:stop.action")}
              </Button>
            ) : null}
            {sandbox.state !== "DELETED" ? (
              <Button
                type="button"
                size="touch"
                variant="ghost"
                data-sandbox-rename=""
                onClick={() => setRenaming(true)}
              >
                {t("sandboxes:rename.action")}
              </Button>
            ) : null}
            {canCapture ? (
              <Button
                type="button"
                size="touch"
                variant="secondary"
                disabled={pending}
                onClick={() => setCapturing(true)}
              >
                {t("sandboxes:capture.action")}
              </Button>
            ) : null}
            {actions.has("destroy") ? (
              <Button
                type="button"
                size="touch"
                variant="destructive"
                disabled={pending}
                onClick={() => {
                  setDestroyToken(sandbox.name);
                  setOpen("destroy");
                }}
              >
                <Trash2 aria-hidden="true" className="size-4" />
                {t(waiting ? "sandboxes:destroy.waitingAction" : "sandboxes:destroy.action")}
              </Button>
            ) : null}
          </div>
        }
      />
      {renaming ? (
        <RenameSandboxSheet lang={lang} sandbox={sandbox} onClose={() => setRenaming(false)} />
      ) : null}
      {capturing ? (
        <SaveAsTemplateDialog sandbox={sandbox} lang={lang} onClose={() => setCapturing(false)} />
      ) : null}
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <StatePill state={sandbox.state} />
        <DiskLocationBadge disk={sandbox.disk} />
        {phase === "ready" ? null : (
          <p className="text-sm text-muted-foreground">{t(`sandboxes:stateHint.${phase}`)}</p>
        )}
      </div>
      {sandbox.capacityWait ? <CapacityWaitLine wait={sandbox.capacityWait} lang={lang} /> : null}
      {hostView === "offline" && sandbox.host && sandbox.state !== "DELETED" ? (
        <p
          role="status"
          data-host-offline=""
          className="rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
        >
          {translateText(t, "sandboxes:hostOffline", {
            host: sandbox.host.label,
            state: t(`hosts:status.${hostConnectionState(sandbox.host, now)}`),
          })}
        </p>
      ) : null}
      {sandbox.host?.quarantinedAt && sandbox.state !== "DELETED" ? (
        <p
          role="status"
          data-host-quarantined=""
          className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
        >
          {t("sandboxes:hostQuarantined", { host: sandbox.host.label })}
        </p>
      ) : null}
      {problem ? (
        <p role="alert" data-action-problem={problem} className="text-sm text-destructive">
          {t(`sandboxes:problem.${problem}`)}
        </p>
      ) : null}
      {override ? (
        <p data-restore-override-hint="" className="text-sm text-muted-foreground">
          {t("sandboxes:restoreOverride.hint")}
        </p>
      ) : null}
      {loginWait ? (
        <div
          role="status"
          data-restore-login-wait={loginWait}
          className="flex min-w-0 flex-wrap items-center gap-x-3 rounded-md border border-amber-600/40 bg-amber-600/10 px-3 py-1 text-sm text-amber-800 dark:text-amber-300"
        >
          <p className="min-w-0 py-2">{t(`sandboxes:restoreLoginWait.${loginWait}`)}</p>
          <Link
            to="/$lang/settings/logins"
            params={{ lang }}
            className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
          >
            {t("sandboxes:restoreLoginWait.logins")}
          </Link>
        </div>
      ) : null}

      <Card title={t("sandboxes:receipt.title")} id="sandbox-receipt">
        <ReceiptLine receipt={sandbox.lastLifecycleOperation} locale={locale} now={now} />
        <Link
          to="/$lang/dashboard/operations"
          params={{ lang }}
          search={{ sandboxId: sandbox.id }}
          data-sandbox-operations={sandbox.id}
          className="inline-flex min-h-11 items-center text-sm underline-offset-4 hover:underline"
        >
          {t("sandboxes:detail.operations")}
        </Link>
      </Card>

      {restored ? (
        <p role="status" data-access-restored="">
          {t("sandboxes:sharing.restored")}
        </p>
      ) : null}
      {sandbox.accessGraceUntil ? (
        <p role="alert" data-access-grace="">
          {t("sandboxes:sharing.loss", {
            date: formatDateTime(sandbox.accessGraceUntil, locale),
          })}
        </p>
      ) : null}
      {sandbox.originPoolId ? (
        <p data-accepted-grace="">
          {t("sandboxes:sharing.accepted", {
            duration: formatGraceDuration(sandbox.acceptedGraceSeconds, locale),
          })}
        </p>
      ) : null}
      <Card title={t("sandboxes:fields.state")} id="sandbox-overview">
        <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
          <Field label={t("sandboxes:fields.host")}>
            <span data-sandbox-host="">
              <HostText host={sandbox.host} now={now} waiting={waiting} />
            </span>
          </Field>
          <Field label={t("sandboxes:fields.allocation")}>
            <span data-sandbox-allocation="" className="tabular-nums">
              {t("sandboxes:allocation", {
                cpuCount: sandbox.cpuCount,
                memoryMiB: sandbox.memoryMiB,
                diskGiB: sandbox.diskGiB,
              })}
            </span>
          </Field>
          <Field label={t("sandboxes:fields.storage")}>
            <span data-sandbox-storage="">
              {sandbox.storagePoolName ?? t("sandboxes:storageUnknown")}
            </span>
          </Field>
          <Field label={t("sandboxes:detail.templateVersion")}>
            <span data-revision-label="">
              <Link
                to="/$lang/dashboard/templates"
                params={{ lang }}
                className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
              >
                {revisionLabel(sandbox.template)}
              </Link>
            </span>
          </Field>
          <Field label={t("sandboxes:detail.placement")}>
            <span data-placement="">
              {sandbox.originPoolId
                ? sandbox.placementPoolLabel
                  ? t("sandboxes:detail.placementPool", { label: sandbox.placementPoolLabel })
                  : t("sandboxes:detail.placementSharedPool")
                : sandbox.host
                  ? t("sandboxes:detail.placementHost", { label: sandbox.host.label })
                  : t("sandboxes:detail.placementHostUnknown")}
            </span>
          </Field>
          <Field label={t("sandboxes:fields.created")}>
            <span title={dateTimeTitle(sandbox.createdAt, locale)}>
              {formatRelativeTime(new Date(sandbox.createdAt).getTime(), locale, now)}
            </span>
          </Field>
          <Field label={t("sandboxes:fields.labels")} wide>
            {labels.length === 0 ? (
              <span className="text-muted-foreground">{t("sandboxes:fields.noLabels")}</span>
            ) : (
              <ul className="flex flex-wrap gap-1">
                {labels.map(([key, value]) => (
                  <li
                    key={key}
                    className="max-w-full truncate rounded border bg-muted/50 px-1.5 py-0.5 font-mono text-xs"
                  >
                    {key}={value}
                  </li>
                ))}
              </ul>
            )}
          </Field>
          {sandbox.lastErrorCode ? (
            <Field label={t("sandboxes:fields.error")}>
              <span className="font-mono text-xs">{sandbox.lastErrorCode}</span>
              {sandbox.lastErrorCode === "host_effect_not_issued" && sandbox.state === "ERROR" ? (
                <span data-effect-not-issued="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:lifetime.hostEffectNotIssued")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "host_effect_not_issued" && sandbox.state === "STOPPED" ? (
                <span data-start-not-issued="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:lifetime.startNotIssued")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "host_disconnect_expired" ? (
                <span
                  data-host-disconnect-expired=""
                  className="block text-xs text-muted-foreground"
                >
                  {t("sandboxes:lifetime.hostDisconnectExpired")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "open_egress_not_permitted" ? (
                <span data-egress-revoked="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:egress.revoked")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "guest_sudo_not_permitted" ? (
                <span data-guest-sudo-revoked="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:guestRoot.revoked")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "egress_guard_unavailable" ? (
                <span
                  data-egress-guard-unavailable=""
                  className="block text-xs text-muted-foreground"
                >
                  {t("sandboxes:egress.guardUnavailable")}
                </span>
              ) : null}
              {sandbox.lastErrorCode === "instance_missing" ? (
                <span data-instance-missing="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:lifetime.instanceMissing")}
                </span>
              ) : null}
              {cleanupPending ? (
                <Button
                  type="button"
                  size="touch"
                  variant="secondary"
                  data-retry-cleanup=""
                  className="mt-2"
                  disabled={pending}
                  onClick={() => retryCleanup.mutate({ id: sandbox.id })}
                >
                  {t("sandboxes:retryCleanup.action")}
                </Button>
              ) : null}
              {sandbox.lastErrorCode === "expiry_failed" ? (
                <span data-expiry-failed="" className="block text-xs text-muted-foreground">
                  {t("sandboxes:lifetime.expiryFailed", {
                    reason: sandbox.expiryFailureReason ?? "",
                  })}
                </span>
              ) : null}
            </Field>
          ) : null}
        </dl>
        <AdvancedDetails>
          <IdRow label={t("sandboxes:detail.sandboxId")} value={sandbox.id} />
          <IdRow label={t("sandboxes:detail.revisionId")} value={sandbox.templateRevisionId} />
          {sandbox.originPoolId ? (
            <IdRow label={t("sandboxes:detail.poolId")} value={sandbox.originPoolId} />
          ) : null}
          {sandbox.storagePoolId ? (
            <IdRow label={t("sandboxes:detail.storageId")} value={sandbox.storagePoolId} />
          ) : null}
        </AdvancedDetails>
      </Card>

      <DiskCard
        sandboxId={sandbox.id}
        disk={sandbox.disk}
        lang={lang}
        locale={locale}
        editable={sandbox.state !== "DELETED"}
      />

      <TemplateCard template={sandbox.template} lang={lang} />

      <EgressCard sandbox={sandbox} waiting={waiting} />

      <GuestRootCard sandbox={sandbox} waiting={waiting} />

      <LifetimeCard sandbox={sandbox} locale={locale} now={now} />

      {sandbox.state === "DELETED" ? null : (
        <SandboxCredentials
          key={`credentials-${sandbox.id}`}
          lang={lang}
          sandboxId={sandbox.id}
          sandboxState={sandbox.state}
        />
      )}

      {sandbox.state === "DELETED" ? null : (
        // Keyed: this component survives navigation to another cached
        // sandbox, and A's terminal must never stay attached on B's page.
        <SandboxTerminal
          key={sandbox.id}
          sandboxId={sandbox.id}
          lang={lang}
          available={sandbox.state === "READY"}
        />
      )}

      {sandbox.state === "DELETED" ? null : <SandboxConnectHint target={sandbox.name} />}

      {/* Kept after the sandbox is destroyed: the audit outlives it. */}
      <SandboxConnections key={`connections-${sandbox.id}`} lang={lang} sandboxId={sandbox.id} />

      {actions.has("files") ? (
        <SandboxFiles sandboxId={sandbox.id} lang={lang} />
      ) : sandbox.state !== "DELETED" ? (
        <p className="text-sm text-muted-foreground">{t("sandboxes:files.unavailable")}</p>
      ) : null}

      {actions.has("files") ? (
        <SandboxProcesses
          key={`processes-${sandbox.id}`}
          sandboxId={sandbox.id}
          available={actions.has("files")}
        />
      ) : null}

      <AlertDialog open={open === "stop"} onOpenChange={(next) => setOpen(next ? "stop" : null)}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>{t("sandboxes:stop.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                ["REQUESTED", "SCHEDULED", "PROVISIONING"].includes(sandbox.state)
                  ? "sandboxes:stop.bootDescription"
                  : "sandboxes:stop.description",
              )}
            </AlertDialogDescription>
            {sandbox.disk && sandbox.disk.eligibility !== "never" ? (
              <p data-stop-offload-policy="" className="text-sm text-muted-foreground">
                {t("sandboxes:stop.offloadPolicy")}{" "}
                <OffloadPolicyText policy={sandbox.disk.offloadPolicy} />
              </p>
            ) : null}
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              disabled={stop.isPending}
              onClick={() =>
                stop.mutate(
                  intents.current.for("stop", signature("stop"), (idempotencyKey) => ({
                    id: sandbox.id,
                    idempotencyKey,
                  })),
                )
              }
            >
              {stop.isPending ? t("sandboxes:stop.pending") : t("sandboxes:stop.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog
        open={open === "startCold"}
        onOpenChange={(next) => setOpen(next ? "startCold" : null)}
      >
        <DialogContent
          closeLabel={t("common:actions.close")}
          className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-md"
        >
          <DialogHeader>
            <DialogTitle>
              {t(offloaded ? "sandboxes:start.restoreTitle" : "sandboxes:start.title")}
            </DialogTitle>
            <DialogDescription>
              {t(offloaded ? "sandboxes:start.restoreDescription" : "sandboxes:start.description")}
            </DialogDescription>
          </DialogHeader>
          {limits.isError ? (
            <InlineRetry
              message={t("sandboxes:lifetime.limitsFailed")}
              onRetry={() => void limits.refetch()}
            />
          ) : null}
          <LifetimeFields
            maxTimeoutMs={lifetimeLimit.maxTimeoutMs}
            allowUnlimited={lifetimeLimit.allowUnlimited}
            minutes={minutes}
            onMinutes={setMinutes}
            onExpire={onExpire}
            disabled={start.isPending}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              disabled={start.isPending || (!lifetimeValid && problem !== "generic")}
              onClick={() =>
                start.mutate(
                  intents.current.for(
                    "start",
                    signature({ minutes, onExpire }),
                    (idempotencyKey) => ({
                      id: sandbox.id,
                      mode: "cold" as const,
                      timeoutMs: timeoutMs ?? LEASE_DEFAULT_MS,
                      idempotencyKey,
                    }),
                  ),
                )
              }
            >
              {start.isPending
                ? t(offloaded ? "sandboxes:start.restorePending" : "sandboxes:start.pending")
                : t(offloaded ? "sandboxes:start.restoreConfirm" : "sandboxes:start.confirm")}
            </Button>
            <Button type="button" variant="outline" size="touch" onClick={() => setOpen(null)}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={open === "restoreOverride"}
        onOpenChange={(next) => setOpen(next ? "restoreOverride" : null)}
      >
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>{t("sandboxes:restoreOverride.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("sandboxes:restoreOverride.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              data-restore-override-confirm=""
              className="min-h-[44px] w-full sm:w-auto"
              disabled={start.isPending}
              onClick={() =>
                start.mutate(
                  intents.current.for(
                    "restoreOverride",
                    signature({ minutes, onExpire, override: true }),
                    (idempotencyKey) => ({
                      id: sandbox.id,
                      mode: "cold" as const,
                      timeoutMs: timeoutMs ?? LEASE_DEFAULT_MS,
                      overrideCreatorAllowlist: true,
                      idempotencyKey,
                    }),
                  ),
                )
              }
            >
              {start.isPending
                ? t("sandboxes:restoreOverride.pending")
                : t("sandboxes:restoreOverride.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog open={open === "renew"} onOpenChange={(next) => setOpen(next ? "renew" : null)}>
        <DialogContent
          closeLabel={t("common:actions.close")}
          className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-md"
        >
          <DialogHeader>
            <DialogTitle>{t("sandboxes:renew.title")}</DialogTitle>
            <DialogDescription>{t("sandboxes:renew.description")}</DialogDescription>
          </DialogHeader>
          {limits.isError ? (
            <InlineRetry
              message={t("sandboxes:lifetime.limitsFailed")}
              onRetry={() => void limits.refetch()}
            />
          ) : null}
          <LifetimeFields
            maxTimeoutMs={lifetimeLimit.maxTimeoutMs}
            allowUnlimited={lifetimeLimit.allowUnlimited}
            minutes={minutes}
            onMinutes={setMinutes}
            onExpire={onExpire}
            disabled={renew.isPending}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              disabled={renew.isPending || (!lifetimeValid && problem !== "generic")}
              onClick={() =>
                renew.mutate(
                  intents.current.for("renew", signature({ minutes, onExpire }), (idempotencyKey) =>
                    renewalInput(sandbox.id, minutes, idempotencyKey, lifetimeLimit),
                  ),
                )
              }
            >
              {renew.isPending ? t("sandboxes:renew.pending") : t("sandboxes:renew.submit")}
            </Button>
            <Button type="button" variant="outline" size="touch" onClick={() => setOpen(null)}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <ConfirmDeleteDialog
        open={open === "destroy"}
        onOpenChange={(next) => setOpen(next ? "destroy" : null)}
        title={t(waiting ? "sandboxes:destroy.waitingTitle" : "sandboxes:destroy.title")}
        description={
          <>
            {t(
              waiting
                ? "sandboxes:destroy.waitingDescription"
                : sandbox.state === "STOPPING"
                  ? "sandboxes:destroy.recoveryDescription"
                  : "sandboxes:destroy.description",
            )}
            {hasStoredCopy(sandbox.disk) ? (
              <span data-destroy-stored-copy="" className="mt-2 block">
                {t("sandboxes:destroy.storedCopy")}
              </span>
            ) : null}
          </>
        }
        confirmToken={destroyToken}
        typePrompt={t("sandboxes:destroy.prompt")}
        copyAriaLabel={t("sandboxes:destroy.copy")}
        confirmLabel={t(waiting ? "sandboxes:destroy.waitingConfirm" : "sandboxes:destroy.confirm")}
        pendingLabel={t("sandboxes:destroy.pending")}
        isPending={destroy.isPending}
        onConfirm={() =>
          destroy.mutate(
            intents.current.for(
              "destroy",
              signature({
                action: "destroy",
                recoveryOperationId:
                  sandbox.state === "STOPPING" ? sandbox.lastLifecycleOperation?.id : null,
              }),
              (idempotencyKey) => ({ id: sandbox.id, idempotencyKey }),
            ),
          )
        }
      />
    </>
  );
}

function Card({ title, id, children }: { title: string; id: string; children: ReactNode }) {
  return (
    <section
      aria-labelledby={id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id={id} className="font-heading text-sm font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** One labelled list of egress grants (CIDRs or domains). */
function GrantList({ title, items, kind }: { title: string; items: string[]; kind: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">{title}</h3>
      <ul className="flex flex-wrap gap-1">
        {items.map((item) => (
          <li
            key={item}
            {...{ [`data-egress-${kind}`]: item }}
            className="max-w-full truncate rounded border bg-muted/50 px-1.5 py-0.5 font-mono text-xs"
          >
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The sandbox's egress, fixed at placement: the EFFECTIVE mode (open, or an
 * allowlist of static CIDR rules and requested domain names), why an open
 * request became an allowlist, and grants the node's blocklist refused.
 * Domain grants are host-resolved and time-limited, so the names are
 * labelled as requested, not as live grant state (SEED-4 / D-6). An
 * allowlist with no grants is deny-all (also the read-back while a create
 * waits for placement, so a waiting sandbox shows its request instead).
 */
function EgressCard({
  sandbox,
  waiting,
}: {
  sandbox: Pick<
    SandboxView,
    "egress" | "egressRequest" | "egressModeReason" | "egressDeniedGrants"
  >;
  waiting: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const pending = waiting && sandbox.egressRequest != null;
  const policy = pending && sandbox.egressRequest ? sandbox.egressRequest : sandbox.egress;
  const open = policy.mode === "open";
  const empty = policy.domains.length === 0 && policy.cidrs.length === 0;
  const fallback =
    open && !pending && sandbox.egressRequest?.mode === "open" ? sandbox.egressRequest : null;
  return (
    <Card title={t("sandboxes:egress.title")} id="sandbox-egress">
      <div
        data-sandbox-egress={open ? "open" : empty ? "deny-all" : "allowlist"}
        className="flex min-w-0 flex-col gap-3 text-sm"
      >
        <div className="flex flex-wrap items-center gap-2">
          <span
            data-egress-mode={policy.mode}
            className={cn(
              "inline-flex min-h-6 items-center rounded-full border px-2 text-xs font-medium",
              open
                ? "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400"
                : "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
            )}
          >
            {t(`sandboxes:egress.mode.${policy.mode}`)}
          </span>
          {pending ? (
            <span data-egress-pending="" className="text-xs text-muted-foreground">
              {t("sandboxes:egress.pending")}
            </span>
          ) : null}
        </div>
        {sandbox.egressModeReason ? (
          <p data-egress-reason={sandbox.egressModeReason} className="text-sm">
            {t(`sandboxes:egress.reason.${sandbox.egressModeReason}`)}
          </p>
        ) : null}
        {open ? (
          <p className="text-muted-foreground">{t("sandboxes:egress.openHint")}</p>
        ) : empty ? (
          <p className="text-muted-foreground">{t("sandboxes:egress.denyAll")}</p>
        ) : null}
        {open ? null : (
          <>
            {policy.cidrs.length > 0 ? (
              <GrantList title={t("sandboxes:egress.cidrs")} items={policy.cidrs} kind="cidr" />
            ) : null}
            {policy.domains.length > 0 ? (
              <div className="flex min-w-0 flex-col gap-1">
                <GrantList
                  title={t("sandboxes:egress.domains")}
                  items={policy.domains}
                  kind="domain"
                />
                <p className="text-xs text-muted-foreground">{t("sandboxes:egress.domainsHint")}</p>
                <p className="text-xs text-muted-foreground" data-egress-domains-lapse="">
                  {t("sandboxes:egress.domainsLapse")}
                </p>
              </div>
            ) : null}
          </>
        )}
        {fallback && (fallback.domains.length > 0 || fallback.cidrs.length > 0) ? (
          <div data-egress-fallback="" className="flex min-w-0 flex-col gap-2">
            {fallback.cidrs.length > 0 ? (
              <GrantList
                title={t("sandboxes:egress.fallbackCidrs")}
                items={fallback.cidrs}
                kind="fallback-cidr"
              />
            ) : null}
            {fallback.domains.length > 0 ? (
              <GrantList
                title={t("sandboxes:egress.fallbackDomains")}
                items={fallback.domains}
                kind="fallback-domain"
              />
            ) : null}
            <p className="text-xs text-muted-foreground">{t("sandboxes:egress.fallbackHint")}</p>
          </div>
        ) : null}
        {sandbox.egressDeniedGrants.length > 0 ? (
          <div data-egress-denied="" className="flex min-w-0 flex-col gap-1">
            <GrantList
              title={t("sandboxes:egress.denied")}
              items={sandbox.egressDeniedGrants}
              kind="denied"
            />
            <p className="text-xs text-muted-foreground">{t("sandboxes:egress.deniedHint")}</p>
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">{t("sandboxes:egress.immutable")}</p>
      </div>
    </Card>
  );
}

/**
 * Root in the guest: the effective `guestSudo` (fixed at placement), why a
 * request was not honoured, and whether the guest may run as root at all
 * (`guestRoot`: sudo, or a revision built with root or captured with guest
 * root). Command results of such a sandbox are reported by the guest itself.
 */
function GuestRootCard({
  sandbox,
  waiting,
}: {
  sandbox: Pick<SandboxView, "guestSudo" | "guestSudoRequested" | "guestSudoReason" | "guestRoot">;
  waiting: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <Card title={t("sandboxes:guestRoot.title")} id="sandbox-guest-root">
      <div
        data-sandbox-guest-sudo={waiting ? "pending" : sandbox.guestSudo ? "on" : "off"}
        className="flex min-w-0 flex-col gap-3 text-sm"
      >
        <div className="flex flex-wrap items-center gap-2">
          <span
            data-guest-sudo-state=""
            className={cn(
              "inline-flex min-h-6 items-center rounded-full border px-2 text-xs font-medium",
              sandbox.guestSudo
                ? "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400"
                : "border-border text-muted-foreground",
            )}
          >
            {t(
              waiting
                ? "sandboxes:guestRoot.pending"
                : sandbox.guestSudo
                  ? "sandboxes:guestRoot.sudoOn"
                  : "sandboxes:guestRoot.sudoOff",
            )}
          </span>
          {sandbox.guestRoot ? (
            <span
              data-guest-root=""
              className="inline-flex min-h-6 items-center rounded-full border border-amber-600/40 bg-amber-600/10 px-2 text-xs font-medium text-amber-700 dark:text-amber-400"
            >
              {t("sandboxes:guestRoot.mayRunAsRoot")}
            </span>
          ) : null}
        </div>
        {sandbox.guestSudoReason ? (
          <p data-guest-sudo-reason={sandbox.guestSudoReason}>
            {t(`sandboxes:guestRoot.reason.${sandbox.guestSudoReason}`)}
          </p>
        ) : null}
        {sandbox.guestRoot ? (
          <p className="text-xs text-muted-foreground" data-guest-root-hint="">
            {t("sandboxes:guestRoot.attested")}
          </p>
        ) : null}
        <p className="text-xs text-muted-foreground">{t("sandboxes:guestRoot.identity")}</p>
      </div>
    </Card>
  );
}

function Field({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? "min-w-0 sm:col-span-2" : "min-w-0"}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** The revision the sandbox started from, read through the session-only `getTemplate`. */
function TemplateCard({ template, lang }: { template: SandboxView["template"]; lang: string }) {
  const { t } = useTranslation(["sandboxes"]);
  const query = useQuery({
    ...orpc.sandboxTemplates.getTemplateRevision.queryOptions({
      input: { id: template.revisionId },
    }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <Card title={t("sandboxes:fields.template")} id="sandbox-template">
      <p data-sandbox-template="" className="text-sm font-medium">
        <Link
          to="/$lang/dashboard/templates"
          params={{ lang }}
          className="inline-flex min-h-11 items-center underline underline-offset-4"
        >
          <TemplateText template={template} />
        </Link>
      </p>
      {query.isError ? (
        <InlineRetry
          message={t("sandboxes:detail.templateLoadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : query.data ? (
        <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
          <Field label={t("sandboxes:detail.architecture")}>
            <span className="font-mono text-xs">{query.data.architecture}</span>
          </Field>
          <Field label={t("sandboxes:detail.guest")}>
            <span className="break-all font-mono text-xs">
              {translateText(t, "sandboxes:detail.guestIdentity", {
                uid: query.data.guestUid,
                gid: query.data.guestGid,
                home: query.data.guestHome,
                shell: query.data.guestShell,
              })}
            </span>
          </Field>
        </dl>
      ) : null}
      {query.data ? (
        <AdvancedDetails>
          <div data-fingerprint="">
            <IdRow label={t("sandboxes:detail.fingerprint")} value={query.data.incusFingerprint} />
          </div>
        </AdvancedDetails>
      ) : query.isError ? null : (
        <SkeletonList count={1} className="rounded-xl border" />
      )}
    </Card>
  );
}

function LifetimeCard({
  sandbox,
  locale,
  now,
}: {
  sandbox: SandboxView;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const lease = leaseView(sandbox);
  const describe = (term: LeaseTerm | null) =>
    term == null
      ? t("sandboxes:expiry.none")
      : term.unlimited || isUnlimitedLeaseEnd(term.expiresAt)
        ? t("sandboxes:expiry.unlimited")
        : t("sandboxes:expiry.at", {
            when: formatRelativeTime(term.expiresAt, locale, now),
            action: t(`sandboxes:expiry.action.${term.onExpire}`),
          });
  const termTitle = (term: LeaseTerm | null) =>
    term == null || term.unlimited || isUnlimitedLeaseEnd(term.expiresAt)
      ? undefined
      : dateTimeTitle(term.expiresAt, locale);
  const deadline = sandbox.leaseExpiresAt ? new Date(sandbox.leaseExpiresAt).getTime() : null;
  // A lease from READY: until the host reports READY the stored deadline is
  // only the provisioning backstop (timeout plus the provision maximum), not
  // the requested lifetime, so name the pending start instead of that time.
  const startsAtReady = sandbox.leasePendingReady === true;
  const hostExpiry =
    sandbox.hostExpiryConfirmedAt == null || sandbox.hostExpiryAction == null ? null : (
      <Field label={t("sandboxes:lifetime.hostEnforced")} wide>
        <span
          data-host-expiry={sandbox.hostExpiryRevision ?? ""}
          title={dateTimeTitle(sandbox.hostExpiryConfirmedAt, locale)}
        >
          {t(
            sandbox.hostExpiryAction === "DESTROY"
              ? "sandboxes:lifetime.hostExpiry.deleted"
              : "sandboxes:lifetime.hostExpiry.stopped",
            {
              when: formatRelativeTime(
                new Date(sandbox.hostExpiryConfirmedAt).getTime(),
                locale,
                now,
              ),
              revision: sandbox.hostExpiryRevision,
            },
          )}
        </span>
      </Field>
    );
  if (sandbox.state === "WAITING_FOR_CAPACITY")
    return (
      <Card title={t("sandboxes:lifetime.title")} id="sandbox-lifetime">
        <p data-lease-waiting="" className="text-sm text-muted-foreground">
          {t("sandboxes:lifetime.waiting")}
        </p>
      </Card>
    );
  if (sandbox.state === "DELETED")
    return hostExpiry ? (
      <Card title={t("sandboxes:lifetime.title")} id="sandbox-lifetime">
        <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">{hostExpiry}</dl>
      </Card>
    ) : null;
  return (
    <Card title={t("sandboxes:lifetime.title")} id="sandbox-lifetime">
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        {hostExpiry}
        <Field label={t("sandboxes:lifetime.deadline")}>
          <span
            data-lease-deadline=""
            title={
              startsAtReady || deadline == null
                ? undefined
                : termTitle({ expiresAt: deadline, onExpire: "stop" })
            }
          >
            {startsAtReady
              ? t("sandboxes:lifetime.startsAtReady")
              : describe(
                  deadline == null
                    ? null
                    : {
                        expiresAt: deadline,
                        onExpire: sandbox.leaseExpireAction === "DESTROY" ? "destroy" : "stop",
                      },
                )}
          </span>
        </Field>
        <Field label={t("sandboxes:lifetime.requested")}>
          <span
            data-lease-requested=""
            title={startsAtReady ? undefined : termTitle(lease.requested)}
          >
            {startsAtReady ? t("sandboxes:lifetime.startsAtReady") : describe(lease.requested)}
          </span>
          <span className="block text-xs text-muted-foreground">
            {t("sandboxes:lifetime.revision", { revision: lease.revision })}
          </span>
        </Field>
        <Field label={t("sandboxes:lifetime.effective")} wide>
          <span
            data-lease-effective=""
            data-lease-ack={lease.ack}
            title={termTitle(lease.effective)}
          >
            {lease.effective == null
              ? t("sandboxes:lifetime.notAcknowledged")
              : describe(lease.effective)}
          </span>
          <span className="block text-xs text-muted-foreground">
            {t(`sandboxes:lifetime.ack.${lease.ack}`)}
          </span>
        </Field>
      </dl>
    </Card>
  );
}

/** A labelled opaque ID inside Advanced: short form, full value on copy. */
function IdRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <CopyableId value={value} label={label} />
    </div>
  );
}
