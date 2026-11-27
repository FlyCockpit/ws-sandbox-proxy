import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { ArrowLeft, SquareTerminal, Trash2 } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { type OverflowAction, PageActions } from "@/components/page-actions";
import { PageHeader } from "@/components/page-shell";
import { SandboxConnectHint, SandboxConnections } from "@/components/sandboxes/sandbox-connections";
import { SandboxCredentials } from "@/components/sandboxes/sandbox-credentials";
import {
  Card,
  EgressCard,
  Field,
  GuestRootCard,
  IdRow,
  LifetimeCard,
  TemplateCard,
  UsageCard,
} from "@/components/sandboxes/sandbox-detail-cards";
import { DiskCard } from "@/components/sandboxes/sandbox-disk";
import { SandboxFiles } from "@/components/sandboxes/sandbox-files";
import {
  type SandboxLifecycle,
  SandboxLifecycleDialogs,
  useSandboxLifecycle,
} from "@/components/sandboxes/sandbox-lifecycle";
import {
  CapacityWaitLine,
  HostText,
  ReceiptLine,
  type SandboxView,
} from "@/components/sandboxes/sandbox-parts";
import { SandboxPorts } from "@/components/sandboxes/sandbox-ports";
import {
  SANDBOX_SECTIONS,
  SandboxPageIndex,
  SandboxSectionBlock,
  SandboxSummary,
  sectionId,
} from "@/components/sandboxes/sandbox-summary";
import { SandboxTerminal } from "@/components/sandboxes/sandbox-terminal";
import {
  isSandboxBusy,
  SANDBOX_BUSY_REFETCH_MS,
  SANDBOX_IDLE_REFETCH_MS,
} from "@/components/sandboxes/sandboxes-page";
import { SkeletonList } from "@/components/skeleton-list";
import type { TerminalPanelHandle } from "@/components/terminal-panel";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useSharingRestoration } from "@/hooks/use-sharing-restoration";
import { useStatusClock } from "@/hooks/use-status-clock";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { dateTimeTitle, formatDateTime } from "@/lib/format-date-time";
import { formatGraceDuration } from "@/lib/format-duration";
import { hostConnectionState, nextHostStateChangeAt } from "@/lib/host-status";
import { isQueryAccessError } from "@/lib/query-access-error";
import {
  isNotFound,
  offersRestoreOverride,
  restoreLoginWait,
  sandboxActions,
  sandboxHostView,
  sandboxLabels,
  sandboxTitle,
} from "@/lib/sandbox-rules";
import { sandboxDisplayOverride } from "@/lib/sandbox-status";
import { revisionLabel } from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";
import { RenameSandboxSheet } from "./rename-sandbox-sheet";
import { SandboxProcesses } from "./sandbox-processes";
import { SaveAsTemplateDialog } from "./save-as-template-dialog";

/**
 * One sandbox (C47, design review #7): a header summary (state, step
 * progress, lifetime with Renew) with one primary action (Open terminal, or
 * Start when stopped), the rest in "More actions"; then an "On this page"
 * index over Overview, Terminal, Ports & previews, Files, Configuration and
 * Activity. Every action is a request: the page shows the server's answer and
 * then whatever the next read reports, never an assumed READY, STOPPED or
 * DELETED. Another owner's sandbox is a plain "not found" (the server's
 * NOT_FOUND).
 */

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
  const now = useStatusClock(query.dataUpdatedAt);
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
  const restored = useSharingRestoration(sandbox.id, sandbox.accessGraceUntil);
  const lifecycle = useSandboxLifecycle(sandbox, lang);
  const { setOpen, problem, pending } = lifecycle;
  const terminalRef = useRef<TerminalPanelHandle>(null);
  const [capturing, setCapturing] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const imagePolicy = useQuery({
    ...orpc.settings.imagePolicy.queryOptions(),
    staleTime: 60_000,
    meta: { skipGlobalErrorToast: true },
  });
  const canCapture =
    imagePolicy.data !== undefined &&
    imagePolicy.data.mode !== "off" &&
    (sandbox.state === "READY" || sandbox.state === "STOPPED");
  const actions = sandboxActions(sandbox.state, sandbox.lastLifecycleOperation);
  const display = sandboxDisplayOverride(sandbox);
  // The template card's query (shared cache): the guest's home, where terminal photos go.
  const guestHome = useQuery({
    ...orpc.sandboxTemplates.getTemplateRevision.queryOptions({
      input: { id: sandbox.template.revisionId },
    }),
    meta: { skipGlobalErrorToast: true },
  }).data?.guestHome;
  const hostView = sandboxHostView(sandbox.host, now);
  const waiting = sandbox.state === "WAITING_FOR_CAPACITY";
  const deleted = sandbox.state === "DELETED";
  // A start of an OFFLOADED sandbox restores its stored disk.
  const offloaded = sandbox.state === "OFFLOADED";
  const override = offersRestoreOverride(sandbox.state, problem, sandbox.lastLifecycleOperation);
  const loginWait = restoreLoginWait(sandbox.state, sandbox.lastLifecycleOperation);
  // A start already in flight is "Starting": offering Start again would only replay it.
  const startOffered = actions.has("startCold") && display === null;
  const sections = SANDBOX_SECTIONS.filter(
    (section) =>
      !deleted || section === "overview" || section === "configuration" || section === "activity",
  );

  const primary = deleted ? null : startOffered ? (
    <Button
      type="button"
      size="touch"
      data-primary-action="start"
      disabled={pending}
      onClick={() => setOpen("startCold")}
    >
      {t(offloaded ? "sandboxes:start.restoreAction" : "sandboxes:start.action")}
    </Button>
  ) : (
    <a
      href={`#${sectionId("terminal")}`}
      data-primary-action="terminal"
      onClick={(event) => {
        if (
          event.button === 0 &&
          !event.metaKey &&
          !event.ctrlKey &&
          !event.shiftKey &&
          !event.altKey
        ) {
          terminalRef.current?.attach();
        }
      }}
      className={buttonVariants({ size: "touch" })}
    >
      <SquareTerminal aria-hidden="true" className="size-4" />
      {t("sandboxes:openTerminal")}
    </a>
  );
  const stopButton = (
    <Button
      type="button"
      size="touch"
      variant="outline"
      disabled={pending}
      onClick={() => setOpen("stop")}
    >
      {t("sandboxes:stop.action")}
    </Button>
  );
  const secondary = override ? (
    <Button
      type="button"
      size="touch"
      variant="outline"
      data-restore-override=""
      disabled={pending}
      onClick={() => setOpen("restoreOverride")}
    >
      {t("sandboxes:restoreOverride.action")}
    </Button>
  ) : actions.has("stop") ? (
    stopButton
  ) : null;
  const overflow: OverflowAction[] = [
    ...(actions.has("renew")
      ? [
          {
            id: "renew",
            label: t("sandboxes:renew.action"),
            disabled: pending,
            onSelect: () => setOpen("renew"),
          },
        ]
      : []),
    ...(override && actions.has("stop")
      ? [
          {
            id: "stop",
            label: t("sandboxes:stop.action"),
            disabled: pending,
            onSelect: () => setOpen("stop"),
          },
        ]
      : []),
    ...(actions.has("reconnectWarm")
      ? [
          {
            id: "reconnect",
            label: t("sandboxes:reconnect.action"),
            disabled: pending,
            onSelect: () => setOpen("reconnectWarm"),
          },
        ]
      : []),
    ...(deleted
      ? []
      : [{ id: "rename", label: t("sandboxes:rename.action"), onSelect: () => setRenaming(true) }]),
    ...(canCapture
      ? [
          {
            id: "capture",
            label: t("sandboxes:capture.action"),
            disabled: pending,
            onSelect: () => setCapturing(true),
          },
        ]
      : []),
    ...(actions.has("destroy")
      ? [
          {
            id: "destroy",
            label: t(waiting ? "sandboxes:destroy.waitingAction" : "sandboxes:destroy.action"),
            icon: Trash2,
            destructive: true,
            disabled: pending,
            onSelect: lifecycle.openDestroy,
          },
        ]
      : []),
  ];

  return (
    <>
      <PageHeader
        className="sm:flex-col lg:flex-row"
        title={sandboxTitle(sandbox)}
        actions={
          <PageActions
            primary={primary}
            secondary={secondary}
            overflow={overflow}
            overflowLabel={t("sandboxes:actionsLabel")}
          />
        }
      />
      {renaming ? (
        <RenameSandboxSheet lang={lang} sandbox={sandbox} onClose={() => setRenaming(false)} />
      ) : null}
      {capturing ? (
        <SaveAsTemplateDialog sandbox={sandbox} lang={lang} onClose={() => setCapturing(false)} />
      ) : null}
      <SandboxSummary
        sandbox={sandbox}
        locale={locale}
        canRenew={actions.has("renew") && !pending}
        onRenew={() => setOpen("renew")}
      />
      <SandboxNotices
        sandbox={sandbox}
        lang={lang}
        now={now}
        hostOffline={hostView === "offline"}
        override={override}
        loginWait={loginWait}
        restored={restored}
        problem={problem}
      />
      <SandboxPageIndex sections={sections} />

      <SandboxSectionBlock section="overview">
        <StateCard sandbox={sandbox} lang={lang} locale={locale} now={now} lifecycle={lifecycle} />
        <UsageCard sandbox={sandbox} locale={locale} now={now} />
        <LifetimeCard sandbox={sandbox} locale={locale} now={now} />
      </SandboxSectionBlock>

      {deleted ? null : (
        <SandboxSectionBlock section="terminal" titled={false}>
          {/* Keyed: this component survives navigation to another cached
              sandbox, and A's terminal must never stay attached on B's page. */}
          <SandboxTerminal
            key={sandbox.id}
            ref={terminalRef}
            sandboxId={sandbox.id}
            name={sandbox.name}
            lang={lang}
            available={sandbox.state === "READY"}
            photo={
              actions.has("files") && guestHome ? { sandboxId: sandbox.id, guestHome } : undefined
            }
          />
          <SandboxConnectHint target={sandbox.name} />
        </SandboxSectionBlock>
      )}

      {deleted ? null : (
        <SandboxSectionBlock section="previews" titled={false}>
          <SandboxPorts sandbox={sandbox} />
        </SandboxSectionBlock>
      )}

      {deleted ? null : (
        <SandboxSectionBlock section="files" titled={false}>
          {actions.has("files") ? (
            <>
              <SandboxFiles sandboxId={sandbox.id} lang={lang} />
              <SandboxProcesses
                key={`processes-${sandbox.id}`}
                sandboxId={sandbox.id}
                available={actions.has("files")}
              />
            </>
          ) : (
            <p className="text-sm text-muted-foreground">{t("sandboxes:files.unavailable")}</p>
          )}
        </SandboxSectionBlock>
      )}

      <SandboxSectionBlock section="configuration">
        <DiskCard
          sandboxId={sandbox.id}
          disk={sandbox.disk}
          lang={lang}
          locale={locale}
          editable={!deleted}
        />
        <TemplateCard template={sandbox.template} lang={lang} />
        <EgressCard sandbox={sandbox} waiting={waiting} />
        <GuestRootCard sandbox={sandbox} waiting={waiting} />
        {deleted ? null : (
          <SandboxCredentials
            key={`credentials-${sandbox.id}`}
            lang={lang}
            sandboxId={sandbox.id}
            sandboxState={sandbox.state}
          />
        )}
      </SandboxSectionBlock>

      <SandboxSectionBlock section="activity">
        <Card title={t("sandboxes:receipt.title")} id="sandbox-receipt">
          <ReceiptLine receipt={sandbox.lastLifecycleOperation} locale={locale} now={now} />
          <p className="text-sm text-muted-foreground">{t("sandboxes:detail.activityHint")}</p>
          <Link
            to="/$lang/dashboard/operations"
            params={{ lang }}
            search={{ sandboxId: sandbox.id }}
            data-sandbox-operations={sandbox.id}
            className={buttonVariants({
              variant: "outline",
              size: "touch",
              className: "self-start",
            })}
          >
            {t("sandboxes:detail.operations")}
          </Link>
        </Card>
        {/* Kept after the sandbox is destroyed: the audit outlives it. */}
        <SandboxConnections key={`connections-${sandbox.id}`} lang={lang} sandboxId={sandbox.id} />
      </SandboxSectionBlock>

      <SandboxLifecycleDialogs
        sandbox={sandbox}
        lang={lang}
        lifecycle={lifecycle}
        waiting={waiting}
      />
    </>
  );
}

/** Host, access and request warnings between the summary and the sections. */
function SandboxNotices({
  sandbox,
  lang,
  now,
  hostOffline,
  override,
  loginWait,
  restored,
  problem,
}: {
  sandbox: SandboxView;
  lang: string;
  now: number;
  hostOffline: boolean;
  override: boolean;
  loginWait: ReturnType<typeof restoreLoginWait>;
  restored: boolean;
  problem: SandboxLifecycle["problem"];
}) {
  const { t, i18n } = useTranslation(["sandboxes", "hosts"]);
  const live = sandbox.state !== "DELETED";
  return (
    <>
      {sandbox.capacityWait ? <CapacityWaitLine wait={sandbox.capacityWait} lang={lang} /> : null}
      {hostOffline && sandbox.host && live ? (
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
      {sandbox.host?.quarantinedAt && live ? (
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
      {restored ? (
        <p role="status" data-access-restored="" className="text-sm">
          {t("sandboxes:sharing.restored")}
        </p>
      ) : null}
      {sandbox.accessGraceUntil ? (
        <p
          role="alert"
          data-access-grace=""
          className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
        >
          {t("sandboxes:sharing.loss", {
            date: formatDateTime(sandbox.accessGraceUntil, i18n.language),
          })}
        </p>
      ) : null}
    </>
  );
}

/** Where and how the sandbox runs: host, storage, template, placement, labels, last error. */
function StateCard({
  sandbox,
  lang,
  locale,
  now,
  lifecycle,
}: {
  sandbox: SandboxView;
  lang: string;
  locale: string;
  now: number;
  lifecycle: SandboxLifecycle;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const labels = sandboxLabels(sandbox.metadata);
  const waiting = sandbox.state === "WAITING_FOR_CAPACITY";
  const { pending } = lifecycle;
  const retryCleanup = lifecycle.mutations.retryCleanup;
  const cleanupPending =
    sandbox.state === "ERROR" && sandbox.lastErrorCode === "restore_cleanup_pending";
  return (
    <Card title={t("sandboxes:fields.state")} id="sandbox-overview">
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <Field label={t("sandboxes:fields.host")}>
          <span data-sandbox-host="">
            <HostText host={sandbox.host} now={now} waiting={waiting} />
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
        {sandbox.originPoolId ? (
          <Field label={t("sandboxes:fields.acceptedGrace")}>
            <span data-accepted-grace="">
              {formatGraceDuration(sandbox.acceptedGraceSeconds, locale)}
            </span>
          </Field>
        ) : null}
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
              <span data-host-disconnect-expired="" className="block text-xs text-muted-foreground">
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
  );
}
