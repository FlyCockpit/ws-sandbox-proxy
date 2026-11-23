import { useForm } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { env } from "@wssp/env/web";
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
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { CopyField } from "@wssp/ui/components/copy-field";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@wssp/ui/components/dialog";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { Switch } from "@wssp/ui/components/switch";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { Plus } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import z from "zod";
import { AdvancedDetails } from "@/components/advanced-details";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CopyableId } from "@/components/copyable-id";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { type HostItem, HostRow, Pill, STATE_TONE } from "@/components/hosts/host-row";
import { HostsTabs } from "@/components/hosts/hosts-tabs";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { docsRepoPath, docsUrl } from "@/lib/docs-links";
import { formatBytes } from "@/lib/format-bytes";
import { dateTimeTitle } from "@/lib/format-date-time";
import {
  formatAge,
  GUARD_FIREWALL_COMMAND,
  GUARD_INSTALL_COMMAND,
  GUEST_SUDO_FOR_OTHERS_COMMAND,
  type HostMutationProblem,
  hostCapacityState,
  hostCommands,
  hostConnectionState,
  hostDeleteBlocker,
  hostDrainBadge,
  hostEgressBlocker,
  hostForgettable,
  hostForgetUnsafeSandboxes,
  hostGuardState,
  hostMutationProblem,
  nextHostStateChangeAt,
  OPEN_EGRESS_FOR_OTHERS_COMMAND,
  type StorageSummary,
  storageDisplayState,
  toMs,
} from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/**
 * Hosts dashboard (C44): the owner's hosts with connection freshness,
 * capacity, drain state and daemon metadata, plus label edit, drain
 * and delete. The browser never holds a host credential here and provides
 * owner-only host-detail links; every mutation is decided by the server, and any
 * refusal is explained and followed by a refetch.
 */

/** Refetch cadence; the stale transition itself is timer-driven (see useRerenderAt). */
const HOSTS_REFETCH_MS = 15_000;

const QUARANTINE_REASONS = [
  "released_instance_present",
  "unknown_sandbox",
  "foreign_sandbox",
  "deleted_instance_present",
  "generation_ahead",
  "lease_ahead",
  "lease_regressed",
  "lease_mismatch",
] as const;

/** Server reason codes are a closed set; anything else reads as generic. */
function quarantineReasonKey(reason: string | null): (typeof QUARANTINE_REASONS)[number] | "other" {
  return QUARANTINE_REASONS.find((known) => known === reason) ?? "other";
}

function useInvalidateHosts() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listHosts.key() });
}

export function HostsPage({ lang }: { lang: string }) {
  const { t, i18n } = useTranslation(["hosts", "dashboard", "common"]);
  const query = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    refetchInterval: HOSTS_REFETCH_MS,
  });
  const hosts = query.data?.pages.flatMap((page) => page.items);
  const now = Date.now();
  useRerenderAt(nextHostStateChangeAt(hosts ?? [], now));
  const [adding, setAdding] = useState(false);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("hosts:title")}
        description={t("hosts:description")}
        actions={
          <Button type="button" size="touch" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" className="size-4" />
            {t("hosts:enroll.action")}
          </Button>
        }
      />
      <HostsTabs lang={lang} />
      <QueryBoundary
        query={{
          data: hosts,
          isPending: query.isPending,
          isError: query.isError,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <div className="flex min-w-0 flex-col gap-3">
            <EmptyState
              className="rounded-xl border px-4"
              title={t("hosts:empty.title")}
              description={t("hosts:empty.description")}
            />
            <section
              aria-labelledby="hosts-enroll-title"
              className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
            >
              <h2 id="hosts-enroll-title" className="text-sm font-medium">
                {t("hosts:enroll.title")}
              </h2>
              <EnrollHost lang={lang} />
            </section>
          </div>
        }
      >
        {(rows) => (
          <>
            <ul aria-label={t("hosts:listRegion")} className="flex min-w-0 flex-col gap-3">
              {rows.map((host) => (
                <HostRow key={host.id} host={host} now={now} lang={lang} locale={i18n.language} />
              ))}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent closeLabel={t("common:actions.close")}>
          <DialogHeader>
            <DialogTitle>{t("hosts:enroll.title")}</DialogTitle>
          </DialogHeader>
          <EnrollHost lang={lang} />
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Enrolling a machine, in the order a new node owner does it: install, enroll
 * with a device code (approved on the link the CLI prints), install the
 * root-owned egress guard (without it the host connects but takes no
 * sandboxes), then start the daemon. Shown in the Add host dialog, and inline
 * while the list is empty.
 */
function EnrollHost({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  const commands = hostCommands(env.VITE_SERVER_URL);
  const step = "flex min-w-0 flex-col gap-2";
  return (
    <div data-host-enroll="" className="flex min-w-0 flex-col gap-3">
      <p className="text-sm text-muted-foreground">{t("enroll.description")}</p>
      {/* Numbers are part of each step's text, so text and command boxes stay
          on the card's text line (docs/design/edge-lines.md). */}
      <ol className="flex min-w-0 flex-col gap-4 text-sm">
        <li data-enroll-step="install" className={step}>
          <span>
            <StepNumber n={1} />
            {t("enroll.steps.install")}{" "}
            <GuideLink page="hostsQuickStart" label={t("enroll.guideLink")} />
          </span>
          <CopyField value={commands.install} copyLabel={t("enroll.copyCommand")} />
        </li>
        <li data-enroll-step="enroll" className={step}>
          <span>
            <StepNumber n={2} />
            {t("enroll.steps.enroll")}
          </span>
          <CopyField value={commands.deviceLogin} copyLabel={t("enroll.copyCommand")} />
        </li>
        <li data-enroll-step="guard" className={step}>
          <span>
            <StepNumber n={3} />
            {t("enroll.steps.guard")}
          </span>
          <CopyField value={GUARD_INSTALL_COMMAND} copyLabel={t("enroll.copyCommand")} />
        </li>
        <li data-enroll-step="run" className={step}>
          <span>
            <StepNumber n={4} />
            {t("enroll.steps.run")}{" "}
            <GuideLink page="hostsService" label={t("enroll.serviceLink")} />
          </span>
          <CopyField value={commands.connect} copyLabel={t("enroll.copyCommand")} />
        </li>
      </ol>
      <p className="text-sm text-muted-foreground">
        <Trans
          t={t}
          i18nKey="connect.caHint"
          shouldUnescape
          components={{ code: <code className="whitespace-nowrap" /> }}
        />
      </p>
      <p className="text-sm text-muted-foreground">
        <Trans
          t={t}
          i18nKey="connect.vmCapacityHint"
          components={{ code: <code className="whitespace-nowrap" /> }}
        />
      </p>
      <p className="text-sm text-muted-foreground">
        {t("enroll.tokenAlternative")}{" "}
        <Link
          to="/$lang/settings/host-credentials"
          params={{ lang }}
          className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
        >
          {t("enroll.tokenLink")}
        </Link>
      </p>
    </div>
  );
}

/** The visible step number; the ordered list already conveys order to assistive tech. */
function StepNumber({ n }: { n: number }) {
  return (
    <span aria-hidden="true" className="font-medium">
      {n}.{" "}
    </span>
  );
}

/** A link into the host guide, or its repository path when no docs base is configured. */
function GuideLink({ page, label }: { page: "hostsQuickStart" | "hostsService"; label: string }) {
  const { t } = useTranslation("hosts");
  const href = docsUrl(env.VITE_DOCS_URL, page);
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      data-docs-link=""
      className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
    >
      {label}
    </a>
  ) : (
    <span data-docs-path="" className="text-muted-foreground">
      {t("enroll.docsPath", { path: docsRepoPath(page) })}
    </span>
  );
}

export function HostCard({
  host,
  now,
  lang,
  locale,
}: {
  host: HostItem;
  now: number;
  lang: string;
  locale: string;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const invalidate = useInvalidateHosts();
  const [problem, setProblem] = useState<HostMutationProblem | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [forgetting, setForgetting] = useState(false);
  const [unsafeSandboxes, setUnsafeSandboxes] = useState<string[]>([]);
  const [confirmingDrain, setConfirmingDrain] = useState(false);
  const [drainOffload, setDrainOffload] = useState(false);
  const state = hostConnectionState(host, now);
  const drainBadge = hostDrainBadge(host);
  const egressBlocker = state === "deleting" ? null : hostEgressBlocker(host);
  const guard = hostGuardState(host);
  const deleteBlocker = hostDeleteBlocker(host);
  const beat = toMs(host.lastHeartbeatAt);
  const commands = hostCommands(env.VITE_SERVER_URL, host);
  const locked = state === "deleting";

  const onProblem = (error: unknown) => {
    setProblem(hostMutationProblem(error));
    setUnsafeSandboxes(hostForgetUnsafeSandboxes(error));
    invalidate();
  };
  const onMutate = () => {
    setProblem(null);
    setUnsafeSandboxes([]);
  };
  const drain = useMutation({
    ...orpc.sandboxHosts.setHostDraining.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate,
    onSuccess: (result) => {
      toast.success(t(result.draining ? "hosts:drain.drainDone" : "hosts:drain.undrainDone"));
      invalidate();
    },
    onError: onProblem,
  });
  const remove = useMutation({
    ...orpc.sandboxHosts.deleteHost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate,
    onSuccess: (result) => {
      setDeleting(false);
      toast.success(t(result.pending ? "hosts:delete.pending" : "hosts:delete.done"));
      invalidate();
    },
    onError: (error) => {
      setDeleting(false);
      onProblem(error);
    },
  });
  // Stored disks detach to the image store only
  // when the server proves nothing may still run there.
  const forget = useMutation({
    ...orpc.sandboxHosts.forgetHost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate,
    onSuccess: (result) => {
      setForgetting(false);
      toast.success(
        t(result.pending ? "hosts:forget.pending" : "hosts:forget.done", {
          count: result.detached,
        }),
      );
      invalidate();
    },
    onError: (error) => {
      setForgetting(false);
      onProblem(error);
    },
  });
  const forgettable = hostForgettable(state);

  return (
    <li
      data-host-id={host.id}
      data-state={state}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{host.label}</p>
          <p className="truncate font-mono text-xs text-muted-foreground">{host.slug}</p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Pill tone={STATE_TONE[state]} data-host-status={state}>
            {t(`hosts:status.${state}`)}
          </Pill>
          {host.quarantinedAt && state !== "quarantined" ? (
            <Pill tone={STATE_TONE.quarantined} data-host-quarantined="">
              {t("hosts:status.quarantined")}
            </Pill>
          ) : null}
          {drainBadge ? (
            <Pill
              tone="border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400"
              data-host-drain={drainBadge}
            >
              {t(`hosts:drain.${drainBadge}`)}
            </Pill>
          ) : null}
          {egressBlocker ? (
            <Pill
              tone="border-destructive/40 bg-destructive/10 text-destructive"
              data-host-egress=""
            >
              {t("hosts:egress.badge")}
            </Pill>
          ) : null}
          {state === "ready" && !egressBlocker && guard !== "running" ? (
            <Pill
              tone="border-destructive/40 bg-destructive/10 text-destructive"
              data-host-guard-badge=""
            >
              {t("hosts:egress.guard.badge")}
            </Pill>
          ) : null}
        </div>
      </div>
      {state === "ready" ? null : (
        <p className="text-sm text-muted-foreground">{t(`hosts:statusHint.${state}`)}</p>
      )}
      {host.quarantinedAt ? (
        <p className="text-sm text-muted-foreground" data-host-quarantine-reason="">
          {t(`hosts:quarantineReason.${quarantineReasonKey(host.quarantineReason)}`)}
        </p>
      ) : null}
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-3">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:heartbeat.label")}</dt>
          <dd title={dateTimeTitle(beat, locale)}>
            {beat == null ? t("hosts:heartbeat.never") : formatAge(beat, locale, now)}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:capacity.label")}</dt>
          <dd data-host-capacity="">
            {t("hosts:capacity.value", { live: host.liveSandboxCount })}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:daemon.label")}</dt>
          <dd className="truncate">
            {host.daemonRuntime
              ? t(`hosts:daemon.runtime.${host.daemonRuntime}`)
              : t("hosts:daemon.notReported")}
            {host.daemonVersion
              ? ` · ${t("hosts:daemon.version", { version: host.daemonVersion })}`
              : ""}
          </dd>
        </div>
      </dl>
      <section
        data-host-memory=""
        className="flex min-w-0 flex-col gap-2 rounded-lg border bg-muted/30 p-3"
      >
        <h3 className="text-sm font-medium">{t("hosts:vmCapacity.title")}</h3>
        <div className="flex flex-wrap gap-2">
          <Badge
            data-capacity-state={hostCapacityState(host, now)}
            variant="outline"
            className={cn(
              "whitespace-normal",
              hostCapacityState(host, now) === "stale" &&
                "border-state-warning/50 bg-state-warning-bg",
            )}
          >
            {t(`hosts:vmCapacity.${hostCapacityState(host, now)}`)}
          </Badge>
          {(host.capacity.memoryOvercommittedMiB ?? 0) > 0 ||
          (host.capacity.vcpuOvercommitted ?? 0) > 0 ? (
            <Badge variant="destructive">{t("hosts:vmCapacity.overcommitted")}</Badge>
          ) : null}
        </div>
        <dl className="grid min-w-0 gap-3 text-sm tabular-nums sm:grid-cols-3">
          {(
            [
              "memoryBudgetMiB",
              "memoryReservedMiB",
              "memoryAvailableMiB",
              "memoryOvercommittedMiB",
              "vcpuBudget",
              "vcpuReserved",
              "vcpuAvailable",
              "vcpuOvercommitted",
              "maxCpuCount",
              "maxMemoryMiB",
            ] as const
          ).map((field) => (
            <div key={field} className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t(`hosts:vmCapacity.${field}`)}</dt>
              <dd
                data-capacity-field={field}
                className={cn(
                  field === "memoryOvercommittedMiB" &&
                    (host.capacity.memoryOvercommittedMiB ?? 0) > 0 &&
                    "font-medium text-destructive",
                )}
              >
                {host.capacity[field] == null
                  ? t("hosts:daemon.notReported")
                  : t(
                      field === "maxCpuCount" || field.startsWith("vcpu")
                        ? "hosts:vmCapacity.cpuValue"
                        : "hosts:vmCapacity.memoryValue",
                      { value: host.capacity[field] },
                    )}
              </dd>
            </div>
          ))}
        </dl>
        <p className="text-xs text-muted-foreground">{t("hosts:vmCapacity.hint")}</p>
        <p data-vcpu-budget-hint="" className="text-xs text-muted-foreground">
          {t("hosts:vmCapacity.vcpuBudgetHint", {
            multiplier: VM_SIZE_LIMITS.hostVcpuBudgetDefaultThreadsMultiplier,
            max: VM_SIZE_LIMITS.hostVcpuBudgetMax,
          })}
        </p>
      </section>
      <p data-retained-roots="" className="text-sm">
        {t("hosts:storage.roots", { count: host.retainedRootCount })}
      </p>
      <p className="text-xs text-muted-foreground">{t("hosts:storage.retainedHint")}</p>
      <section aria-label={t("hosts:storage.title")} className="flex min-w-0 flex-col gap-3">
        <h3 className="text-sm font-medium">{t("hosts:storage.title")}</h3>
        {host.storagePools.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("hosts:storage.empty")}</p>
        ) : null}
        {host.storagePools.map((pool) => (
          <StorageCard key={pool.id} pool={pool} now={now} locale={locale} />
        ))}
      </section>
      {host.daemonRuntime === "UNSUPPORTED" ? (
        <p className="text-sm text-destructive">{t("hosts:daemon.unsupportedHint")}</p>
      ) : null}
      {egressBlocker ? (
        <p className="text-sm text-destructive" data-host-egress-hint={egressBlocker}>
          <Trans
            t={t}
            i18nKey={`hosts:egress.${egressBlocker}`}
            components={{ code: <code className="whitespace-nowrap" /> }}
          />
        </p>
      ) : null}
      {locked ? null : <HostNetwork host={host} connected={state === "ready"} />}
      {drainBadge ? (
        <p className="text-sm text-muted-foreground">
          {drainBadge === "drained"
            ? t("hosts:drain.drainedHint")
            : t("hosts:drain.drainingHint", { count: host.liveSandboxCount })}
        </p>
      ) : null}
      {host.draining && host.drainOffload ? (
        <p data-host-drain-offload="" className="text-sm text-muted-foreground">
          {t("hosts:drain.offloadingHint")}
        </p>
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`hosts:problem.${problem}`)}
        </p>
      ) : null}
      {unsafeSandboxes.length > 0 ? (
        <ul data-host-forget-unsafe="" className="flex min-w-0 flex-col gap-1 text-sm">
          {unsafeSandboxes.map((id) => (
            <li key={id} className="min-w-0 truncate font-mono text-xs">
              {id}
            </li>
          ))}
        </ul>
      ) : null}
      {locked ? null : (
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="secondary" size="touch" onClick={() => setEditing(true)}>
            {t("hosts:edit.action")}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="touch"
            title={host.draining ? undefined : t("hosts:drain.hint")}
            disabled={drain.isPending}
            // Draining is undoable but blocks new work, so it is confirmed;
            // undrain stays one click.
            onClick={() =>
              host.draining
                ? drain.mutate({ id: host.id, draining: false })
                : setConfirmingDrain(true)
            }
          >
            {t(host.draining ? "hosts:drain.undrain" : "hosts:drain.drain")}
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="touch"
            disabled={deleteBlocker != null || remove.isPending}
            aria-describedby={
              deleteBlocker === "live" ? `host-delete-blocked-${host.id}` : undefined
            }
            onClick={() => setDeleting(true)}
          >
            {t("hosts:delete.action")}
          </Button>
          {forgettable ? (
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={forget.isPending}
              onClick={() => setForgetting(true)}
            >
              {t("hosts:forget.action")}
            </Button>
          ) : null}
        </div>
      )}
      {locked && forgettable ? (
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="touch"
            disabled={forget.isPending}
            onClick={() => setForgetting(true)}
          >
            {t("hosts:forget.action")}
          </Button>
        </div>
      ) : null}
      {deleteBlocker === "live" ? (
        <p id={`host-delete-blocked-${host.id}`} className="text-xs text-muted-foreground">
          {t("hosts:delete.blockedLive")}
        </p>
      ) : null}
      {locked ? null : (
        <details className="min-w-0 text-sm">
          <summary className="flex min-h-11 cursor-pointer items-center font-medium">
            {t("hosts:connect.title")}
          </summary>
          <div className="flex min-w-0 flex-col gap-2 pt-2">
            <p className="text-muted-foreground">{t("hosts:connect.device")}</p>
            <CopyField value={commands.deviceLogin} copyLabel={t("hosts:connect.copyCommand")} />
            <CopyField value={commands.connect} copyLabel={t("hosts:connect.copyCommand")} />
            <p className="text-muted-foreground">
              <Trans
                t={t}
                i18nKey="hosts:connect.caHint"
                shouldUnescape
                components={{ code: <code className="whitespace-nowrap" /> }}
              />
            </p>
            <p className="text-muted-foreground">
              <Trans
                t={t}
                i18nKey="hosts:connect.vmCapacityHint"
                components={{ code: <code className="whitespace-nowrap" /> }}
              />
            </p>
            <p className="text-muted-foreground">
              {t("hosts:connect.token")}{" "}
              <Link
                to="/$lang/settings/host-credentials"
                params={{ lang }}
                className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
              >
                {t("hosts:enroll.tokenLink")}
              </Link>
            </p>
            {commands.tokenConnect ? (
              <CopyField value={commands.tokenConnect} copyLabel={t("hosts:connect.copyCommand")} />
            ) : null}
          </div>
        </details>
      )}
      {editing ? <EditHostSheet host={host} onClose={() => setEditing(false)} /> : null}
      <AlertDialog open={confirmingDrain} onOpenChange={setConfirmingDrain}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("hosts:drain.confirmTitle", { name: host.label })}
            </AlertDialogTitle>
            <AlertDialogDescription>{t("hosts:drain.hint")}</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex min-h-11 min-w-0 items-start justify-between gap-3 text-sm">
            <label htmlFor={`host-drain-offload-${host.id}`} className="min-w-0">
              <span className="block font-medium">{t("hosts:drain.offloadLabel")}</span>
              <span className="block text-muted-foreground">{t("hosts:drain.offloadHint")}</span>
            </label>
            <Switch
              id={`host-drain-offload-${host.id}`}
              data-host-drain-offload-toggle=""
              checked={drainOffload}
              onCheckedChange={setDrainOffload}
            />
          </div>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              disabled={drain.isPending}
              onClick={() => {
                setConfirmingDrain(false);
                drain.mutate({ id: host.id, draining: true, offload: drainOffload });
              }}
            >
              {t("hosts:drain.drain")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("hosts:delete.title", { name: host.label })}
        description={t("hosts:delete.description")}
        confirmToken={host.slug}
        typePrompt={t("hosts:delete.typePrompt")}
        copyAriaLabel={t("hosts:delete.copySlug")}
        inputMode="url"
        isPending={remove.isPending}
        onConfirm={() => remove.mutate({ id: host.id })}
      />
      <ConfirmDeleteDialog
        open={forgetting}
        onOpenChange={setForgetting}
        title={t("hosts:forget.title", { name: host.label })}
        description={t("hosts:forget.description")}
        confirmToken={host.slug}
        typePrompt={t("hosts:delete.typePrompt")}
        copyAriaLabel={t("hosts:delete.copySlug")}
        inputMode="url"
        confirmLabel={t("hosts:forget.confirm")}
        isPending={forget.isPending}
        onConfirm={() => forget.mutate({ id: host.id })}
      />
    </li>
  );
}

/**
 * Default-open egress on this node: the root-owned guard's health (no active
 * lease means no sandbox can start here, in either mode), whether the daemon
 * can serve open internet, and the owner's consent for other users'
 * sandboxes. Both are set on the host; the install command is shown for the
 * owner to run as root, never run for them.
 */
function HostNetwork({ host, connected }: { host: HostItem; connected: boolean }) {
  const { t } = useTranslation(["hosts"]);
  const guard = hostGuardState(host);
  const unhealthy = connected && guard !== "running";
  return (
    <section
      data-host-network=""
      aria-label={t("hosts:egress.title")}
      className="flex min-w-0 flex-col gap-2 rounded-lg border bg-muted/30 p-3"
    >
      <h3 className="text-sm font-medium">{t("hosts:egress.title")}</h3>
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:egress.guard.label")}</dt>
          <dd data-host-guard={connected ? guard : "offline"}>
            {t(`hosts:egress.guard.state.${connected ? guard : "offline"}`)}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:egress.openForOthers")}</dt>
          <dd data-host-open-for-others={host.openEgressForOthers ? "on" : "off"}>
            {t(host.openEgressForOthers ? "hosts:egress.on" : "hosts:egress.off")}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("hosts:egress.guestSudoForOthers")}</dt>
          <dd data-host-guest-sudo-for-others={host.guestSudoForOthers ? "on" : "off"}>
            {t(
              host.guestSudoForOthers
                ? "hosts:egress.guestSudoForOthersOn"
                : "hosts:egress.guestSudoForOthersOff",
            )}
          </dd>
        </div>
      </dl>
      {unhealthy ? (
        <div data-host-guard-hint={guard} className="flex min-w-0 flex-col gap-2">
          <p className="text-sm text-destructive">
            {t(`hosts:egress.guard.reason.${guard}`)} <span>{t("hosts:egress.guard.blocked")}</span>
          </p>
          {guard === "incus_server_shared" ? null : guard === "host_firewall_blocks_sandboxes" ? (
            <>
              <p className="text-xs text-muted-foreground">{t("hosts:egress.guard.firewall")}</p>
              <CopyField
                value={GUARD_FIREWALL_COMMAND}
                copyLabel={t("hosts:connect.copyCommand")}
              />
            </>
          ) : (
            <>
              <p className="text-xs text-muted-foreground">{t("hosts:egress.guard.install")}</p>
              <CopyField value={GUARD_INSTALL_COMMAND} copyLabel={t("hosts:connect.copyCommand")} />
            </>
          )}
        </div>
      ) : null}
      {connected && host.egressEnforcement && !host.egressOpen ? (
        <p data-host-open-unsupported="" className="text-sm text-muted-foreground">
          {t("hosts:egress.openUnsupported")}
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        {t("hosts:egress.openForOthersHint", { command: OPEN_EGRESS_FOR_OTHERS_COMMAND })}
      </p>
      {host.openEgressForOthers ? (
        <p data-host-open-warning="" className="text-xs text-muted-foreground">
          {t("hosts:egress.openForOthersWarning")}
        </p>
      ) : null}
      <p data-host-guest-sudo-hint="" className="text-xs text-muted-foreground">
        {t("hosts:egress.guestSudoForOthersHint", { command: GUEST_SUDO_FOR_OTHERS_COMMAND })}
      </p>
    </section>
  );
}

function StorageCard({ pool, now, locale }: { pool: StorageSummary; now: number; locale: string }) {
  const { t } = useTranslation("hosts");
  const state = storageDisplayState(pool, now);
  const over = Math.max(0, pool.diskReservedGiB - pool.capacityGiB);
  const report = toMs(pool.reportedAt);
  return (
    <div
      data-storage-id={pool.id}
      data-storage-state={state}
      className="flex min-w-0 flex-col gap-2 rounded-lg border p-3 text-sm"
    >
      <h4 className="break-all font-medium">{pool.name}</h4>
      <div className="flex flex-wrap gap-2">
        <Badge variant={state === "healthy" ? "outline" : "destructive"}>
          {t(`storage.${state}`)}
        </Badge>
        {pool.draining ? <Badge variant="outline">{t("storage.draining")}</Badge> : null}
        {over > 0 ? (
          <Badge variant="destructive">{t("storage.overcommitted", { value: over })}</Badge>
        ) : null}
      </div>
      {pool.reason ? <p>{t(`storage.reason.${pool.reason}`)}</p> : null}
      <p>
        {t("storage.commitments", {
          reserved: pool.diskReservedGiB,
          capacity: pool.capacityGiB,
          free: Math.max(0, pool.capacityGiB - pool.diskReservedGiB),
        })}
      </p>
      <p>{t(`storage.source.${pool.capacitySource}`)}</p>
      {pool.capacitySource === "implicit" ? (
        <>
          <p>
            {t("storage.derived", {
              total: pool.totalBasedCapacityGiB,
              effective: pool.capacityGiB,
              ceiling: pool.implicitCeilingGiB,
            })}
          </p>
          {pool.capacityGiB < (pool.totalBasedCapacityGiB ?? 0) ? (
            <p data-storage-limited="" className="text-state-warning">
              {t("storage.limited")}
            </p>
          ) : null}
          <details>
            <summary className="flex min-h-11 cursor-pointer items-center">
              {t("storage.derivation")}
            </summary>
            <dl className="grid gap-2 sm:grid-cols-2">
              {(
                [
                  "derivationTotalBytes",
                  "derivationFreeBytes",
                  "derivationCommittedBytes",
                  "derivationActualBytes",
                  "derivationHeadroomBytes",
                ] as const
              ).map((field) => (
                <div key={field}>
                  <dt>{t(`storage.${field}`)}</dt>
                  <dd>
                    {pool[field] === null
                      ? t("daemon.notReported")
                      : formatBytes(Number(pool[field]), locale)}
                  </dd>
                </div>
              ))}
            </dl>
          </details>
        </>
      ) : null}
      <p>
        {pool.totalBytes === null
          ? t("storage.usageUnknown")
          : t("storage.usage", {
              total: formatBytes(Number(pool.totalBytes), locale),
              used: formatBytes(Number(pool.usedBytes ?? 0), locale),
              free: formatBytes(Number(pool.freeBytes ?? 0), locale),
            })}
      </p>
      <p title={dateTimeTitle(report, locale)}>
        {t("storage.reported", {
          age: report === null ? t("heartbeat.never") : formatAge(report, locale, now),
        })}
      </p>
      <p className="text-xs text-muted-foreground">{t("storage.hint")}</p>
      <AdvancedDetails>
        <div className="flex min-w-0 flex-col gap-1">
          <span className="text-xs text-muted-foreground">{t("storage.identityLabel")}</span>
          <CopyableId value={pool.marker} label={t("storage.identityLabel")} />
        </div>
      </AdvancedDetails>
    </div>
  );
}

function editSchema(t: (key: string) => string) {
  return z.object({
    label: z.string().trim().min(1, t("hosts:edit.labelRequired")).max(160),
  });
}

function EditHostSheet({ host, onClose }: { host: HostItem; onClose: () => void }) {
  const { t } = useTranslation(["hosts", "common"]);
  const invalidate = useInvalidateHosts();
  const [problem, setProblem] = useState<HostMutationProblem | null>(null);
  const update = useMutation({
    ...orpc.sandboxHosts.updateHost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { label: host.label },
    validators: { onSubmit: editSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await update.mutateAsync({
          id: host.id,
          label: value.label.trim(),
        });
      } catch (error) {
        setProblem(hostMutationProblem(error));
        invalidate();
        return;
      }
      toast.success(t("hosts:edit.saved"));
      invalidate();
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        closeLabel={t("common:actions.close")}
        className="overflow-x-hidden overflow-y-auto"
      >
        <SheetHeader>
          <SheetTitle>{t("hosts:edit.title")}</SheetTitle>
          <SheetDescription>{t("hosts:edit.description")}</SheetDescription>
        </SheetHeader>
        <form
          className="flex min-w-0 flex-col gap-4 px-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <form.Field name="label">
            {(field) => (
              <TextField
                field={field}
                label={t("hosts:edit.label")}
                inputMode="text"
                autoComplete="off"
                maxLength={160}
              />
            )}
          </form.Field>
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`hosts:problem.${problem}`)}
            </p>
          ) : null}
          <SheetFooter className="px-0">
            <form.Subscribe selector={(formState) => formState.isSubmitting}>
              {(submitting) => (
                <Button type="submit" size="touch" disabled={submitting}>
                  {submitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
                </Button>
              )}
            </form.Subscribe>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
