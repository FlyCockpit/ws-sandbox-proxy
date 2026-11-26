import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { cn } from "@wssp/ui/lib/utils";
import { Boxes, Plus, Server, SquareTerminal } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";

import { EmptyState } from "@/components/empty-state";
import { Pill, STATE_TONE } from "@/components/hosts/host-row";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useStatusClock } from "@/hooks/use-status-clock";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { dateTimeTitle } from "@/lib/format-date-time";
import {
  formatAge,
  HOST_STATUS_REFETCH_MS,
  hostConnectionState,
  nextHostStateChangeAt,
} from "@/lib/host-status";
import {
  NEW_TERMINAL_TARGETS_LIMIT,
  TERMINAL_KIND_FILTERS,
  type TerminalKindFilter,
} from "@/lib/terminal-page-search";
import { orpc } from "@/utils/orpc";

/** Live terminals come from relay memory; poll so other tabs' terminals show up. */
const TERMINALS_REFETCH_MS = 10_000;
/** The picker follows sandboxes starting elsewhere. */
const TARGETS_REFETCH_MS = 30_000;
const NEW_TERMINAL_ID = "new-terminal";

type LiveTerminal = Awaited<ReturnType<typeof orpc.terminals.list.call>>["terminals"][number];

const ROW_CLASS =
  "flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground sm:flex-row sm:items-center";
const STATUS_TONE = {
  attached: STATE_TONE.ready,
  connecting: STATE_TONE.stale,
} as const;

/**
 * The signed-in person's own live browser terminals, on their sandboxes and
 * hosts, plus where to open a new one. Terminals are not persistent: one
 * lives as long as the tab that opened it, and opening another terminal on
 * the same sandbox or host ends the first (a fresh shell starts).
 */
export function TerminalsPage({
  lang,
  kind,
  onKindChange,
}: {
  lang: string;
  kind: TerminalKindFilter;
  onKindChange: (kind: TerminalKindFilter) => void;
}) {
  const { t, i18n } = useTranslation(["terminal", "dashboard", "common"]);
  const query = useQuery({
    ...orpc.terminals.list.queryOptions(),
    refetchInterval: TERMINALS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const all = query.data?.terminals;
  const shown = all?.filter((terminal) => kind === "all" || terminal.target.kind === kind);
  const now = Date.now();

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        title={t("terminal:page.title")}
        description={t("terminal:page.description")}
        actions={
          <Link
            to="/$lang/dashboard/terminals"
            params={{ lang }}
            search={{ kind: kind === "all" ? undefined : kind }}
            hash={NEW_TERMINAL_ID}
            className={buttonVariants({ size: "touch" })}
            data-new-terminal-link=""
          >
            <Plus aria-hidden="true" className="size-4" />
            {t("terminal:page.new")}
          </Link>
        }
      />
      <SegmentedControl
        ariaLabel={t("terminal:page.filter.label")}
        value={kind}
        onChange={onKindChange}
        items={TERMINAL_KIND_FILTERS.map((value) => ({
          value,
          label: t(`terminal:page.filter.${value}`),
        }))}
      />
      <section aria-labelledby="terminals-open-title" className="flex min-w-0 flex-col gap-3">
        <h2 id="terminals-open-title" className="text-sm font-medium">
          {t("terminal:page.openTitle")}
        </h2>
        <QueryBoundary
          query={{
            data: shown,
            isPending: query.isPending,
            isError: query.isError,
            error: query.error,
            refetch: query.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              className="rounded-xl border px-4"
              title={t(
                all && all.length > 0 ? "terminal:page.emptyFiltered" : "terminal:page.empty.title",
              )}
              // The picker sits right below: the description points at it.
              description={t(`terminal:page.empty.description.${kind}`)}
            />
          }
        >
          {(rows) => (
            <>
              <ul aria-label={t("terminal:page.openTitle")} className="flex min-w-0 flex-col gap-3">
                {rows.map((terminal) => (
                  <TerminalRow
                    key={terminal.id}
                    terminal={terminal}
                    lang={lang}
                    locale={i18n.language}
                    now={now}
                  />
                ))}
              </ul>
              {query.data?.truncated ? (
                <p className="text-sm text-muted-foreground">{t("terminal:page.truncated")}</p>
              ) : null}
            </>
          )}
        </QueryBoundary>
      </section>
      <NewTerminal lang={lang} kind={kind} live={all ?? []} />
    </div>
  );
}

/** The target's page, scrolled to its terminal (attaching stays an explicit click). */
function targetLink(target: { kind: "sandbox" | "host"; id: string }, lang: string) {
  return target.kind === "sandbox"
    ? ({
        to: "/$lang/dashboard/sandboxes/$sandboxId",
        params: { lang, sandboxId: target.id },
        hash: "terminal",
      } as const)
    : ({
        to: "/$lang/settings/hosts/$hostId",
        params: { lang, hostId: target.id },
        hash: "terminal",
      } as const);
}

function TerminalRow({
  terminal,
  lang,
  locale,
  now,
}: {
  terminal: LiveTerminal;
  lang: string;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["terminal", "sandboxes", "hosts", "common"]);
  const [confirming, setConfirming] = useState(false);
  const queryClient = useQueryClient();
  const end = useMutation({
    ...orpc.terminals.end.mutationOptions(),
    // This mutation explains every outcome itself (gone is not a failure).
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => toast.success(t("terminal:page.end.done")),
    onError: (error) => {
      // Already gone is still the outcome the person asked for.
      if ((error as { code?: unknown }).code === "NOT_FOUND")
        toast.success(t("terminal:page.end.alreadyGone"));
      else toast.error(t("terminal:page.end.failed"));
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: orpc.terminals.list.key() }),
  });
  const name = terminal.target.name ?? t("terminal:page.unknownTarget");
  const Icon = terminal.target.kind === "sandbox" ? Boxes : Server;
  const targetState =
    terminal.target.kind === "sandbox"
      ? terminal.target.state
        ? t(`sandboxes:state.${terminal.target.state}`)
        : null
      : terminal.target.status
        ? t(`terminal:page.hostStatus.${terminal.target.status}`)
        : null;
  const device = deviceLabel(terminal, {
    thisBrowser: t("terminal:page.thisBrowser"),
    unknown: t("terminal:page.deviceUnknown"),
    both: (browser, os) => t("terminal:page.deviceBoth", { browser, os }),
  });
  const opened = new Date(terminal.openedAt).getTime();
  const active = new Date(terminal.lastActivityAt).getTime();

  return (
    <li
      className={ROW_CLASS}
      data-terminal-id={terminal.id}
      data-terminal-kind={terminal.target.kind}
      data-terminal-status={terminal.status}
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
        <div className="flex min-w-0 flex-1 flex-col gap-1.5">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Link
              {...targetLink(terminal.target, lang)}
              className="inline-flex min-h-11 min-w-0 items-center truncate font-medium underline-offset-4 hover:underline"
            >
              {name}
            </Link>
            <span className="text-xs text-muted-foreground">
              {t(`terminal:page.kind.${terminal.target.kind}`)}
              {targetState ? ` · ${targetState}` : ""}
            </span>
            <Pill tone={STATUS_TONE[terminal.status]} data-terminal-state={terminal.status}>
              {t(`terminal:page.status.${terminal.status}`)}
            </Pill>
          </div>
          <dl className="grid min-w-0 grid-cols-1 gap-x-4 gap-y-1 text-sm text-muted-foreground sm:grid-cols-[auto_1fr] lg:flex lg:flex-wrap">
            <div className="flex min-w-0 gap-1">
              <dt>{t("terminal:page.openedFrom")}</dt>
              <dd className="min-w-0 truncate text-foreground">{device}</dd>
            </div>
            <div className="flex min-w-0 gap-1">
              <dt>{t("terminal:page.started")}</dt>
              <dd title={dateTimeTitle(opened, locale)}>{formatAge(opened, locale, now)}</dd>
            </div>
            <div className="flex min-w-0 gap-1">
              <dt>{t("terminal:page.lastActivity")}</dt>
              <dd title={dateTimeTitle(active, locale)}>{formatAge(active, locale, now)}</dd>
            </div>
          </dl>
        </div>
      </div>
      <div className="flex min-w-0 flex-wrap gap-2 sm:shrink-0">
        <Link
          {...targetLink(terminal.target, lang)}
          aria-label={t("terminal:page.openHereLabel", { name })}
          className={cn(
            buttonVariants({ variant: "outline", size: "touch" }),
            "flex-1 sm:flex-none",
          )}
        >
          <SquareTerminal aria-hidden="true" className="size-4" />
          {t("terminal:page.openHere")}
        </Link>
        <Button
          type="button"
          variant="destructive"
          size="touch"
          className="flex-1 sm:flex-none"
          aria-label={t("terminal:page.end.label", { name })}
          disabled={end.isPending}
          onClick={() => setConfirming(true)}
        >
          {t("terminal:page.end.action")}
        </Button>
      </div>
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>{t("terminal:page.end.title", { name })}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                terminal.thisBrowser
                  ? "terminal:page.end.descriptionHere"
                  : "terminal:page.end.description",
                { device },
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              variant="destructive"
              data-terminal-end-confirm=""
              onClick={() => {
                setConfirming(false);
                end.mutate({ id: terminal.id });
              }}
            >
              {t("terminal:page.end.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  );
}

/** "This browser (another tab)", "Firefox on Linux", "Firefox", or "Another browser". */
function deviceLabel(
  terminal: Pick<LiveTerminal, "thisBrowser" | "device">,
  labels: { thisBrowser: string; unknown: string; both: (browser: string, os: string) => string },
): string {
  if (terminal.thisBrowser) return labels.thisBrowser;
  const { browser, os } = terminal.device;
  if (browser && os) return labels.both(browser, os);
  return browser ?? os ?? labels.unknown;
}

/**
 * Where a new terminal can open: the person's running sandboxes and their
 * own hosts. Each row goes to the target's page, where the terminal attaches
 * on an explicit click (a host may also ask for its TOTP code there).
 */
function NewTerminal({
  lang,
  kind,
  live,
}: {
  lang: string;
  kind: TerminalKindFilter;
  live: readonly LiveTerminal[];
}) {
  const { t } = useTranslation(["terminal", "hosts", "dashboard"]);
  const sandboxes = useQuery({
    ...orpc.sandboxes.list.queryOptions({
      input: { limit: NEW_TERMINAL_TARGETS_LIMIT, states: ["READY"] },
    }),
    enabled: kind !== "host",
    refetchInterval: TARGETS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = useQuery({
    ...orpc.terminals.hostTargets.queryOptions(),
    enabled: kind !== "sandbox",
    // Heartbeats are judged against a 30 s window: a list cached while the
    // filter hid it (or from an earlier visit) is refetched as soon as it
    // shows, and polled at the host-status cadence, never the five-minute
    // default staleTime.
    staleTime: 0,
    refetchOnMount: "always",
    refetchInterval: HOST_STATUS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  // Until that refetch lands, the cached rows are judged as of their fetch.
  const now = useStatusClock(hosts.dataUpdatedAt, hosts.isFetching);
  // A heartbeat turns stale on screen on time, even while a refetch hangs.
  useRerenderAt(nextHostStateChangeAt(hosts.data?.hosts ?? [], now));
  const openOn = new Set(live.map((terminal) => `${terminal.target.kind}:${terminal.target.id}`));

  return (
    <section
      id={NEW_TERMINAL_ID}
      aria-labelledby="new-terminal-title"
      tabIndex={-1}
      className="flex min-w-0 scroll-mt-4 flex-col gap-4 rounded-xl border bg-card p-4 text-card-foreground focus-visible:outline-none"
    >
      <header className="space-y-1">
        <h2 id="new-terminal-title" className="text-sm font-medium">
          {t("terminal:page.newTitle")}
        </h2>
        <p className="text-sm text-muted-foreground">{t("terminal:page.newHint")}</p>
      </header>
      {kind !== "host" ? (
        <TargetGroup
          title={t("terminal:page.filter.sandbox")}
          query={{ ...sandboxes, loaded: sandboxes.data !== undefined }}
          rows={(sandboxes.data?.items ?? []).map((sandbox) => ({
            key: sandbox.id,
            name: sandbox.name,
            detail: null,
            disabledReason: null,
            help: null,
            open: openOn.has(`sandbox:${sandbox.id}`),
            link: targetLink({ kind: "sandbox", id: sandbox.id }, lang),
          }))}
          more={Boolean(sandboxes.data?.nextCursor)}
          moreLink={
            <Link
              to="/$lang/dashboard/sandboxes"
              params={{ lang }}
              className="inline-flex min-h-11 items-center underline"
            >
              {t("terminal:page.allSandboxes")}
            </Link>
          }
          empty={
            <p className="text-sm text-muted-foreground">
              {t("terminal:page.noSandboxes")}{" "}
              <Link
                to="/$lang/dashboard/sandboxes"
                params={{ lang }}
                className="inline-flex min-h-11 items-center underline"
              >
                {t("terminal:page.goSandboxes")}
              </Link>
            </p>
          }
        />
      ) : null}
      {kind !== "sandbox" ? (
        <TargetGroup
          title={t("terminal:page.filter.host")}
          query={{ ...hosts, loaded: hosts.data !== undefined }}
          rows={(hosts.data?.hosts ?? []).map((host) => {
            const state = hostConnectionState(host, now);
            const connected = state === "ready" || state === "stale";
            return {
              key: host.id,
              name: host.label,
              detail: t(`hosts:status.${state}`),
              disabledReason: !connected
                ? t("terminal:page.hostOffline", { command: "wssp host run" })
                : host.hostTerminal === false
                  ? t("terminal:page.hostTerminalOff")
                  : host.hostTerminal === null
                    ? // Its live connection is not known here yet: never claim "off".
                      t("terminal:page.hostTerminalUnknown")
                    : null,
              // Off at the node: the host page explains how to turn it on.
              help:
                connected && host.hostTerminal === false
                  ? targetLink({ kind: "host", id: host.id }, lang)
                  : null,
              open: openOn.has(`host:${host.id}`),
              link: targetLink({ kind: "host", id: host.id }, lang),
            };
          })}
          more={Boolean(hosts.data?.more)}
          moreLink={
            <Link
              to="/$lang/settings/hosts"
              params={{ lang }}
              className="inline-flex min-h-11 items-center underline"
            >
              {t("terminal:page.allHosts")}
            </Link>
          }
          empty={
            <p className="text-sm text-muted-foreground">
              {t("terminal:page.noHosts")}{" "}
              <Link
                to="/$lang/settings/hosts"
                params={{ lang }}
                className="inline-flex min-h-11 items-center underline"
              >
                {t("terminal:page.goHosts")}
              </Link>
            </p>
          }
          footnote={t("terminal:page.hostHint")}
        />
      ) : null}
    </section>
  );
}

type TargetRow = {
  key: string;
  name: string;
  detail: string | null;
  disabledReason: string | null;
  /** Where to fix what `disabledReason` names (the host page), if anywhere. */
  help: ReturnType<typeof targetLink> | null;
  /** A terminal is already open there: opening another ends it. */
  open: boolean;
  link: ReturnType<typeof targetLink>;
};

function TargetGroup({
  title,
  query,
  rows,
  more,
  moreLink,
  empty,
  footnote,
}: {
  title: string;
  query: {
    loaded: boolean;
    isPending: boolean;
    isError: boolean;
    error: unknown;
    refetch: () => unknown;
  };
  rows: TargetRow[];
  more: boolean;
  moreLink: ReactNode;
  empty: ReactNode;
  footnote?: string;
}) {
  const { t } = useTranslation(["terminal", "dashboard"]);
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</h3>
      <QueryBoundary
        // Rows exist only once the source query has loaded: a failed first
        // load must show its retry, never "no sandboxes" or "no hosts".
        query={{ ...query, data: query.loaded ? rows : undefined }}
        skeleton={<SkeletonList layout="resource" count={2} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(list) => list.length === 0}
        empty={empty}
      >
        {(list) => (
          <ul className="grid min-w-0 grid-cols-1 gap-2 md:grid-cols-2 2xl:grid-cols-3">
            {list.map((row) => (
              <li
                key={row.key}
                data-new-terminal-target={row.key}
                className="flex min-w-0 items-center gap-3 rounded-lg border p-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">{row.name}</p>
                  {row.detail || row.disabledReason || row.open ? (
                    <p className="text-xs text-muted-foreground">
                      {[
                        row.detail,
                        row.disabledReason,
                        row.open ? t("terminal:page.alreadyOpen") : null,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </p>
                  ) : null}
                </div>
                {row.disabledReason ? (
                  row.help ? (
                    <Link
                      {...row.help}
                      className="inline-flex min-h-11 shrink-0 items-center text-sm underline"
                    >
                      {t("terminal:page.howToTurnOn")}
                    </Link>
                  ) : null
                ) : (
                  <Link
                    {...row.link}
                    aria-label={t(
                      row.open ? "terminal:page.replaceOnLabel" : "terminal:page.openOnLabel",
                      { name: row.name },
                    )}
                    className={cn(
                      buttonVariants({ variant: "outline", size: "touch" }),
                      "shrink-0",
                    )}
                  >
                    <SquareTerminal aria-hidden="true" className="size-4" />
                    {t(row.open ? "terminal:page.replaceOn" : "terminal:page.openOn")}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </QueryBoundary>
      {more ? moreLink : null}
      {footnote ? <p className="text-xs text-muted-foreground">{footnote}</p> : null}
    </div>
  );
}
