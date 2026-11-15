import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { Badge } from "@wssp/ui/components/badge";
import { cn } from "@wssp/ui/lib/utils";
import { ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";

import { dateTimeTitle } from "@/lib/format-date-time";
import {
  formatAge,
  type HostConnectionState,
  hostConnectionState,
  hostDrainBadge,
  toMs,
} from "@/lib/host-status";

type HostPage = Awaited<ReturnType<AppRouterClient["sandboxHosts"]["listHosts"]>>;
export type HostItem = HostPage["items"][number];

export const STATE_TONE: Record<HostConnectionState, string> = {
  ready: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  stale: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  quarantined: "border-destructive/40 bg-destructive/10 text-destructive",
  reconnecting: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  offline: "border-border bg-muted text-muted-foreground",
  never: "border-border bg-muted text-muted-foreground",
  revoked: "border-destructive/40 bg-destructive/10 text-destructive",
  deleting: "border-destructive/40 bg-destructive/10 text-destructive",
};

export function Pill({
  tone,
  children,
  ...rest
}: { tone: string; children: string } & Record<`data-${string}`, string>) {
  return (
    <Badge
      {...rest}
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {children}
    </Badge>
  );
}

/**
 * One host in the Hosts list: label, status, heartbeat, live sandboxes and a
 * RAM/vCPU meter, as a single link to its detail page (where the full card,
 * storage, network and actions live).
 */
export function HostRow({
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
  const { t } = useTranslation("hosts");
  const state = hostConnectionState(host, now);
  const drainBadge = hostDrainBadge(host);
  const beat = toMs(host.lastHeartbeatAt);
  return (
    <li data-host-id={host.id} data-state={state} className="min-w-0">
      <Link
        to="/$lang/settings/hosts/$hostId"
        params={{ lang, hostId: host.id }}
        aria-label={t("row.open", { label: host.label })}
        className="flex min-h-11 min-w-0 items-center gap-3 rounded-xl border bg-card p-4 text-card-foreground transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 truncate font-medium">{host.label}</span>
            {host.slug !== host.label ? (
              <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
                {host.slug}
              </span>
            ) : null}
            <Pill tone={STATE_TONE[state]} data-host-status={state}>
              {t(`status.${state}`)}
            </Pill>
            {drainBadge ? (
              <Pill
                tone="border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400"
                data-host-drain={drainBadge}
              >
                {t(`drain.${drainBadge}`)}
              </Pill>
            ) : null}
          </div>
          <p className="flex min-w-0 flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span title={dateTimeTitle(beat, locale)}>
              {t("row.heartbeat", {
                age: beat == null ? t("heartbeat.never") : formatAge(beat, locale, now),
              })}
            </span>
            <span data-host-capacity="">
              {t("capacity.value", { live: host.liveSandboxCount })}
            </span>
          </p>
          <div className="grid min-w-0 gap-2 sm:grid-cols-2">
            <Meter
              kind="memory"
              label={t("row.ram")}
              used={host.capacity.memoryReservedMiB}
              total={host.capacity.memoryBudgetMiB}
              valueText={(used, total) => t("row.memoryUse", { used, total })}
            />
            <Meter
              kind="vcpu"
              label={t("row.vcpu")}
              hint={t("vmCapacity.vcpuBudgetHint", {
                multiplier: VM_SIZE_LIMITS.hostVcpuBudgetDefaultThreadsMultiplier,
                max: VM_SIZE_LIMITS.hostVcpuBudgetMax,
              })}
              used={host.capacity.vcpuReserved}
              total={host.capacity.vcpuBudget}
              valueText={(used, total) => t("row.vcpuUse", { used, total })}
            />
          </div>
        </div>
        <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      </Link>
    </li>
  );
}

function Meter({
  kind,
  label,
  used,
  total,
  valueText,
  hint,
}: {
  kind: string;
  label: string;
  /** What the number means, on hover (the vCPU budget is not CPU threads). */
  hint?: string;
  used: number | null;
  total: number | null;
  valueText: (used: number, total: number) => string;
}) {
  const { t } = useTranslation("hosts");
  if (used == null || total == null || total <= 0)
    return (
      <p data-host-meter={kind} title={hint} className="text-xs text-muted-foreground">
        {label}: {t("daemon.notReported")}
      </p>
    );
  const percent = Math.min(100, Math.round((used / total) * 100));
  const text = valueText(used, total);
  return (
    <div data-host-meter={kind} title={hint} className="flex min-w-0 flex-col gap-1">
      <div className="flex min-w-0 justify-between gap-2 text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="tabular-nums">{text}</span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={Math.min(used, total)}
        aria-valuetext={text}
        className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
      >
        <div
          className={cn("h-full rounded-full", used > total ? "bg-destructive" : "bg-primary")}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
