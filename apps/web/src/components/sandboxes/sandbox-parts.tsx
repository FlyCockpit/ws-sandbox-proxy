import type { AppRouterClient } from "@wssp/api/routers/index";
import { Badge } from "@wssp/ui/components/badge";
import { Label } from "@wssp/ui/components/label";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import { SelectItem } from "@wssp/ui/components/select";
import { cn } from "@wssp/ui/lib/utils";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { ResourceIdentity } from "@/components/resource-identity";
import { dateTimeTitle, formatDateTime } from "@/lib/format-date-time";

import { hostConnectionState } from "@/lib/host-status";
import { formatLeaseDuration } from "@/lib/lease-duration";
import {
  type DiskView,
  isOperationActive,
  KEEP_LIFETIME,
  lifetimeOptions,
  type SandboxPhase,
  type SandboxState,
  sandboxPhase,
} from "@/lib/sandbox-rules";
import type { SandboxDisplayOverride } from "@/lib/sandbox-status";
import { formatRelativeTime } from "@/utils/relative-time";

/** Shared pieces of the Sandboxes list and detail pages (C47). */

export type SandboxView = Awaited<ReturnType<AppRouterClient["sandboxes"]["getSandbox"]>>;
export type SandboxListItem = Awaited<
  ReturnType<AppRouterClient["sandboxes"]["list"]>
>["items"][number];

const PHASE_TONE: Record<SandboxPhase, string> = {
  waiting: "border-violet-600/40 bg-violet-600/10 text-violet-700 dark:text-violet-400",
  ready: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  starting: "border-sky-600/40 bg-sky-600/10 text-sky-700 dark:text-sky-400",
  stopping: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  stopped: "border-border bg-muted text-muted-foreground",
  deleted: "border-border bg-muted text-muted-foreground",
  problem: "border-destructive/40 bg-destructive/10 text-destructive",
};

/**
 * The sandbox's state. `display` names a request in flight that the stored
 * state does not show (a start of a stopped sandbox, a destroy that the
 * server stores as stopping); `data-sandbox-state` stays the server's state.
 */
export function StatePill({
  state,
  display,
}: {
  state: SandboxState;
  display?: SandboxDisplayOverride | null;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const tone = display
    ? PHASE_TONE[display === "DESTROYING" ? "stopping" : "starting"]
    : PHASE_TONE[sandboxPhase(state)];
  return (
    <Badge
      data-sandbox-state={state}
      data-sandbox-display={display ?? undefined}
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {display ? t(`sandboxes:displayState.${display}`) : t(`sandboxes:state.${state}`)}
    </Badge>
  );
}

/** "Alpha (alpha) · Offline" — the host and its live connection state, or that it has none
 * (a create waiting for capacity has never had one). */
export function HostText({
  host,
  now,
  waiting = false,
}: {
  host: SandboxView["host"];
  now: number;
  waiting?: boolean;
}) {
  const { t } = useTranslation(["sandboxes", "hosts"]);
  if (!host)
    return <>{t(waiting ? "sandboxes:fields.noHostWaiting" : "sandboxes:fields.noHost")}</>;
  return (
    <>
      <ResourceIdentity label={host.label} slug={host.slug} />
      {" · "}
      {t(`hosts:status.${hostConnectionState(host, now)}`)}
    </>
  );
}

/** "Ubuntu" or "Ubuntu (archived)". */
export function TemplateText({ template }: { template: SandboxView["template"] }) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <>
      {template.retiredAt == null
        ? template.label
        : t("sandboxes:templateArchived", { label: template.label })}
    </>
  );
}

/** The latest lifecycle receipt as the server reported it; QUEUED and UNKNOWN_OUTCOME stay visible. */
export function ReceiptLine({
  receipt,
  locale,
  now,
  compact = false,
}: {
  receipt: SandboxView["lastLifecycleOperation"];
  locale: string;
  now: number;
  compact?: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  if (!receipt) {
    return compact ? null : (
      <p className="text-sm text-muted-foreground">{t("sandboxes:receipt.none")}</p>
    );
  }
  // In a list a finished operation is noise ("Stop: Done" on every card);
  // only one in flight or one that went wrong is worth a line there.
  if (compact && receipt.state === "SUCCEEDED") return null;
  const created = new Date(receipt.createdAt).getTime();
  const hint =
    receipt.state === "QUEUED" || receipt.state === "UNKNOWN_OUTCOME" || receipt.state === "FAILED"
      ? t(`sandboxes:receipt.hint.${receipt.state}`)
      : null;
  return (
    <div
      data-receipt-state={receipt.state}
      data-receipt-kind={receipt.kind}
      className={cn(
        "flex min-w-0 flex-col gap-0.5 text-sm",
        receipt.state === "UNKNOWN_OUTCOME" || receipt.state === "FAILED"
          ? "text-destructive"
          : isOperationActive(receipt.state)
            ? "text-foreground"
            : "text-muted-foreground",
      )}
    >
      <p>
        {t("sandboxes:receipt.line", {
          kind: t(`sandboxes:receipt.kind.${receipt.kind}`),
          state: t(`sandboxes:receipt.state.${receipt.state}`),
        })}
        {Number.isFinite(created) ? (
          <span className="text-muted-foreground" title={dateTimeTitle(created, locale)}>
            {" · "}
            {t("sandboxes:receipt.since", { when: formatRelativeTime(created, locale, now) })}
          </span>
        ) : null}
        {receipt.errorCode ? (
          <span className="font-mono text-xs"> ({receipt.errorCode})</span>
        ) : null}
      </p>
      {receipt.progressPhase && isOperationActive(receipt.state) ? (
        <p data-receipt-phase={receipt.progressPhase} className="text-xs text-muted-foreground">
          {t(`sandboxes:capture.phase.${receipt.progressPhase}`)}
        </p>
      ) : null}
      {hint && !compact ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

const DISK_TONE: Record<DiskView["location"], string> = {
  host: "border-border bg-muted text-muted-foreground",
  host_and_store: "border-sky-600/40 bg-sky-600/10 text-sky-700 dark:text-sky-400",
  store: "border-violet-600/40 bg-violet-600/10 text-violet-700 dark:text-violet-400",
};

/**
 * Where the root disk lives (disk offload): on its host, on its host with a
 * stored copy, or only in the image store. Nothing while it has no disk.
 */
export function DiskLocationBadge({ disk }: { disk: DiskView | null }) {
  const { t } = useTranslation(["sandboxes"]);
  if (!disk) return null;
  return (
    <Badge
      data-disk-location={disk.location}
      title={t(`sandboxes:disk.locationHint.${disk.location}`)}
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
        DISK_TONE[disk.location],
      )}
    >
      {t(`sandboxes:disk.location.${disk.location}`)}
    </Badge>
  );
}

/** Lifetime select plus the expiry action (stop keeps the disk, destroy deletes it). */
export function LifetimeFields({
  maxTimeoutMs,
  allowUnlimited = false,
  minutes,
  onMinutes,
  onExpire,
  onOnExpire,
  keepTimeoutMs,
  keepOverLimit = false,
  disabled,
  hint,
  error,
}: {
  maxTimeoutMs: number;
  /** The target allows "no time limit" (timeoutMs 0). */
  allowUnlimited?: boolean;
  minutes: string;
  onMinutes: (value: string) => void;
  onExpire: "stop" | "destroy";
  onOnExpire?: (value: "stop" | "destroy") => void;
  /**
   * A start's remembered lease (`0` is no time limit): offered first as
   * "keep its lifetime" (value `KEEP_LIFETIME`), which sends no timeout.
   */
  keepTimeoutMs?: number;
  /** The remembered lease is above the current limit: listed, disabled, with the reason. */
  keepOverLimit?: boolean;
  disabled?: boolean;
  /** Replaces the default hint (Create states its own default). */
  hint?: string;
  /** An inline problem with the chosen lifetime (marks the field invalid). */
  error?: string | null;
}) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const lifetimeId = useId();
  const hintId = useId();
  const errorId = useId();
  const radioName = useId();
  const expireLabelId = useId();
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className="flex min-w-0 flex-col gap-2">
        <Label htmlFor={lifetimeId}>{t("sandboxes:lifetime.field")}</Label>
        <FormSelect
          id={lifetimeId}
          autoComplete="off"
          value={minutes}
          disabled={disabled}
          aria-describedby={error ? `${hintId} ${errorId}` : hintId}
          aria-invalid={error ? true : undefined}
          onValueChange={(value) => onMinutes(value)}
        >
          {keepTimeoutMs === undefined ? null : (
            <SelectItem
              value={KEEP_LIFETIME}
              disabled={keepOverLimit}
              data-keep-over-limit={keepOverLimit ? "" : undefined}
            >
              {keepTimeoutMs === 0
                ? t(
                    keepOverLimit
                      ? "sandboxes:lifetime.keepUnlimitedOverLimit"
                      : "sandboxes:lifetime.keepUnlimited",
                  )
                : t(
                    keepOverLimit ? "sandboxes:lifetime.keepOverLimit" : "sandboxes:lifetime.keep",
                    {
                      lifetime: formatLeaseDuration(keepTimeoutMs, i18n.language),
                      action: t(`sandboxes:expiry.action.${onExpire}`),
                    },
                  )}
            </SelectItem>
          )}
          {lifetimeOptions(maxTimeoutMs, allowUnlimited).map((value) => (
            <SelectItem key={value} value={String(value)}>
              {value === 0
                ? t("sandboxes:lifetime.unlimited")
                : value < 60
                  ? t("sandboxes:lifetime.minutes", { count: value })
                  : value < 2880
                    ? t("sandboxes:lifetime.hours", { count: value / 60 })
                    : t("sandboxes:lifetime.days", { count: value / 1440 })}
            </SelectItem>
          ))}
        </FormSelect>
        <p id={hintId} className="text-xs text-muted-foreground">
          {hint ??
            t(
              keepTimeoutMs === undefined
                ? "sandboxes:lifetime.hint"
                : keepOverLimit
                  ? "sandboxes:lifetime.keepOverLimitHint"
                  : "sandboxes:lifetime.keepHint",
            )}
        </p>
        {error ? (
          <p id={errorId} role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
      </div>
      {onOnExpire && (
        <div className="flex min-w-0 flex-col gap-1">
          <p id={expireLabelId} className="mb-1 text-sm font-medium">
            {t("sandboxes:lifetime.onExpire")}
          </p>
          <RadioGroup
            aria-labelledby={expireLabelId}
            name={radioName}
            value={onExpire}
            disabled={disabled}
            onValueChange={(value: "stop" | "destroy") => onOnExpire(value)}
          >
            {(["stop", "destroy"] as const).map((value) => (
              <label key={value} className="flex min-h-11 min-w-0 items-center gap-3 text-sm">
                <RadioGroupItem value={value} />
                <span>{t(`sandboxes:lifetime.${value}Option`)}</span>
              </label>
            ))}
          </RadioGroup>
        </div>
      )}
    </div>
  );
}

/** Queue position, deadline and last blocker of a create waiting for capacity. */
export function CapacityWaitLine({
  wait,
  lang,
}: {
  wait: {
    position: number;
    deadlineAt: string | null;
    blocker: string | null;
  };
  lang: string;
}) {
  const { t } = useTranslation(["sandboxes", "hosts"]);
  return (
    <p data-capacity-wait="" className="text-sm text-muted-foreground">
      {t("sandboxes:capacityWait.line", {
        position: wait.position,
        deadline: wait.deadlineAt
          ? formatDateTime(wait.deadlineAt, lang)
          : t("sandboxes:capacityWait.noDeadline"),
        blocker: wait.blocker ? t(`hosts:poolCapacity.blocker.${wait.blocker}`) : "—",
      })}
    </p>
  );
}
