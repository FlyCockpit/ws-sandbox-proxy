import { Button } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { Check, Circle, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import {
  DiskLocationBadge,
  type SandboxView,
  StatePill,
} from "@/components/sandboxes/sandbox-parts";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { dateTimeTitle } from "@/lib/format-date-time";
import { formatLeaseDuration } from "@/lib/lease-duration";
import { sandboxPhase } from "@/lib/sandbox-rules";
import {
  finiteDeadline,
  formatClock,
  formatSpan,
  provisionProgress,
  sandboxDisplayOverride,
} from "@/lib/sandbox-status";

/** Sections of the detail page, in page order; the "On this page" index links them. */
export const SANDBOX_SECTIONS = [
  "overview",
  "terminal",
  "previews",
  "files",
  "configuration",
  "activity",
] as const;
export type SandboxSection = (typeof SANDBOX_SECTIONS)[number];

/** The element id of a detail page section (a `#` target). */
export function sectionId(section: SandboxSection): string {
  return `sandbox-section-${section}`;
}

/**
 * The header summary under the title (design review #7): the state (with
 * Starting / Restoring / Destroying while a request moves it), one line of
 * what it means, the create's step progress with elapsed time, and the
 * lifetime as an absolute time with what is left and a Renew action.
 */
export function SandboxSummary({
  sandbox,
  locale,
  onRenew,
  canRenew,
}: {
  sandbox: SandboxView;
  locale: string;
  onRenew: () => void;
  canRenew: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const display = sandboxDisplayOverride(sandbox);
  const phase = sandboxPhase(sandbox.state);
  const hint = display
    ? t(`sandboxes:displayHint.${display}`)
    : phase === "ready"
      ? null
      : t(`sandboxes:stateHint.${phase}`);
  return (
    <div data-sandbox-summary="" className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <StatePill state={sandbox.state} display={display} />
        <DiskLocationBadge disk={sandbox.disk} />
        {hint ? <p className="min-w-0 text-sm text-muted-foreground">{hint}</p> : null}
      </div>
      <ProvisionSteps sandbox={sandbox} locale={locale} />
      <LifetimeSummary sandbox={sandbox} locale={locale} onRenew={onRenew} canRenew={canRenew} />
    </div>
  );
}

function ProvisionSteps({ sandbox, locale }: { sandbox: SandboxView; locale: string }) {
  const { t } = useTranslation(["sandboxes"]);
  const now = Date.now();
  const progress = provisionProgress(sandbox);
  // A one-second clock for the elapsed time, only while something is starting.
  useRerenderAt(progress ? now + 1000 : null);
  if (!progress) return null;
  const elapsed = Number.isFinite(progress.sinceMs)
    ? formatSpan(now - progress.sinceMs, locale, { seconds: true })
    : null;
  return (
    <div data-provision-progress="" className="flex min-w-0 flex-col gap-1">
      <ol
        aria-label={t("sandboxes:progress.label")}
        className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-sm"
      >
        {progress.steps.map(({ step, status }) => (
          <li
            key={step}
            data-step={step}
            data-step-status={status}
            aria-current={status === "current" ? "step" : undefined}
            className={cn(
              "inline-flex min-w-0 items-center gap-1.5",
              status === "todo" ? "text-muted-foreground" : "text-foreground",
              status === "current" && "font-medium",
            )}
          >
            {status === "done" ? (
              <Check aria-hidden="true" className="size-4 text-emerald-600" />
            ) : status === "current" ? (
              <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
            ) : (
              <Circle aria-hidden="true" className="size-3" />
            )}
            <span>{t(`sandboxes:progress.${step}`)}</span>
            <span className="sr-only">{t(`sandboxes:progress.status.${status}`)}</span>
          </li>
        ))}
      </ol>
      <p className="text-xs text-muted-foreground">
        {elapsed
          ? t("sandboxes:progress.elapsed", { time: elapsed })
          : t("sandboxes:progress.usually")}
      </p>
    </div>
  );
}

/**
 * "Stops at 03:50 (in 3 h 59 min) · Renew". A stopped sandbox has no running
 * lifetime: it says what a start gives it instead of a deadline it will not
 * meet. Ticks once a minute so the time left stays honest.
 */
function LifetimeSummary({
  sandbox,
  locale,
  onRenew,
  canRenew,
}: {
  sandbox: SandboxView;
  locale: string;
  onRenew: () => void;
  canRenew: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const now = Date.now();
  const deadline = finiteDeadline(sandbox.leaseExpiresAt);
  const live = ["READY", "UNREACHABLE", "RECOVERED"].includes(sandbox.state);
  useRerenderAt(live && deadline !== null ? now + 60_000 - (now % 60_000) : null);
  const phase = sandboxPhase(sandbox.state);
  const display = sandboxDisplayOverride(sandbox);
  let line: string | null = null;
  // Deleted, destroying or waiting for capacity: nothing runs (the Lifetime
  // card says when a waiting create's lifetime starts).
  if (["DELETED", "WAITING_FOR_CAPACITY"].includes(sandbox.state) || display === "DESTROYING")
    return null;
  else if (display === "STARTING" || display === "RESTORING")
    line = t("sandboxes:lifetime.startsAtReady");
  else if (phase === "stopped")
    line =
      sandbox.rememberedLeaseTimeoutMs === 0
        ? t("sandboxes:summary.stoppedUnlimited")
        : t("sandboxes:summary.stopped", {
            lifetime: formatLeaseDuration(sandbox.rememberedLeaseTimeoutMs, locale),
          });
  else if (sandbox.leasePendingReady === true || phase === "starting")
    line = t("sandboxes:lifetime.startsAtReady");
  else if (sandbox.leaseExpiresAt == null) line = t("sandboxes:expiry.none");
  else if (deadline === null) line = t("sandboxes:expiry.unlimited");
  if (line === null && (deadline === null || !live)) return null;
  return (
    <p data-lifetime-summary="" className="flex min-w-0 flex-wrap items-center gap-x-2 text-sm">
      <span className="text-muted-foreground">{t("sandboxes:summary.label")}</span>
      {line !== null ? (
        <span>{line}</span>
      ) : deadline !== null ? (
        <span title={dateTimeTitle(deadline, locale)}>
          {t(
            sandbox.leaseExpireAction === "DESTROY"
              ? "sandboxes:summary.destroysAt"
              : "sandboxes:summary.stopsAt",
            { time: formatClock(deadline, locale, now) },
          )}{" "}
          <span className="text-muted-foreground">
            (
            {deadline > now
              ? t("sandboxes:summary.left", { span: formatSpan(deadline - now, locale) })
              : t("sandboxes:summary.endingNow")}
            )
          </span>
        </span>
      ) : null}
      {canRenew ? (
        <Button
          type="button"
          variant="link"
          size="touch"
          data-summary-renew=""
          aria-label={t("sandboxes:renew.action")}
          className="h-auto min-h-11 px-1"
          onClick={onRenew}
        >
          {t("sandboxes:summary.renew")}
        </Button>
      ) : null}
    </p>
  );
}

/**
 * "On this page": in-page `#` links (the root hash-target contract scrolls
 * <main> and keeps history); no tabs, so every section stays on the one page
 * scroller and nothing is hidden.
 */
export function SandboxPageIndex({ sections }: { sections: readonly SandboxSection[] }) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <nav aria-label={t("sandboxes:sections.label")} data-sandbox-index="" className="min-w-0">
      <ul className="flex min-w-0 flex-wrap gap-x-1 gap-y-1 text-sm">
        {sections.map((section) => (
          <li key={section}>
            <a
              href={`#${sectionId(section)}`}
              className="inline-flex min-h-11 items-center rounded-md px-2 text-muted-foreground underline-offset-4 hover:bg-muted hover:text-foreground hover:underline"
            >
              {t(`sandboxes:sections.${section}`)}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/**
 * A page section and its `#` target, which takes focus when an index link
 * lands on it. `titled={false}` for a section whose one card already carries
 * the same heading (Terminal, Files, Ports & previews): no duplicate heading.
 */
export function SandboxSectionBlock({
  section,
  titled = true,
  children,
}: {
  section: SandboxSection;
  titled?: boolean;
  children: ReactNode;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const id = sectionId(section);
  return (
    <section
      id={id}
      tabIndex={-1}
      aria-labelledby={titled ? `${id}-heading` : undefined}
      data-sandbox-section={section}
      className="flex min-w-0 scroll-mt-2 flex-col gap-4 outline-none"
    >
      {titled ? (
        <h2 id={`${id}-heading`} className="font-heading text-base font-semibold">
          {t(`sandboxes:sections.${section}`)}
        </h2>
      ) : null}
      {children}
    </section>
  );
}
