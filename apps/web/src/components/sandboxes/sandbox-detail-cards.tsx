import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { CopyableId } from "@/components/copyable-id";
import { InlineRetry } from "@/components/inline-retry";
import { type SandboxView, TemplateText } from "@/components/sandboxes/sandbox-parts";
import { SkeletonList } from "@/components/skeleton-list";
import { translateText } from "@/i18n/translate-text";
import { dateTimeTitle } from "@/lib/format-date-time";
import { isUnlimitedLeaseEnd, type LeaseTerm, leaseView, sandboxPhase } from "@/lib/sandbox-rules";
import { formatSpan, runningSinceMs } from "@/lib/sandbox-status";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * The detail page's read-only cards (C47): egress, root in the guest, the
 * template revision, the lifetime's server/requested/host terms and usage.
 */

export function Card({ title, id, children }: { title: string; id: string; children: ReactNode }) {
  return (
    <section
      aria-labelledby={id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h3 id={id} className="font-heading text-sm font-semibold">
        {title}
      </h3>
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
export function EgressCard({
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
export function GuestRootCard({
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

export function Field({
  label,
  wide,
  children,
}: {
  label: string;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={wide ? "min-w-0 sm:col-span-2" : "min-w-0"}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** The revision the sandbox started from, read through the session-only `getTemplate`. */
export function TemplateCard({
  template,
  lang,
}: {
  template: SandboxView["template"];
  lang: string;
}) {
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

export function LifetimeCard({
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
  // A stopped VM has no running lifetime: a term still ahead is never
  // "in 4 hours, then stop" (only the history of one that ended is shown).
  const stopped = sandboxPhase(sandbox.state) === "stopped";
  const describe = (term: LeaseTerm | null) =>
    term == null
      ? t("sandboxes:expiry.none")
      : stopped && !term.unlimited && term.expiresAt > now
        ? t("sandboxes:lifetime.notRunning")
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
            {stopped
              ? t("sandboxes:lifetime.stopped")
              : startsAtReady
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
export function IdRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <CopyableId value={value} label={label} />
    </div>
  );
}

/** "0.5", "2", "1.25": GiB from MiB without trailing zeros. */
function gib(memoryMiB: number, locale: string): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(memoryMiB / 1024);
}

/**
 * Usage (design review #11): what this sandbox has reserved on its host
 * (allocation) and how long it has run since its last start, both from the
 * server's read. The server measures nothing per sandbox yet, so measured use
 * says so instead of showing a number it does not have.
 */
export function UsageCard({
  sandbox,
  locale,
  now,
}: {
  sandbox: SandboxView;
  locale: string;
  now: number;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const since = runningSinceMs(sandbox);
  const running = sandbox.state === "READY";
  return (
    <Card title={t("sandboxes:usage.title")} id="sandbox-usage">
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <Field label={t("sandboxes:usage.allocated")} wide>
          <span data-sandbox-allocation="" className="tabular-nums">
            {t("sandboxes:usage.allocation", {
              cpuCount: sandbox.cpuCount,
              memoryGiB: gib(sandbox.memoryMiB, locale),
              diskGiB: sandbox.diskGiB,
            })}
          </span>
          <span className="block text-xs text-muted-foreground">
            {t("sandboxes:usage.allocatedHint")}
          </span>
        </Field>
        <Field label={t("sandboxes:usage.running")}>
          <span data-sandbox-running="" title={since ? dateTimeTitle(since, locale) : undefined}>
            {!running
              ? t("sandboxes:usage.notRunning")
              : since !== null
                ? t("sandboxes:usage.runningFor", { span: formatSpan(now - since, locale) })
                : t("sandboxes:usage.runningUnknown")}
          </span>
        </Field>
        <Field label={t("sandboxes:usage.measured")}>
          <span data-sandbox-measured="" className="text-muted-foreground">
            {t("sandboxes:usage.measuredNone")}
          </span>
        </Field>
      </dl>
    </Card>
  );
}
