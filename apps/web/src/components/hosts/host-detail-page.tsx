import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { TextField } from "@wssp/ui/components/text-field";
import { Trans, useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { SkeletonList } from "@/components/skeleton-list";
import { TerminalPanel } from "@/components/terminal-panel";
import { useAuthSession } from "@/hooks/use-auth-session";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { useStatusClock } from "@/hooks/use-status-clock";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import { formatLeaseDuration, isUnlimitedLeaseEnd } from "@/lib/lease-duration";
import { isQueryAccessError } from "@/lib/query-access-error";
import { orpc } from "@/utils/orpc";
import { HostAgentAccess, QueuedHostCommands } from "./host-agent-access";
import { HostAuditList } from "./host-audit-list";
import { HostImageCacheCard } from "./host-image-cache-card";
import { HostsBackLink } from "./hosts-back-link";
import { HostCard } from "./hosts-page";

/** The detail page's sections, in page order; "On this page" links to each. */
const HOST_SECTIONS = ["overview", "capacity", "network", "access", "images"] as const;

export function HostDetailPage({ hostId, lang }: { hostId: string; lang: string }) {
  const { t } = useTranslation(["hosts", "terminal"]);
  const host = useQuery({
    ...orpc.sandboxHosts.getHost.queryOptions({ input: { id: hostId } }),
    refetchInterval: 5000,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [host.error]);
  const now = useStatusClock(host.dataUpdatedAt);
  if (host.isPending) return <SkeletonList count={3} />;
  if ((host.isError && isQueryAccessError(host.error)) || !host.data)
    return (
      <div className="flex min-w-0 flex-col gap-4">
        <HostsBackLink lang={lang} />
        <InlineRetry message={t("hosts:loadFailed")} onRetry={() => void host.refetch()} />
      </div>
    );
  const deleting = host.data.deletionRequestedAt != null;
  return (
    <div className="flex min-w-0 flex-col gap-6">
      {host.isError ? (
        <InlineRetry message={t("hosts:loadFailed")} onRetry={() => void host.refetch()} />
      ) : null}
      <PageHeader
        back={<HostsBackLink lang={lang} />}
        title={host.data.label}
        description={host.data.slug !== host.data.label ? host.data.slug : undefined}
      />
      <nav
        aria-label={t("hosts:sections.onThisPage")}
        data-host-toc=""
        className="flex min-w-0 flex-wrap items-center gap-x-1 gap-y-1 text-sm"
      >
        <span className="me-1 text-muted-foreground">{t("hosts:sections.onThisPage")}</span>
        {HOST_SECTIONS.filter((id) => !(deleting && id === "network")).map((id) => (
          <a
            key={id}
            href={`#host-${id}`}
            className="inline-flex min-h-11 items-center rounded-md px-2 font-medium underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {t(`hosts:sections.${id}`)}
          </a>
        ))}
      </nav>
      <ul aria-label={t("hosts:title")} className="min-w-0">
        <HostCard
          host={host.data}
          lang={lang}
          now={now}
          locale={lang}
          overviewExtra={
            host.data.lease ? (
              <HostLease lease={host.data.lease} draining={host.data.draining} lang={lang} />
            ) : null
          }
        />
      </ul>
      <section
        id="host-access"
        aria-labelledby="host-access-title"
        className="flex min-w-0 scroll-mt-4 flex-col gap-6"
      >
        <h2 id="host-access-title" className="text-base font-semibold">
          {t("hosts:sections.access")}
        </h2>
        <HostAgentAccess host={host.data} lang={lang} />
        <QueuedHostCommands hostId={hostId} lang={lang} policy={host.data.terminalPolicy} />
        <HostAuditList
          entries={host.data.recentAudit}
          lang={lang}
          onRetry={() => void host.refetch()}
        />
        <HostGuests hostId={hostId} lang={lang} />
        <div className="flex min-w-0 flex-col gap-3">
          <HostTerminal
            key={`${hostId}:${host.data.terminalPolicy?.policyRevision ?? "offline"}`}
            hostId={hostId}
            name={host.data.label}
            lang={lang}
            policy={host.data.terminalPolicy}
          />
        </div>
      </section>
      <div id="host-images" className="min-w-0 scroll-mt-4">
        <HostImageCacheCard hostId={hostId} lang={lang} />
      </div>
    </div>
  );
}
/**
 * Read-only host lease ceiling (set on the machine with the CLI, never from
 * the dashboard) and, while draining, when the host will be empty.
 */
function HostLease({
  lease,
  draining,
  lang,
}: {
  lease: {
    ceilingMs: number | null;
    drain: { live: number; unlimited: number; emptyBy: Date | string | null };
  };
  draining: boolean;
  lang: string;
}) {
  const { t } = useTranslation(["hosts"]);
  return (
    <section aria-labelledby="host-lease" className="flex min-w-0 flex-col gap-2">
      <h2 id="host-lease" className="text-base font-semibold">
        {t("hosts:lease.title")}
      </h2>
      <p data-host-lease-ceiling="">
        <Trans
          t={t}
          i18nKey="hosts:lease.ceiling"
          values={{
            value:
              lease.ceilingMs === null
                ? t("hosts:lease.unlimited")
                : formatLeaseDuration(lease.ceilingMs, lang),
          }}
          components={{ code: <code className="whitespace-nowrap" /> }}
        />
      </p>
      <p className="text-sm text-muted-foreground">{t("hosts:lease.ceilingHint")}</p>
      {draining ? (
        <p data-host-drain="">
          {lease.drain.unlimited > 0
            ? t("hosts:lease.drainNever", { count: lease.drain.unlimited })
            : lease.drain.live === 0 || lease.drain.emptyBy === null
              ? t("hosts:lease.drainEmpty")
              : t("hosts:lease.drainBy", {
                  date: formatDateTime(lease.drain.emptyBy, lang),
                })}
        </p>
      ) : null}
    </section>
  );
}

/** Run in a local login on the host; the only way host terminals turn on. */
const HOST_TERMINAL_ON_COMMAND = "wssp host config set-host-terminal on";

type Policy = {
  hostTerminal: boolean;
  requireHostTerminalTotp: boolean;
  policyRevision: number;
} | null;
export function HostTerminal({
  hostId,
  lang,
  policy,
  typeCommand,
  pretypeOnAttach,
  name,
  maximizable,
}: {
  /** False inside a dialog (see TerminalPanel). */
  maximizable?: boolean;
  hostId: string;
  /** The picker's label on phones (the host's label). */
  name?: string;
  lang: string;
  policy: Policy;
  typeCommand?: string;
  pretypeOnAttach?: boolean;
}) {
  const { t } = useTranslation(["terminal", "hosts", "common"]);
  const unavailable = useSensitiveAccessUnavailable();
  const { state: auth } = useAuthSession();
  const client = useQueryClient();
  const raise = useMutation({
    ...orpc.hostTerminals.raiseHostTerminalTotp.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => void client.invalidateQueries({ queryKey: orpc.sandboxHosts.getHost.key() }),
  });
  const form = useForm({
    defaultValues: { code: "" },
    validators: {
      onChange: z.object({ code: z.string().regex(/^\d{6}$/, t("terminal:host.invalidCode")) }),
    },
  });
  const code = useStore(form.store, (state) => state.values.code);
  const required = policy?.requireHostTerminalTotp !== false;
  const needsEnrollment =
    required && auth.status === "authenticated" && auth.session.user.twoFactorEnabled !== true;
  if (unavailable) return <p role="status">{t("terminal:host.refused")}</p>;
  // Turned off at the node: no code form or Attach that can only fail, just
  // how to turn it on (only at the node; the dashboard can never raise it).
  if (policy && !policy.hostTerminal)
    return (
      <section
        data-host-terminal-off=""
        aria-labelledby={`${hostId}-host-terminal-off`}
        className="flex min-w-0 flex-col gap-2 rounded-xl border p-4"
      >
        <h3 id={`${hostId}-host-terminal-off`} className="text-sm font-medium">
          {t("terminal:host.title")}
        </h3>
        <p className="text-sm">{t("terminal:host.offHint")}</p>
        <CodeSnippet code={HOST_TERMINAL_ON_COMMAND} copyLabel={t("terminal:host.copyOnCommand")} />
      </section>
    );
  return (
    <>
      <p>
        {t(
          policy
            ? policy.hostTerminal
              ? "terminal:host.enabled"
              : "terminal:host.disabled"
            : "terminal:host.offline",
        )}
      </p>
      <p>{t(required ? "terminal:host.required" : "terminal:host.optional")}</p>
      {policy && !required ? (
        <Button
          size="touch"
          disabled={raise.isPending}
          onClick={() => raise.mutate({ id: hostId })}
        >
          {t("terminal:host.raise")}
        </Button>
      ) : null}
      {raise.isPending ? <p role="status">{t("terminal:host.unconfirmed")}</p> : null}
      {raise.isSuccess ? (
        <p role="status">
          {t(raise.data.confirmed ? "terminal:host.confirmed" : "terminal:host.unconfirmed")}
        </p>
      ) : null}
      {raise.isError ? <p role="alert">{t("terminal:host.raiseFailed")}</p> : null}
      <TerminalPanel
        name={name}
        maximizable={maximizable}
        typeCommand={typeCommand}
        pretypeOnAttach={pretypeOnAttach}
        hostId={hostId}
        lang={lang}
        available={
          policy?.hostTerminal === true && !needsEnrollment && (!required || /^\d{6}$/.test(code))
        }
        unavailableMessage={
          policy === null
            ? t("terminal:host.offline")
            : policy.hostTerminal
              ? t(needsEnrollment ? "terminal:host.enrollment" : "terminal:host.fresh")
              : t("hosts:terminalOff")
        }
        attachCode={() => {
          const value = required ? form.getFieldValue("code") : undefined;
          form.reset();
          return value;
        }}
        onAttempt={() => form.reset()}
        beforeAttach={
          required ? (
            <div className="flex flex-col gap-3">
              <p>{t("terminal:host.fresh")}</p>
              <form.Field name="code">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("terminal:host.code")}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    type="password"
                    maxLength={6}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
              {/* Only someone without an authenticator is sent to set one up. */}
              {needsEnrollment ? (
                <Link
                  to="/$lang/settings/security"
                  params={{ lang }}
                  data-host-terminal-enroll=""
                  className="inline-flex min-h-11 items-center underline"
                >
                  {t("terminal:host.enroll")}
                </Link>
              ) : null}
            </div>
          ) : (
            <p>{t("terminal:host.optional")}</p>
          )
        }
      />
    </>
  );
}

function HostGuests({ hostId, lang }: { hostId: string; lang: string }) {
  const { t } = useTranslation("hosts");
  const guests = useInfiniteQuery({
    ...orpc.sandboxHosts.listHostGuests.infiniteOptions({
      input: (cursor: string | undefined) => ({ id: hostId, cursor, limit: 20 }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (page) => page.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <section aria-labelledby="host-guests-title" className="flex min-w-0 flex-col gap-2">
      <h3 id="host-guests-title" className="font-semibold">
        {t("hosts:sharing.foreignGuests")}
      </h3>
      {guests.data?.pages[0]?.items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("hosts:sharing.noForeignGuests")}</p>
      ) : null}
      <ul className="flex min-w-0 flex-col gap-2">
        {guests.data?.pages
          .flatMap((p) => p.items)
          .map((guest) => (
            <li key={guest.id} className="break-all rounded-lg border p-3 text-sm">
              {guest.id} · {t(`hosts:sharing.purpose.${guest.purpose}`)} ·{" "}
              {t(`hosts:guestStates.${guest.state}`)} ·{" "}
              {t("hosts:sharing.guestAllocation", {
                memory: guest.memoryMiB,
                vcpu: guest.cpuCount,
                disk: guest.diskGiB,
              })}{" "}
              ·{" "}
              {t("hosts:sharing.expires", {
                date:
                  guest.leaseExpiresAt && !isUnlimitedLeaseEnd(guest.leaseExpiresAt)
                    ? formatDateTime(guest.leaseExpiresAt, lang)
                    : t("hosts:sharing.unlimited"),
              })}
            </li>
          ))}
      </ul>
      {guests.isError ? (
        <InlineRetry message={t("hosts:loadFailed")} onRetry={() => void guests.refetch()} />
      ) : null}
      <LoadMore
        hasNextPage={guests.hasNextPage}
        isFetchingNextPage={guests.isFetchingNextPage}
        onLoadMore={() => void guests.fetchNextPage()}
      />
    </section>
  );
}
