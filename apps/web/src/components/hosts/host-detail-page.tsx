import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { TextField } from "@wssp/ui/components/text-field";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { SkeletonList } from "@/components/skeleton-list";
import { TerminalPanel } from "@/components/terminal-panel";
import { useAuthSession } from "@/hooks/use-auth-session";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatLeaseDuration, isUnlimitedLeaseEnd } from "@/lib/lease-duration";
import { isQueryAccessError } from "@/lib/query-access-error";
import { orpc } from "@/utils/orpc";
import { HostAgentAccess, QueuedHostCommands } from "./host-agent-access";
import { HostAuditList } from "./host-audit-list";
import { HostImageCacheCard } from "./host-image-cache-card";
import { HostCard } from "./hosts-page";

export function HostDetailPage({ hostId, lang }: { hostId: string; lang: string }) {
  const { t } = useTranslation(["hosts", "terminal"]);
  const host = useQuery({
    ...orpc.sandboxHosts.getHost.queryOptions({ input: { id: hostId } }),
    refetchInterval: 5000,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [host.error]);
  if (host.isPending) return <SkeletonList count={3} />;
  if ((host.isError && isQueryAccessError(host.error)) || !host.data)
    return <InlineRetry message={t("hosts:loadFailed")} onRetry={() => void host.refetch()} />;
  return (
    <div className="flex min-w-0 flex-col gap-6">
      {host.isError ? (
        <InlineRetry message={t("hosts:loadFailed")} onRetry={() => void host.refetch()} />
      ) : null}
      <PageHeader title={host.data.label} description={host.data.slug} />
      <ul aria-label={t("hosts:title")}>
        <HostCard host={host.data} lang={lang} now={Date.now()} locale={lang} />
      </ul>
      {host.data.lease ? (
        <HostLease lease={host.data.lease} draining={host.data.draining} lang={lang} />
      ) : null}
      <HostAgentAccess host={host.data} lang={lang} />
      <QueuedHostCommands hostId={hostId} lang={lang} policy={host.data.terminalPolicy} />
      <HostAuditList
        entries={host.data.recentAudit}
        lang={lang}
        onRetry={() => void host.refetch()}
      />
      <HostImageCacheCard hostId={hostId} lang={lang} />
      <HostGuests hostId={hostId} lang={lang} />
      <HostTerminal
        key={`${hostId}:${host.data.terminalPolicy?.policyRevision ?? "offline"}`}
        hostId={hostId}
        lang={lang}
        policy={host.data.terminalPolicy}
      />
      <Link
        to="/$lang/settings/hosts"
        params={{ lang }}
        className="inline-flex min-h-11 items-center underline"
      >
        {t("hosts:title")}
      </Link>
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
        {t("hosts:lease.ceiling", {
          value:
            lease.ceilingMs === null
              ? t("hosts:lease.unlimited")
              : formatLeaseDuration(lease.ceilingMs, lang),
        })}
      </p>
      <p className="text-sm text-muted-foreground">{t("hosts:lease.ceilingHint")}</p>
      {draining ? (
        <p data-host-drain="">
          {lease.drain.unlimited > 0
            ? t("hosts:lease.drainNever", { count: lease.drain.unlimited })
            : lease.drain.live === 0 || lease.drain.emptyBy === null
              ? t("hosts:lease.drainEmpty")
              : t("hosts:lease.drainBy", {
                  date: new Date(lease.drain.emptyBy).toLocaleString(lang),
                })}
        </p>
      ) : null}
    </section>
  );
}

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
}: {
  hostId: string;
  lang: string;
  policy: Policy;
  typeCommand?: string;
  pretypeOnAttach?: boolean;
}) {
  const { t } = useTranslation(["terminal", "common"]);
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
        typeCommand={typeCommand}
        pretypeOnAttach={pretypeOnAttach}
        hostId={hostId}
        lang={lang}
        available={
          policy?.hostTerminal === true && !needsEnrollment && (!required || /^\d{6}$/.test(code))
        }
        unavailableMessage={
          policy?.hostTerminal
            ? t(needsEnrollment ? "terminal:host.enrollment" : "terminal:host.fresh")
            : undefined
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
              <Link
                to="/$lang/settings/security"
                params={{ lang }}
                className="inline-flex min-h-11 items-center underline"
              >
                {t("terminal:host.enroll")}
              </Link>
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
    <section>
      <h2>{t("hosts:sharing.foreignGuests")}</h2>
      <ul>
        {guests.data?.pages
          .flatMap((p) => p.items)
          .map((guest) => (
            <li key={guest.id} className="break-all border p-3">
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
                    ? new Date(guest.leaseExpiresAt).toLocaleString(lang)
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
