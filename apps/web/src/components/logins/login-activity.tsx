import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Badge } from "@wssp/ui/components/badge";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { LoadMore } from "@/components/load-more";
import type { LoginItem } from "@/components/logins/logins-shared";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { dateTimeTitle } from "@/lib/format-date-time";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Event types the dashboard labels (`logins:events.type.*`). An unknown type
 * (a newer server) shows its raw name rather than a wrong label.
 */
export const CREDENTIAL_EVENT_TYPES = [
  "created",
  "deleted",
  "settings_changed",
  "policy_changed",
  "repinned",
  "account_created",
  "account_deleted",
  "instance_created",
  "instance_deleted",
  "value_written",
  "capture_rejected",
  "capture_failed",
  "capture_lost",
  "recovery_required",
  "needs_login",
  "force_released",
  "checkpoint_promoted",
  "rejected_discarded",
  "login_started",
  "login_saved",
  "login_failed",
  "login_cancelled",
] as const;
const KNOWN_EVENTS: ReadonlySet<string> = new Set(CREDENTIAL_EVENT_TYPES);

/** The label key for an event type, or null for a type this build does not know. */
export function eventTypeKey(type: string): string | null {
  return KNOWN_EVENTS.has(type) ? `logins:events.type.${type}` : null;
}

/**
 * Login sessions still holding an instance (PROVISIONING, READY, SAVING,
 * FAILED), so a reload or a closed tab can return to the session page.
 * There are at most a couple per owner; this login's are shown.
 */
export function OpenLoginSessions({ lang, login }: { lang: string; login: LoginItem }) {
  const { t } = useTranslation(["logins"]);
  const sessions = useQuery({
    ...orpc.logins.listLoginSessions.queryOptions({ input: { open: true, limit: 20 } }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [sessions.error]);
  const mine = (sessions.data?.items ?? []).filter((item) => item.credentialId === login.id);
  if (mine.length === 0) return null;
  return (
    <section
      aria-labelledby="open-login-sessions"
      className="flex min-w-0 flex-col gap-2 rounded-xl border border-amber-500/50 p-4"
    >
      <h2 id="open-login-sessions" className="font-medium">
        {t("logins:session.openHeading")}
      </h2>
      <ul className="flex min-w-0 flex-col gap-1">
        {mine.map((item) => (
          <li key={item.id} className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
            <Badge variant="outline">{t(`logins:session.state.${item.state}`)}</Badge>
            <Link
              to="/$lang/settings/logins/sessions/$sessionId"
              params={{ lang, sessionId: item.id }}
              className="inline-flex min-h-11 items-center underline underline-offset-4"
            >
              {t("logins:session.resume")}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** The login's metadata-only activity log, newest first. */
export function LoginActivity({ lang, login }: { lang: string; login: LoginItem }) {
  const { t, i18n } = useTranslation(["logins", "dashboard"]);
  const events = useInfiniteQuery({
    ...orpc.logins.listEvents.infiniteOptions({
      input: (cursor: string | undefined) => ({
        credentialId: login.id,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [events.error]);
  const rows = events.data?.pages.flatMap((page) => page.items);
  const now = Date.now();
  return (
    <section aria-labelledby="login-activity" className="flex min-w-0 flex-col gap-3">
      <h2 id="login-activity" className="font-heading text-lg font-semibold">
        {t("logins:events.heading")}
      </h2>
      <QueryBoundary
        query={{
          data: rows,
          isPending: events.isPending,
          isError: events.isError,
          error: events.error,
          refetch: events.refetch,
        }}
        skeleton={<SkeletonList count={2} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={<p className="text-sm text-muted-foreground">{t("logins:events.empty")}</p>}
      >
        {(items) => (
          <>
            <ul
              aria-label={t("logins:events.label")}
              className="flex min-w-0 flex-col divide-y rounded-lg border text-sm"
            >
              {items.map((event) => {
                const key = eventTypeKey(event.type);
                return (
                  <li
                    key={event.id}
                    data-event-type={event.type}
                    className="flex min-w-0 flex-wrap items-baseline justify-between gap-2 px-3 py-2"
                  >
                    <span className="min-w-0 break-words">
                      {key ? t(key) : event.type}
                      {event.reason ? (
                        <span className="text-muted-foreground">
                          {" · "}
                          {event.reason}
                        </span>
                      ) : null}
                    </span>
                    <time
                      dateTime={event.at}
                      title={dateTimeTitle(event.at, i18n.language)}
                      className="text-muted-foreground"
                    >
                      {formatRelativeTime(Date.parse(event.at), i18n.language, now)}
                    </time>
                  </li>
                );
              })}
            </ul>
            <LoadMore
              hasNextPage={events.hasNextPage}
              isFetchingNextPage={events.isFetchingNextPage}
              onLoadMore={() => void events.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
    </section>
  );
}
