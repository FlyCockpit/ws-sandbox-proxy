import { useInfiniteQuery } from "@tanstack/react-query";
import { Badge } from "@wssp/ui/components/badge";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { LoadMore } from "@/components/load-more";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { dateTimeTitle } from "@/lib/format-date-time";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * The sandbox detail "Recent connections" panel (wssp-ssh §10): the owner's
 * CLI connections to this sandbox, newest first, one bounded page at a time.
 * Metadata only (key, origin, times, end reason, channel counts, bytes):
 * the server never records what ran.
 */

const KNOWN_INTENTS = new Set([
  "client",
  "detached",
  "backpressure",
  "revoked",
  "superseded",
  "protocol_violation",
  "host_disconnected",
  "expired",
  "sandbox_stopped",
  "sandbox_destroyed",
  "lifecycle_unconfirmed",
  "shutdown",
]);

/** The translation key of a close intent (an unknown one reads "other"). */
export function connectionIntentKey(intent: string | null): string | null {
  if (intent === null) return null;
  return `sandboxes:connections.intent.${KNOWN_INTENTS.has(intent) ? intent : "other"}`;
}

function bytes(value: string, locale: string): string {
  const parsed = Number(value);
  return formatBytes(Number.isFinite(parsed) && parsed >= 0 ? parsed : 0, locale);
}

export function SandboxConnections({ lang, sandboxId }: { lang: string; sandboxId: string }) {
  const { t, i18n } = useTranslation(["sandboxes", "dashboard"]);
  const locale = i18n.language;
  const query = useInfiniteQuery({
    ...orpc.sandboxes.listConnectSessions.infiniteOptions({
      input: (cursor: string | undefined) => ({
        id: sandboxId,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const rows = query.data?.pages.flatMap((page) => page.items);
  const now = Date.now();

  return (
    <section
      aria-labelledby="sandbox-connections"
      data-sandbox-connections=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="sandbox-connections" className="text-sm font-medium">
        {t("sandboxes:connections.heading")}
      </h2>
      <p className="text-sm text-muted-foreground">{t("sandboxes:connections.description")}</p>
      <QueryBoundary
        query={{
          data: rows,
          isPending: query.isPending,
          isError: query.isError,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList count={2} layout="resource" className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <p data-connections-empty="" className="text-sm text-muted-foreground">
            {t("sandboxes:connections.empty")}
          </p>
        }
      >
        {(items) => (
          <>
            <ul
              aria-label={t("sandboxes:connections.label")}
              className="flex min-w-0 flex-col divide-y rounded-lg border"
            >
              {items.map((row) => {
                const opened = new Date(row.openedAt).getTime();
                const intent = connectionIntentKey(row.closeIntent);
                return (
                  <li
                    key={row.id}
                    data-connection-id={row.id}
                    data-connection-status={row.status}
                    className="flex min-w-0 flex-col gap-1 px-3 py-2 text-sm"
                  >
                    <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 break-words font-medium">
                        {row.keyName ?? t("sandboxes:connections.unknownKey")}
                      </span>
                      <span className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" data-origin={row.origin}>
                          {t(`sandboxes:connections.origin.${row.origin}`)}
                        </Badge>
                        <Badge
                          variant={row.status === "open" ? "default" : "outline"}
                          data-status={row.status}
                        >
                          {t(`sandboxes:connections.status.${row.status}`)}
                        </Badge>
                      </span>
                    </div>
                    <span className="text-muted-foreground" title={dateTimeTitle(opened, locale)}>
                      {t("sandboxes:connections.opened", {
                        when: formatRelativeTime(opened, locale, now),
                      })}
                    </span>
                    {intent ? (
                      <span data-close-intent={row.closeIntent} className="text-muted-foreground">
                        {t("sandboxes:connections.closedReason", { reason: t(intent) })}
                      </span>
                    ) : null}
                    <span className="break-words text-muted-foreground">
                      {[
                        t("sandboxes:connections.shells", { count: row.ptyChannels }),
                        t("sandboxes:connections.commands", { count: row.execChannels }),
                        t("sandboxes:connections.bytes", {
                          sent: bytes(row.bytesIn, locale),
                          received: bytes(row.bytesOut, locale),
                        }),
                      ].join(" · ")}
                    </span>
                  </li>
                );
              })}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
    </section>
  );
}
