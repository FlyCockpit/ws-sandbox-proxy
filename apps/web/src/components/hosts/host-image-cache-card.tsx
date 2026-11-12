import { useInfiniteQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { CopyableId } from "@/components/copyable-id";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { revisionLabel } from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";

const PAGE_LIMIT = 20;

/**
 * The host's managed image cache (owner only). The owner's own images are
 * listed; other accounts' images are one aggregate size. Accepting other
 * accounts' images is a host-side setting, shown read-only with its command.
 */
export function HostImageCacheCard({ hostId, lang }: { hostId: string; lang: string }) {
  const { t } = useTranslation("hosts");
  const cache = useInfiniteQuery({
    ...orpc.sandboxHosts.imageCache.infiniteOptions({
      input: (cursor: string | undefined) => ({ hostId, cursor, limit: PAGE_LIMIT }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (page) => page.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [cache.error]);
  const summary = cache.data?.pages[0]?.summary;
  const bytes = (value: string | null | undefined) =>
    value == null ? "—" : formatBytes(Number(value), lang);
  return (
    <section aria-labelledby="host-image-cache" className="flex min-w-0 flex-col gap-2">
      <h2 id="host-image-cache" className="text-base font-semibold">
        {t("imageCache.title")}
      </h2>
      {cache.isPending ? <SkeletonList count={1} className="rounded-xl border" /> : null}
      {cache.isError ? (
        <InlineRetry message={t("imageCache.loadFailed")} onRetry={() => void cache.refetch()} />
      ) : null}
      {summary && !summary.enabled ? (
        <p className="text-sm text-muted-foreground">{t("imageCache.disabled")}</p>
      ) : null}
      {summary?.enabled ? (
        <>
          <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-3">
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t("imageCache.cap")}</dt>
              <dd data-image-cache-cap="" className="tabular-nums">
                {bytes(summary.capBytes)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t("imageCache.used")}</dt>
              <dd data-image-cache-used="" className="tabular-nums">
                {bytes(summary.usedBytes)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t("imageCache.foreign")}</dt>
              <dd data-image-cache-foreign="" className="tabular-nums">
                {bytes(summary.foreignBytes)}
              </dd>
            </div>
          </dl>
          {summary.current ? null : (
            <p className="text-sm text-muted-foreground">{t("imageCache.stale")}</p>
          )}
          <p data-image-cache-accept-foreign="" className="text-sm">
            {t(
              summary.acceptForeign ? "imageCache.acceptForeignOn" : "imageCache.acceptForeignOff",
            )}
          </p>
          <p className="text-xs text-muted-foreground">
            {t("imageCache.acceptForeignHint")}{" "}
            <code className="break-all font-mono">accept_foreign_images = true</code>
          </p>
          {summary.builder ? (
            <div className="flex min-w-0 flex-col gap-1" data-host-builder="">
              <p className="flex flex-wrap gap-1.5">
                <span className="inline-flex items-center rounded-sm border border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                  {t("imageCache.builder")}
                </span>
                {summary.acceptForeignBuilds ? (
                  <span
                    data-host-builder-foreign=""
                    className="inline-flex items-center rounded-sm border border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground"
                  >
                    {t("imageCache.builderForeign")}
                  </span>
                ) : null}
              </p>
              <p className="text-xs text-muted-foreground">{t("imageCache.builderHint")}</p>
            </div>
          ) : null}
        </>
      ) : null}
      <ul aria-label={t("imageCache.listLabel")} className="flex min-w-0 flex-col gap-2">
        {cache.data?.pages
          .flatMap((page) => page.items)
          .map((entry) => (
            <li
              key={entry.id}
              data-image-cache-entry={entry.fingerprint}
              className="min-w-0 rounded border p-3 text-xs"
            >
              <p data-image-cache-name="" className="text-sm font-medium">
                {entry.revision
                  ? t("imageCache.named", {
                      revision: revisionLabel(entry.revision),
                      size: formatBytes(Number(entry.compressedBytes), lang),
                    })
                  : t("imageCache.unnamed", {
                      size: formatBytes(Number(entry.compressedBytes), lang),
                    })}
              </p>
              <p className="text-muted-foreground">
                {t(`imageCache.origin.${entry.origin}`, { defaultValue: entry.origin })}
                {entry.pinned ? ` · ${t("imageCache.pinned")}` : ""}
              </p>
              <CopyableId
                className="mt-1"
                value={entry.fingerprint}
                label={t("imageCache.fingerprint")}
              />
            </li>
          ))}
      </ul>
      {cache.data && cache.data.pages[0]?.items.length === 0 && summary?.enabled ? (
        <p className="text-sm text-muted-foreground">{t("imageCache.empty")}</p>
      ) : null}
      <LoadMore
        hasNextPage={cache.hasNextPage}
        isFetchingNextPage={cache.isFetchingNextPage}
        onLoadMore={() => void cache.fetchNextPage()}
        label={t("imageCache.more")}
      />
    </section>
  );
}
