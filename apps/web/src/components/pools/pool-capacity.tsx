import { useForm } from "@tanstack/react-form";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { TextField } from "@wssp/ui/components/text-field";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatLeaseDuration } from "@/lib/lease-duration";
import { orpc } from "@/utils/orpc";

/** One capacity read per 30 s per open panel stays well inside the owner's
 * 30 reads/minute capacity budget, even with a few pools open. */
const CAPACITY_REFETCH_MS = 30_000;
const paging = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
};

function Meter({
  label,
  used,
  total,
  unit,
}: {
  label: string;
  used: number;
  total: number;
  unit: string;
}) {
  const percent = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex justify-between gap-2 text-sm">
        <span>{label}</span>
        <span className="tabular-nums text-muted-foreground">
          {used} / {total} {unit}
        </span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={used}
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

/**
 * Schedulable capacity of one pool for the caller: aggregates over hosts the
 * caller can schedule on (never per foreign host), what fits now for a
 * template, the lease limit and the queue. Pool owners also see their own
 * hosts in detail and the waiting creates (requester, size, waited, blocker).
 */
export function PoolCapacityDialog({
  poolId,
  owner,
  lang,
  onClose,
}: {
  poolId: string;
  owner: boolean;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const [template, setTemplate] = useState("");
  const capacity = useQuery({
    ...orpc.sandboxPools.capacity.queryOptions({
      input: { id: poolId, ...(template ? { template } : {}) },
    }),
    refetchInterval: CAPACITY_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const queue = useInfiniteQuery({
    ...orpc.sandboxPools.queue.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ poolId, cursor, limit: 20 }),
    }),
    enabled: owner,
    refetchInterval: CAPACITY_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [capacity.error]);
  const form = useForm({
    defaultValues: { template: "" },
    validators: { onSubmit: z.object({ template: z.string().max(200) }) },
    onSubmit: ({ value }) => setTemplate(value.template.trim()),
  });
  const data = capacity.data;
  const wait = (ms: number | null) =>
    ms === null
      ? t("hosts:poolCapacity.unlimited")
      : ms === 0
        ? t("hosts:poolCapacity.waitsOff")
        : formatLeaseDuration(ms, lang);
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("common:actions.close")}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>{t("hosts:poolCapacity.title")}</DialogTitle>
          <DialogDescription>{t("hosts:poolCapacity.description")}</DialogDescription>
        </DialogHeader>
        <form
          className="flex min-w-0 flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void form.handleSubmit();
          }}
        >
          <form.Field name="template">
            {(field) => (
              <TextField
                field={field}
                label={t("hosts:poolCapacity.template")}
                description={t("hosts:poolCapacity.templateHint")}
                autoComplete="off"
                inputMode="text"
                maxLength={200}
                inputClassName="min-h-11"
              />
            )}
          </form.Field>
          <Button type="submit" size="touch" variant="secondary">
            {t("hosts:poolCapacity.check")}
          </Button>
        </form>
        {capacity.isPending ? (
          <SkeletonList count={3} />
        ) : capacity.isError ? (
          <InlineRetry
            message={t("hosts:poolCapacity.failed")}
            onRetry={() => void capacity.refetch()}
          />
        ) : data ? (
          <div className="flex min-w-0 flex-col gap-4" data-pool-capacity="">
            <section className="flex min-w-0 flex-col gap-3">
              <h3 className="font-medium">{t("hosts:poolCapacity.schedulable")}</h3>
              <Meter
                label={t("hosts:poolCapacity.ram")}
                used={data.aggregate.budget.memoryMiB - data.aggregate.free.memoryMiB}
                total={data.aggregate.budget.memoryMiB}
                unit="MiB"
              />
              <Meter
                label={t("hosts:poolCapacity.vcpu")}
                used={data.aggregate.budget.vcpu - data.aggregate.free.vcpu}
                total={data.aggregate.budget.vcpu}
                unit="vCPU"
              />
              <Meter
                label={t("hosts:poolCapacity.disk")}
                used={data.aggregate.budget.diskGiB - data.aggregate.free.diskGiB}
                total={data.aggregate.budget.diskGiB}
                unit="GiB"
              />
              {data.fits !== null ? (
                <p data-capacity-fits="">{t("hosts:poolCapacity.fits", { count: data.fits })}</p>
              ) : null}
              <p>
                {t("hosts:poolCapacity.lease", {
                  duration: formatLeaseDuration(data.lease.maxTimeoutMs, lang),
                })}
              </p>
            </section>
            <section className="flex min-w-0 flex-col gap-1">
              <h3 className="font-medium">{t("hosts:poolCapacity.queue")}</h3>
              <p>
                {t("hosts:poolCapacity.queueSummary", {
                  waiting: data.queue.waiting,
                  mine: data.queue.mine,
                })}
              </p>
              {data.queue.myOldestPosition !== null ? (
                <p>
                  {t("hosts:poolCapacity.myPosition", { position: data.queue.myOldestPosition })}
                </p>
              ) : null}
              <p className="text-sm text-muted-foreground">
                {t("hosts:poolCapacity.limits", {
                  wait: wait(data.queue.limits.maxWaitMs),
                  perKey: data.queue.limits.perKey ?? t("hosts:poolCapacity.unlimited"),
                  perOwner: data.queue.limits.perOwner ?? t("hosts:poolCapacity.unlimited"),
                })}
              </p>
              <p className="text-sm text-muted-foreground">
                {t(
                  data.queue.preferOwnHosts
                    ? "hosts:poolCapacity.preferOwnOn"
                    : "hosts:poolCapacity.preferOwnOff",
                )}
              </p>
            </section>
            {data.hosts.length > 0 ? (
              <section className="flex min-w-0 flex-col gap-2">
                <h3 className="font-medium">{t("hosts:poolCapacity.ownHosts")}</h3>
                <ul className="flex min-w-0 flex-col gap-2">
                  {data.hosts.map((host) => (
                    <li
                      key={host.id}
                      className="flex min-w-0 flex-col gap-1 rounded-lg border p-3"
                      data-capacity-host={host.id}
                    >
                      <span className="break-words font-medium">{host.label}</span>
                      <Meter
                        label={t("hosts:poolCapacity.ram")}
                        used={host.memory.reservedMiB}
                        total={host.memory.budgetMiB}
                        unit="MiB"
                      />
                      <Meter
                        label={t("hosts:poolCapacity.vcpu")}
                        used={host.vcpu.reserved}
                        total={host.vcpu.budget}
                        unit="vCPU"
                      />
                      <p className="text-sm text-muted-foreground">
                        {host.excludedBy
                          ? t(`hosts:poolCapacity.excluded.${host.excludedBy}`)
                          : host.fits !== null
                            ? t("hosts:poolCapacity.hostFits", {
                                count: host.fits,
                                share:
                                  host.dominantShareAfter === null
                                    ? "—"
                                    : `${Math.round(host.dominantShareAfter * 100)}%`,
                              })
                            : t("hosts:poolCapacity.live", { count: host.liveCount })}
                      </p>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            {owner ? (
              <section className="flex min-w-0 flex-col gap-2">
                <h3 className="font-medium">{t("hosts:poolCapacity.waiting")}</h3>
                {queue.isPending ? <SkeletonList count={2} /> : null}
                {queue.isError ? (
                  <InlineRetry
                    message={t("hosts:poolCapacity.queueFailed")}
                    onRetry={() => void queue.refetch()}
                  />
                ) : null}
                <ul className="flex min-w-0 flex-col gap-2">
                  {queue.data?.pages
                    .flatMap((page) => page.items)
                    .map((entry) => (
                      <li
                        key={entry.id}
                        className="rounded-lg border p-3 text-sm"
                        data-queue-entry=""
                      >
                        {t("hosts:poolCapacity.entry", {
                          position: entry.position ?? "—",
                          requester: entry.requester,
                          cpu: entry.cpuCount,
                          memory: entry.memoryMiB,
                          disk: entry.diskGiB,
                          since: new Date(entry.enqueuedAt).toLocaleString(lang),
                          deadline: entry.deadlineAt
                            ? new Date(entry.deadlineAt).toLocaleString(lang)
                            : t("hosts:poolCapacity.unlimited"),
                          blocker: entry.blocker
                            ? t(`hosts:poolCapacity.blocker.${entry.blocker}`)
                            : "—",
                        })}
                      </li>
                    ))}
                </ul>
                {queue.data?.pages[0]?.items.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t("hosts:poolCapacity.queueEmpty")}
                  </p>
                ) : null}
                <LoadMore
                  hasNextPage={queue.hasNextPage}
                  isFetchingNextPage={queue.isFetchingNextPage}
                  onLoadMore={() => void queue.fetchNextPage()}
                />
              </section>
            ) : null}
          </div>
        ) : null}
        <Button type="button" size="touch" variant="outline" onClick={onClose}>
          {t("common:actions.close")}
        </Button>
      </DialogContent>
    </Dialog>
  );
}
