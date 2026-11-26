import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { Button } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { SkeletonList } from "@/components/skeleton-list";
import { WideSheet } from "@/components/wide-sheet";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import { formatLeaseDuration } from "@/lib/lease-duration";
import { orpc } from "@/utils/orpc";

/** One capacity read per 30 s per open panel stays well inside the owner's
 * 30 reads/minute capacity budget, even with a few pools open. */
const CAPACITY_REFETCH_MS = 30_000;
/** Templates offered in the "what fits" picker (the first page of active ones). */
const TEMPLATE_PICKER_LIMIT = 100;
/** The picker's "no template" choice (a select item needs a value). */
const ANY_TEMPLATE = "__any__";
const paging = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
};

/** MiB → GiB, one decimal: the meters read in the same unit as the rest of the app. */
function toGiB(mib: number): number {
  return Math.round((mib / 1024) * 10) / 10;
}

/**
 * One capacity bar. The text names both sides ("3.9 GiB used of 4 GiB · 0.1 GiB
 * free"): a bare "3.9 / 4" reads as available as easily as used.
 */
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
  const { t } = useTranslation("hosts");
  const percent = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
  const free = Math.max(0, Math.round((total - used) * 10) / 10);
  const text = t("hosts:poolCapacity.usedFree", { used, total, free, unit });
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex min-w-0 flex-wrap justify-between gap-x-2 text-sm">
        <span>{label}</span>
        <span className="tabular-nums text-muted-foreground">{text}</span>
      </div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={Math.min(used, total)}
        aria-valuetext={text}
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

type Largest = { cpuCount: number; memoryMiB: number; diskGiB: number } | null;

/** The largest single sandbox that fits now, or that nothing fits. */
function LargestFit({ largest }: { largest: Largest }) {
  const { t } = useTranslation("hosts");
  const none =
    largest === null ||
    largest.cpuCount < VM_SIZE_LIMITS.cpuCountMin ||
    largest.memoryMiB < VM_SIZE_LIMITS.memoryMiBMin ||
    largest.diskGiB < VM_SIZE_LIMITS.diskGiBMin;
  return (
    <p data-capacity-largest={none ? "none" : ""} className="font-medium">
      {none
        ? t("hosts:poolCapacity.largestNone")
        : t("hosts:poolCapacity.largest", {
            cpu: largest.cpuCount,
            memory: toGiB(largest.memoryMiB),
            disk: largest.diskGiB,
          })}
    </p>
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
  const templateId = useId();
  const [template, setTemplate] = useState("");
  const templates = useInfiniteQuery({
    ...orpc.sandboxTemplates.listTemplates.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({
        limit: TEMPLATE_PICKER_LIMIT,
        cursor,
        status: "active" as const,
      }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const templateChoices = templates.data?.pages.flatMap((page) => page.items) ?? [];
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
  const data = capacity.data;
  const wait = (ms: number | null) =>
    ms === null
      ? t("hosts:poolCapacity.unlimited")
      : ms === 0
        ? t("hosts:poolCapacity.waitsOff")
        : formatLeaseDuration(ms, lang);
  return (
    <WideSheet
      data-pool-capacity-sheet=""
      title={t("hosts:poolCapacity.title")}
      description={t("hosts:poolCapacity.description")}
      closeLabel={t("common:actions.close")}
      onClose={onClose}
      actions={
        <Button type="button" size="touch" variant="outline" onClick={onClose}>
          {t("common:actions.close")}
        </Button>
      }
    >
      <div className="flex min-w-0 flex-col gap-2 sm:max-w-md">
        <Label htmlFor={templateId}>{t("hosts:poolCapacity.template")}</Label>
        <FormSelect
          id={templateId}
          autoComplete="off"
          optionsSettled={templates.isSuccess && !templates.isFetching}
          value={template || ANY_TEMPLATE}
          onValueChange={(value) => setTemplate(value === ANY_TEMPLATE ? "" : value)}
        >
          <SelectItem value={ANY_TEMPLATE}>{t("hosts:poolCapacity.anyTemplate")}</SelectItem>
          {templateChoices.map((choice) => (
            <SelectItem key={choice.id} value={choice.slug}>
              {t("hosts:poolCapacity.templateOption", {
                label: choice.label,
                slug: choice.slug,
              })}
            </SelectItem>
          ))}
        </FormSelect>
        <p className="text-xs text-muted-foreground">{t("hosts:poolCapacity.templateHint")}</p>
      </div>
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
              used={toGiB(data.aggregate.budget.memoryMiB - data.aggregate.free.memoryMiB)}
              total={toGiB(data.aggregate.budget.memoryMiB)}
              unit="GiB"
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
            <LargestFit largest={data.largest} />
            {data.fits !== null ? (
              <p data-capacity-fits="">{t("hosts:poolCapacity.fits", { count: data.fits })}</p>
            ) : null}
            <p className="text-xs text-muted-foreground">{t("hosts:poolCapacity.largestHint")}</p>
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
              <p>{t("hosts:poolCapacity.myPosition", { position: data.queue.myOldestPosition })}</p>
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
                      used={toGiB(host.memory.reservedMiB)}
                      total={toGiB(host.memory.budgetMiB)}
                      unit="GiB"
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
                        since: formatDateTime(entry.enqueuedAt, lang),
                        deadline: entry.deadlineAt
                          ? formatDateTime(entry.deadlineAt, lang)
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
    </WideSheet>
  );
}
