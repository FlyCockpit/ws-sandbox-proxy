import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { logStops, RangeField } from "@wssp/ui/components/range-field";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { SharingNotice } from "@/components/pools/pool-sharing";
import { SkeletonList } from "@/components/skeleton-list";
import { formatGraceDuration } from "@/lib/format-duration";
import { CPU_STOPS, gibFromMib, MEMORY_STOPS_MIB, type SizeCap } from "@/lib/sandbox-size";

/**
 * Presentational parts of the Create sandbox page: picker load states, the
 * pool trust line with its disclosure, the size sliders and the one-line
 * summaries. State and submit semantics live in `create-sandbox-page.tsx`.
 */

type PickerQuery = {
  isPending: boolean;
  isError: boolean;
  fetchStatus: "fetching" | "paused" | "idle";
  refetch: () => unknown;
};

/**
 * A picker's load state that always resolves: a short skeleton while it
 * loads, an inline retry when it failed, and an offline retry when the query
 * is paused for the network (instead of an endless skeleton).
 */
export function PickerStatus({ query, failed }: { query: PickerQuery; failed: string }) {
  const { t } = useTranslation(["sandboxes"]);
  if (query.isError)
    return <InlineRetry variant="destructive" message={failed} onRetry={() => query.refetch()} />;
  if (query.isPending && query.fetchStatus === "paused")
    return (
      <InlineRetry
        variant="destructive"
        message={t("sandboxes:create.offline")}
        onRetry={() => query.refetch()}
      />
    );
  if (query.isPending) return <SkeletonList count={1} className="rounded-xl border" />;
  return null;
}

/** The pool trust copy as one line, with the full notice and grace quote under "Learn more". */
export function PoolTrustNotice({
  graceSeconds,
  lang,
}: {
  graceSeconds: number | undefined;
  lang: string;
}) {
  const { t } = useTranslation(["sandboxes", "hosts"]);
  return (
    <div className="flex min-w-0 flex-col gap-1 text-sm text-muted-foreground">
      <p data-pool-trust-line="">{t("sandboxes:create.poolTrustLine")}</p>
      <details data-pool-trust-more="" className="min-w-0">
        <summary className="flex min-h-11 cursor-pointer items-center font-medium text-foreground">
          {t("sandboxes:create.learnMore")}
        </summary>
        <div className="flex min-w-0 flex-col gap-2 pb-2">
          <SharingNotice />
          {graceSeconds !== undefined ? (
            <p data-grace-quote="">
              {t("hosts:sharing.grace", { duration: formatGraceDuration(graceSeconds, lang) })}
            </p>
          ) : null}
        </div>
      </details>
    </div>
  );
}

export type SizeValues = {
  cpuCount: number | null;
  memoryMiB: number | null;
  diskGiB: number | null;
};

export type SizeDefaults = {
  cpuCount: number;
  memoryMiB: number;
  defaultDiskGiB: number;
  minDiskGiB: number;
} | null;

/**
 * vCPU, memory and root disk as sliders with a typed escape hatch. `null` is
 * "use the template's default" (nothing is sent). `cap` is the real capacity
 * of the chosen placement (a host's free resources, or the most one pool host
 * can take); values above it are refused with a one-line reason.
 */
export function SizeFields({
  values,
  onChange,
  defaults,
  cap,
  capSource,
  errors,
  disabled,
}: {
  values: SizeValues;
  onChange: (field: keyof SizeValues, value: number | null) => void;
  defaults: SizeDefaults;
  cap: SizeCap | null;
  capSource: "host" | "pool";
  errors: Partial<Record<keyof SizeValues, string>>;
  disabled: boolean;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const diskMin = defaults?.minDiskGiB ?? VM_SIZE_LIMITS.diskGiBMin;
  const capMessage = (field: keyof SizeValues): string | undefined => {
    if (!cap) return undefined;
    if (field === "cpuCount")
      return t(`sandboxes:create.capacity.${capSource}Cpu`, { count: cap.cpuCount });
    if (field === "memoryMiB")
      return t(`sandboxes:create.capacity.${capSource}Memory`, {
        amount: gibFromMib(cap.memoryMiB),
      });
    return t(`sandboxes:create.capacity.${capSource}Disk`, { amount: cap.diskGiB });
  };
  const common = {
    defaultLabel: t("sandboxes:create.templateDefault"),
    resetLabel: t("sandboxes:create.resetDefault"),
    disabled,
  };
  return (
    <div data-size-fields="" className="flex min-w-0 flex-col gap-5">
      <RangeField
        {...common}
        label={t("sandboxes:create.vcpu")}
        value={values.cpuCount}
        onChange={(value) => onChange("cpuCount", value)}
        min={VM_SIZE_LIMITS.cpuCountMin}
        max={VM_SIZE_LIMITS.cpuCountMax}
        stops={CPU_STOPS}
        step={1}
        defaultValue={defaults?.cpuCount ?? null}
        capacityMax={cap?.cpuCount}
        capacityMessage={capMessage("cpuCount")}
        rangeMessage={t("common:range.outOfRange", {
          min: VM_SIZE_LIMITS.cpuCountMin,
          max: VM_SIZE_LIMITS.cpuCountMax,
        })}
        unit="vCPU"
        format={(value) => `${value} vCPU`}
        error={errors.cpuCount}
      />
      <RangeField
        {...common}
        label={t("sandboxes:create.memory")}
        value={values.memoryMiB}
        onChange={(value) => onChange("memoryMiB", value)}
        min={VM_SIZE_LIMITS.memoryMiBMin}
        max={VM_SIZE_LIMITS.memoryMiBMax}
        stops={MEMORY_STOPS_MIB}
        step={VM_SIZE_LIMITS.memoryMiBStep}
        defaultValue={defaults?.memoryMiB ?? null}
        capacityMax={cap?.memoryMiB}
        capacityMessage={capMessage("memoryMiB")}
        rangeMessage={t("common:range.outOfRange", {
          min: gibFromMib(VM_SIZE_LIMITS.memoryMiBMin),
          max: gibFromMib(VM_SIZE_LIMITS.memoryMiBMax),
        })}
        unit="GiB"
        toDisplay={gibFromMib}
        fromDisplay={(gib) => gib * 1024}
        inputStep={0.25}
        format={(value) => `${gibFromMib(value)} GiB`}
        error={errors.memoryMiB}
      />
      <RangeField
        {...common}
        label={t("sandboxes:create.disk")}
        description={
          defaults
            ? t("sandboxes:create.revisionDiskHint", {
                defaultDiskGiB: defaults.defaultDiskGiB,
                minDiskGiB: defaults.minDiskGiB,
              })
            : undefined
        }
        value={values.diskGiB}
        onChange={(value) => onChange("diskGiB", value)}
        min={diskMin}
        max={VM_SIZE_LIMITS.diskGiBMax}
        stops={logStops(diskMin, VM_SIZE_LIMITS.diskGiBMax)}
        step={1}
        defaultValue={defaults?.defaultDiskGiB ?? null}
        capacityMax={cap?.diskGiB}
        capacityMessage={capMessage("diskGiB")}
        rangeMessage={t("common:range.outOfRange", {
          min: diskMin,
          max: VM_SIZE_LIMITS.diskGiBMax,
        })}
        unit="GiB"
        format={(value) => `${value} GiB`}
        error={errors.diskGiB}
      />
    </div>
  );
}

/**
 * "2 vCPU · 4 GiB · 32 GiB disk", or "Template default" while nothing is
 * overridden. A value that is neither set nor known from a pinned revision is
 * left out: "8 GiB · rest from the template".
 */
export function sizeSummary(t: TFunction, values: SizeValues, defaults: SizeDefaults): string {
  if (values.cpuCount === null && values.memoryMiB === null && values.diskGiB === null)
    return t("sandboxes:create.summary.templateDefault");
  const cpu = values.cpuCount ?? defaults?.cpuCount;
  const memory = values.memoryMiB ?? defaults?.memoryMiB;
  const disk = values.diskGiB ?? defaults?.defaultDiskGiB;
  if (cpu !== undefined && memory !== undefined && disk !== undefined)
    return t("sandboxes:create.summary.size", { cpu, memory: gibFromMib(memory), disk });
  return [
    cpu !== undefined ? t("sandboxes:create.summary.cpu", { count: cpu }) : null,
    memory !== undefined
      ? t("sandboxes:create.summary.memory", { amount: gibFromMib(memory) })
      : null,
    disk !== undefined ? t("sandboxes:create.summary.disk", { amount: disk }) : null,
    t("sandboxes:create.summary.restFromTemplate"),
  ]
    .filter((part): part is string => part !== null)
    .join(" · ");
}

/** A lifetime choice in words ("1 hour", "15 minutes", "no time limit"). */
export function lifetimeText(t: TFunction, minutesText: string): string {
  const minutes = Number(minutesText);
  if (minutes === 0) return t("sandboxes:create.status.unlimited");
  if (minutes < 60) return t("sandboxes:lifetime.minutes", { count: minutes });
  if (minutes < 2880) return t("sandboxes:lifetime.hours", { count: minutes / 60 });
  return t("sandboxes:lifetime.days", { count: minutes / 1440 });
}
