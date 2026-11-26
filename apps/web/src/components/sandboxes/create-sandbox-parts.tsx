import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { Button } from "@wssp/ui/components/button";
import { RangeField } from "@wssp/ui/components/range-field";
import type { FieldLike } from "@wssp/ui/components/text-field";
import { GIBIBYTE_UNITS, type RangeUnit } from "@wssp/ui/lib/range-scale";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { SharingNotice } from "@/components/pools/pool-sharing";
import { SkeletonList } from "@/components/skeleton-list";
import { useRangeFieldLabels } from "@/hooks/use-form-field-labels";
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
 * is paused for the network (instead of an endless skeleton). `holdsPlace`:
 * the caller already draws its control, disabled, while the query loads, so
 * the section keeps its loaded height and no skeleton is added.
 */
export function PickerStatus({
  query,
  failed,
  holdsPlace = false,
}: {
  query: PickerQuery;
  failed: string;
  holdsPlace?: boolean;
}) {
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
  if (query.isPending && !holdsPlace)
    return <SkeletonList count={1} className="rounded-xl border" />;
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
  /** The pinned version these come from. */
  revision: number;
  cpuCount: number;
  memoryMiB: number;
  defaultDiskGiB: number;
  minDiskGiB: number;
} | null;

/**
 * Memory is stored in MiB and always shown in GiB ("0.5 GiB", "4 GiB"): one
 * unit, so a bare typed number means GiB too.
 */
const MEMORY_UNITS: readonly RangeUnit[] = [{ factor: 1024, label: "GiB", aliases: ["gb", "g"] }];

/**
 * vCPU, memory and root disk as sliders with a typed escape hatch. `null` is
 * "use the template's default" (nothing is sent): the field shows the pinned
 * version's value with the default mark, and choosing that value again (or
 * Reset) goes back to `null`. With Latest the default is unknown until the
 * create, so there is no mark: an untouched field shows the newest listed
 * version's value (or the minimum) and says it is not set. `cap` is the real
 * capacity of the chosen placement (a host's free resources, or the most one
 * pool host can take): the slider stops there with a one-line reason. While
 * a pooled create waits for room, `capAdvisory` shows that line without
 * capping anything. Any typed or slid value is an override, even one equal to
 * the shown Latest value; "Use template default" puts every field back to
 * `null` (with Latest there is no per-field Reset: no default is known).
 */
export function SizeFields({
  values,
  onChange,
  defaults,
  fallback,
  cap,
  capSource,
  capAdvisory,
  errors,
  disabled,
}: {
  values: SizeValues;
  onChange: (field: keyof SizeValues, value: number | null) => void;
  defaults: SizeDefaults;
  /** What an untouched field shows when there is no default (Latest). */
  fallback: SizeDefaults;
  cap: SizeCap | null;
  capSource: "host" | "pool";
  /** Show the cap's reason, but do not cap (the create waits for capacity). */
  capAdvisory: boolean;
  errors: Partial<Record<keyof SizeValues, string>>;
  disabled: boolean;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const rangeLabels = useRangeFieldLabels();
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
  const defaultOf = (name: keyof SizeValues): number | undefined =>
    defaults ? (name === "diskGiB" ? defaults.defaultDiskGiB : defaults[name]) : undefined;
  const fallbackOf = (name: keyof SizeValues, min: number): number => {
    const known = fallback ? (name === "diskGiB" ? fallback.defaultDiskGiB : fallback[name]) : min;
    // A shown-only value never reads as over the cap: nothing is sent for it.
    const top = cap && !capAdvisory ? Math.max(cap[name], min) : Number.POSITIVE_INFINITY;
    return Math.min(Math.max(known, min), top);
  };
  /** A TanStack-style field over the page's size state (`null`: inherit). */
  const sizeField = (name: keyof SizeValues, min: number): FieldLike<number> => {
    const inherited = defaultOf(name);
    const error = errors[name];
    return {
      name,
      state: {
        value: values[name] ?? inherited ?? fallbackOf(name, min),
        meta: { errors: error ? [error] : [] },
      },
      handleBlur: () => {},
      // The default itself is "inherit": nothing is sent for it.
      handleChange: (next) =>
        onChange(name, inherited !== undefined && next === inherited ? null : next),
    };
  };
  /** The line under a field: not set (Latest), else the advisory cap. */
  const note = (name: keyof SizeValues, extra?: string) => {
    const parts = [
      extra,
      values[name] === null && defaultOf(name) === undefined
        ? t("sandboxes:create.sizeNotSet")
        : undefined,
      capAdvisory ? capMessage(name) : undefined,
    ].filter((part): part is string => Boolean(part));
    return parts.length > 0 ? parts.join(" ") : undefined;
  };
  const limitProps = (name: keyof SizeValues) =>
    cap && !capAdvisory ? { limit: cap[name], limitMessage: capMessage(name) } : {};
  const defaultLabel = defaults
    ? t("sandboxes:create.sizeDefaultSource", { revision: defaults.revision })
    : undefined;
  const common = { labels: rangeLabels, defaultLabel, disabled };
  return (
    <div data-size-fields="" className="flex min-w-0 flex-col gap-5">
      <RangeField
        {...common}
        {...limitProps("cpuCount")}
        field={sizeField("cpuCount", VM_SIZE_LIMITS.cpuCountMin)}
        label={t("sandboxes:create.vcpu")}
        description={note("cpuCount")}
        min={VM_SIZE_LIMITS.cpuCountMin}
        max={VM_SIZE_LIMITS.cpuCountMax}
        stops={CPU_STOPS}
        step={1}
        units={[{ factor: 1, label: "vCPU" }]}
        defaultValue={defaultOf("cpuCount")}
      />
      <RangeField
        {...common}
        {...limitProps("memoryMiB")}
        field={sizeField("memoryMiB", VM_SIZE_LIMITS.memoryMiBMin)}
        label={t("sandboxes:create.memory")}
        description={note("memoryMiB")}
        min={VM_SIZE_LIMITS.memoryMiBMin}
        max={VM_SIZE_LIMITS.memoryMiBMax}
        stops={MEMORY_STOPS_MIB}
        step={VM_SIZE_LIMITS.memoryMiBStep}
        units={MEMORY_UNITS}
        defaultValue={defaultOf("memoryMiB")}
      />
      <RangeField
        {...common}
        {...limitProps("diskGiB")}
        field={sizeField("diskGiB", diskMin)}
        label={t("sandboxes:create.disk")}
        description={note(
          "diskGiB",
          defaults
            ? t("sandboxes:create.revisionDiskHint", {
                defaultDiskGiB: defaults.defaultDiskGiB,
                minDiskGiB: defaults.minDiskGiB,
              })
            : undefined,
        )}
        min={diskMin}
        max={VM_SIZE_LIMITS.diskGiBMax}
        scale="log"
        step={1}
        units={GIBIBYTE_UNITS}
        defaultValue={defaultOf("diskGiB")}
      />
      {SIZE_FIELDS.some((name) => values[name] !== null) ? (
        <div>
          <Button
            type="button"
            variant="outline"
            size="touch"
            data-size-use-default=""
            disabled={disabled}
            onClick={() => {
              for (const name of SIZE_FIELDS) if (values[name] !== null) onChange(name, null);
            }}
          >
            {t("sandboxes:create.sizeUseTemplateDefault")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

const SIZE_FIELDS = [
  "cpuCount",
  "memoryMiB",
  "diskGiB",
] as const satisfies readonly (keyof SizeValues)[];

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
