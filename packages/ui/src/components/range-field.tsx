import { Slider as SliderPrimitive } from "@base-ui/react/slider";
import { Button } from "@wssp/ui/components/button";
import { Input } from "@wssp/ui/components/input";
import { cn } from "@wssp/ui/lib/utils";
import { RotateCcw } from "lucide-react";
import type * as React from "react";
import { useId, useState } from "react";

/**
 * A slider with a number input beside it (template-forms `RangeField`). The
 * slider moves between snap `stops` on a log scale (1, 2, 4, 8 …); the input
 * is the escape hatch for any value in range. `value: null` means "use the
 * default": the default is marked on the track, the input shows it, and a
 * Reset returns to it. A dynamic `capacityMax` below `max` greys out the
 * track above it, refuses slider moves past it and explains why in one line.
 *
 * Values are in the caller's unit (MiB, GiB, vCPU); `toDisplay`/`fromDisplay`
 * convert for the input and labels (e.g. MiB shown as GiB). The server still
 * validates; this only prevents.
 *
 * Local wssp wrapper; phase B swaps it for the template's identical copy.
 */

/** Powers of two from `min` to `max`, both ends included. */
export function logStops(min: number, max: number): number[] {
  const stops = [min];
  let next = 2 ** Math.ceil(Math.log2(Math.max(min, 1)));
  if (next <= min) next *= 2;
  while (next < max) {
    stops.push(next);
    next *= 2;
  }
  if (max > min) stops.push(max);
  return stops;
}

/** Fractional stop index of `value` (log-interpolated between neighbours). */
export function positionOf(stops: readonly number[], value: number): number {
  const first = stops[0];
  const last = stops.length - 1;
  const top = stops[last];
  if (first === undefined || top === undefined || value <= first) return 0;
  if (value >= top) return last;
  for (let index = 0; index < last; index += 1) {
    const low = stops[index] ?? first;
    const high = stops[index + 1] ?? top;
    if (value <= high) {
      const span = Math.log(high) - Math.log(low);
      return index + (span > 0 ? (Math.log(value) - Math.log(low)) / span : 0);
    }
  }
  return last;
}

/** The value a slider index means, clamped to `limit`. */
export function valueAt(stops: readonly number[], index: number, limit: number): number {
  const stop = stops[Math.max(0, Math.min(stops.length - 1, Math.round(index)))] ?? limit;
  if (stop <= limit) return stop;
  const below = stops.filter((candidate) => candidate <= limit);
  return below[below.length - 1] ?? limit;
}

export type RangeFieldProps = {
  id?: string;
  label: string;
  description?: React.ReactNode;
  /** null: inherit the default. */
  value: number | null;
  onChange: (value: number | null) => void;
  min: number;
  max: number;
  /** Snap stops for the slider (ascending, within min..max). Defaults to `logStops(min, max)`. */
  stops?: readonly number[];
  /** Typed values round to this step (caller's unit). */
  step?: number;
  /** What `null` means; marked on the track. */
  defaultValue?: number | null;
  /** "Default (from template)". */
  defaultLabel?: string;
  resetLabel?: string;
  /** Real capacity of the chosen placement (caller's unit); null/undefined: unknown. */
  capacityMax?: number | null;
  /** One line shown while `capacityMax` limits the range ("This host has 6 vCPUs free"). */
  capacityMessage?: string;
  /** Shown when a typed value is out of range. */
  rangeMessage?: string;
  /** "vCPU", "GiB" — shown after the input. */
  unit: string;
  /** Value → display number (e.g. MiB → GiB). */
  toDisplay?: (value: number) => number;
  /** Display number → value (e.g. GiB → MiB, rounded to the step). */
  fromDisplay?: (display: number) => number;
  /** Display string for labels and aria-valuetext ("4 GiB"). */
  format?: (value: number) => string;
  /** Number input step in display units. */
  inputStep?: number;
  disabled?: boolean;
  /** External (form) error. */
  error?: string | null;
  className?: string;
};

export function RangeField({
  id,
  label,
  description,
  value,
  onChange,
  min,
  max,
  stops: givenStops,
  step = 1,
  defaultValue = null,
  defaultLabel,
  resetLabel = "Reset",
  capacityMax,
  capacityMessage,
  rangeMessage,
  unit,
  toDisplay = (input) => input,
  fromDisplay = (input) => input,
  format,
  inputStep,
  disabled = false,
  error,
  className,
}: RangeFieldProps) {
  const generatedId = useId();
  const baseId = id ?? generatedId;
  const stops = givenStops && givenStops.length > 0 ? givenStops : logStops(min, max);
  const limit =
    capacityMax !== null && capacityMax !== undefined ? Math.min(max, capacityMax) : max;
  const capped = limit < max;
  const shown = value ?? defaultValue;
  const display = (input: number) => format?.(input) ?? `${toDisplay(input)} ${unit}`;
  // While typing the input owns its text; otherwise it shows the current value
  // (so slider moves and resets show up without an effect).
  const [text, setText] = useState("");
  const [editing, setEditing] = useState(false);
  const shownText = shown === null ? "" : String(toDisplay(shown));

  const overCapacity = shown !== null && shown > limit;
  const outOfRange = shown !== null && (shown < min || shown > max);
  const message = error ?? (outOfRange ? rangeMessage : overCapacity ? capacityMessage : null);
  // The capacity line is not repeated while the error already says it.
  const capacityLine = capped && capacityMessage && message !== capacityMessage;
  const describedBy =
    [
      description ? `${baseId}-description` : null,
      capacityLine ? `${baseId}-capacity` : null,
      message ? `${baseId}-error` : null,
    ]
      .filter(Boolean)
      .join(" ") || undefined;
  const last = stops.length - 1;
  const percent = (input: number) => (last > 0 ? (positionOf(stops, input) / last) * 100 : 0);

  const commitText = (raw: string) => {
    if (raw.trim() === "") {
      onChange(null);
      return;
    }
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return;
    const next = Math.round(fromDisplay(parsed) / step) * step;
    onChange(defaultValue !== null && next === defaultValue ? null : next);
  };

  return (
    <div data-slot="range-field" className={cn("flex min-w-0 flex-col gap-2", className)}>
      <div className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <label htmlFor={`${baseId}-input`} className="text-sm font-medium">
          {label}
        </label>
        {defaultValue !== null && defaultLabel ? (
          <span
            data-range-default={value === null ? "current" : ""}
            className="text-xs text-muted-foreground"
          >
            {defaultLabel}: {display(defaultValue)}
          </span>
        ) : null}
      </div>
      {description ? (
        <p id={`${baseId}-description`} className="text-xs text-muted-foreground">
          {description}
        </p>
      ) : null}
      <div className="flex min-w-0 items-center gap-3">
        <SliderPrimitive.Root
          className="min-w-0 flex-1"
          value={shown === null ? 0 : positionOf(stops, shown)}
          min={0}
          max={Math.max(1, last)}
          step={1}
          disabled={disabled}
          onValueChange={(next) => {
            const index = Array.isArray(next) ? next[0] : next;
            const picked = valueAt(stops, index, limit);
            if (picked < min) return;
            setEditing(false);
            onChange(defaultValue !== null && picked === defaultValue ? null : picked);
          }}
        >
          <SliderPrimitive.Control className="relative flex h-11 w-full touch-none items-center select-none">
            <SliderPrimitive.Track className="relative h-1.5 w-full rounded-full bg-muted">
              {capped ? (
                <div
                  aria-hidden="true"
                  data-range-capped=""
                  className="absolute inset-y-0 end-0 rounded-e-full bg-[repeating-linear-gradient(45deg,var(--color-muted-foreground)_0_2px,transparent_2px_6px)] opacity-40"
                  style={{ width: `${100 - percent(limit)}%` }}
                />
              ) : null}
              <SliderPrimitive.Indicator className="rounded-full bg-primary" />
              {defaultValue !== null ? (
                <div
                  aria-hidden="true"
                  data-range-default-tick=""
                  className="absolute top-1/2 h-3 w-0.5 -translate-x-1/2 -translate-y-1/2 bg-foreground/60"
                  style={{ insetInlineStart: `${percent(defaultValue)}%` }}
                />
              ) : null}
              <SliderPrimitive.Thumb
                aria-label={label}
                getAriaValueText={() => (shown === null ? "" : display(shown))}
                className="block size-5 rounded-full border-2 border-primary bg-background shadow-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50 data-disabled:opacity-50"
              />
            </SliderPrimitive.Track>
          </SliderPrimitive.Control>
        </SliderPrimitive.Root>
        <div className="flex shrink-0 items-center gap-1.5">
          <Input
            id={`${baseId}-input`}
            type="number"
            inputMode="decimal"
            autoComplete="off"
            className="min-h-11 w-24 tabular-nums"
            min={toDisplay(min)}
            max={toDisplay(limit)}
            step={inputStep ?? toDisplay(step)}
            value={editing ? text : shownText}
            disabled={disabled}
            aria-invalid={message ? true : undefined}
            aria-describedby={describedBy}
            onFocus={() => {
              setText(shownText);
              setEditing(true);
            }}
            onChange={(event) => {
              setText(event.target.value);
              commitText(event.target.value);
            }}
            onBlur={() => {
              setEditing(false);
              commitText(text);
            }}
          />
          <span className="text-sm text-muted-foreground">{unit}</span>
        </div>
      </div>
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        {capacityLine ? (
          <p id={`${baseId}-capacity`} className="text-xs text-muted-foreground">
            {capacityMessage}
          </p>
        ) : (
          <span />
        )}
        {value !== null && defaultValue !== null ? (
          <Button
            type="button"
            variant="ghost"
            size="touch"
            disabled={disabled}
            onClick={() => {
              setEditing(false);
              onChange(null);
            }}
          >
            <RotateCcw aria-hidden="true" />
            {resetLabel}
          </Button>
        ) : null}
      </div>
      {message ? (
        <p id={`${baseId}-error`} role="alert" className="text-sm text-destructive">
          {message}
        </p>
      ) : null}
    </div>
  );
}
