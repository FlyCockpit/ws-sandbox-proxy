import { Button } from "@wssp/ui/components/button";
import { Input } from "@wssp/ui/components/input";
import { Textarea } from "@wssp/ui/components/textarea";
import { cn } from "@wssp/ui/lib/utils";
import { Eye, EyeOff, Plus, Trash2 } from "lucide-react";
import type * as React from "react";
import { useId, useState } from "react";

/**
 * KEY / value rows with a `.env` text mode (template-forms `KeyValueEditor`).
 * Environment variables and labels are never a JSON textarea: the API may keep
 * a JSON object underneath, but people edit rows or `KEY=value` lines and may
 * paste a whole `.env` file. Problems show inline on the row (or the line in
 * text mode); the caller decides what counts as invalid or reserved.
 *
 * Local wssp wrapper; phase B swaps it for the template's identical copy.
 */

export type KeyValueRow = { id: string; key: string; value: string };

/** `valueCleared`: a caller cleared this row's value (e.g. a secret) and needs it typed again. */
export type KeyValueProblem =
  | "emptyKey"
  | "invalidKey"
  | "duplicateKey"
  | "reservedKey"
  | "valueCleared";

export type KeyValueEditorLabels = {
  key: string;
  value: string;
  add: string;
  remove: (key: string) => string;
  rowsMode: string;
  textMode: string;
  textHint: string;
  show: string;
  hide: string;
  problem: (problem: KeyValueProblem, key: string) => string;
  /** "Line 3: expected KEY=value". */
  lineProblem: (line: number) => string;
  empty: string;
  /** Shown when text mode is refused because a key has no `KEY=value` form. */
  unwritableKeys?: string;
};

const UNWRITABLE_KEYS_DEFAULT = "Some keys can't be written as KEY=value lines; edit them as rows.";

/**
 * A key `.env` text cannot carry: a leading `#` reads as a comment, `=` splits
 * early, and whitespace or quotes do not survive the round trip.
 */
const UNWRITABLE_KEY = /^#|[=\s"']/;
const hasUnwritableKey = (rows: readonly KeyValueRow[]) =>
  rows.some((row) => UNWRITABLE_KEY.test(row.key.trim()));

let rowSeq = 0;
export function newKeyValueRow(key = "", value = ""): KeyValueRow {
  rowSeq += 1;
  return { id: `kv-${rowSeq}`, key, value };
}

export function recordToRows(record: Record<string, string> | null | undefined): KeyValueRow[] {
  return Object.entries(record ?? {}).map(([key, value]) => newKeyValueRow(key, value));
}

/**
 * Rows to an object; blank rows (no key and no value) are dropped. Null
 * prototype: a `__proto__` key stays an own key instead of vanishing (and
 * `keyValueProblems` reports it as reserved).
 */
export function rowsToRecord(rows: readonly KeyValueRow[]): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  for (const row of rows) {
    if (!row.key.trim() && !row.value) continue;
    out[row.key.trim()] = row.value;
  }
  return out;
}

const needsQuotes = /[\s#"'\\]|^$/;
function quote(value: string): string {
  if (!needsQuotes.test(value) || value === "") return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
}

/** `KEY=value` lines; values with spaces, quotes or `#` are double-quoted. */
export function formatDotenv(rows: readonly KeyValueRow[]): string {
  return rows
    .filter((row) => row.key.trim() || row.value)
    .map((row) => `${row.key.trim()}=${quote(row.value)}`)
    .join("\n");
}

/**
 * Parse `.env` text: `KEY=value`, optional `export `, `#` comments, blank
 * lines, single- or double-quoted values (double quotes understand `\n`, `\"`
 * and `\\`), and an unquoted value's trailing ` # comment`. Lines without `=`
 * are reported by 1-based line number.
 */
export function parseDotenv(text: string): { rows: KeyValueRow[]; badLines: number[] } {
  const rows: KeyValueRow[] = [];
  const badLines: number[] = [];
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const body = line.startsWith("export ") ? line.slice(7).trimStart() : line;
    const eq = body.indexOf("=");
    if (eq <= 0) {
      badLines.push(index + 1);
      return;
    }
    const key = body.slice(0, eq).trim();
    let value = body.slice(eq + 1).trim();
    if (value.startsWith('"')) {
      const end = findClosingQuote(value);
      value =
        end === -1
          ? value.slice(1)
          : value
              .slice(1, end)
              .replace(/\\(["\\n])/g, (_match, ch: string) => (ch === "n" ? "\n" : ch));
    } else if (value.startsWith("'")) {
      const end = value.indexOf("'", 1);
      value = end === -1 ? value.slice(1) : value.slice(1, end);
    } else {
      const hash = value.search(/\s#/);
      if (hash !== -1) value = value.slice(0, hash).trimEnd();
    }
    rows.push(newKeyValueRow(key, value));
  });
  return { rows, badLines };
}

function findClosingQuote(value: string): number {
  for (let index = 1; index < value.length; index += 1) {
    if (value[index] === "\\") {
      index += 1;
      continue;
    }
    if (value[index] === '"') return index;
  }
  return -1;
}

/**
 * A key no object can hold as data: always reserved, whatever the caller's rules.
 */
const ALWAYS_RESERVED = new Set(["__proto__"]);

/**
 * Per-row problems: empty key with a value, pattern mismatch, duplicates,
 * reserved keys (the caller's, plus `__proto__`).
 */
export function keyValueProblems(
  rows: readonly KeyValueRow[],
  options: { keyPattern?: RegExp; reservedKey?: (key: string) => boolean } = {},
): Map<string, KeyValueProblem> {
  const problems = new Map<string, KeyValueProblem>();
  const seen = new Map<string, string>();
  for (const row of rows) {
    const key = row.key.trim();
    if (!key) {
      if (row.value) problems.set(row.id, "emptyKey");
      continue;
    }
    if (options.keyPattern && !options.keyPattern.test(key)) {
      problems.set(row.id, "invalidKey");
      continue;
    }
    if (ALWAYS_RESERVED.has(key) || options.reservedKey?.(key)) {
      problems.set(row.id, "reservedKey");
      continue;
    }
    if (seen.has(key)) {
      problems.set(row.id, "duplicateKey");
      continue;
    }
    seen.set(key, row.id);
  }
  return problems;
}

type Mode = "rows" | "text";

export function KeyValueEditor({
  id,
  label,
  description,
  rows,
  onChange,
  labels,
  problems,
  masked = false,
  disabled = false,
  maxRows,
  keyPlaceholder,
  valuePlaceholder,
  keyInputClassName,
  className,
  error,
  onValidityChange,
}: {
  id?: string;
  label: string;
  description?: React.ReactNode;
  rows: readonly KeyValueRow[];
  onChange: (rows: KeyValueRow[]) => void;
  labels: KeyValueEditorLabels;
  /** From `keyValueProblems` (or the caller's own rules); shown on the row. */
  problems?: ReadonlyMap<string, KeyValueProblem>;
  /** Mask values (secrets-style) with a per-row reveal. */
  masked?: boolean;
  disabled?: boolean;
  maxRows?: number;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  keyInputClassName?: string;
  className?: string;
  /** A whole-editor error (e.g. the server refused the set). */
  error?: string | null;
  /**
   * Called from the change handlers when the `.env` text gains or loses
   * lines that are not `KEY=value`. Those lines never reach `onChange`, so a
   * caller that submits `rows` must refuse while this reports `false`.
   * Switching back to rows (which drops them, visibly) reports `true`.
   */
  onValidityChange?: (valid: boolean) => void;
}) {
  const generatedId = useId();
  const baseId = id ?? generatedId;
  const [mode, setMode] = useState<Mode>("rows");
  const [text, setText] = useState("");
  const [badLines, setBadLines] = useState<number[]>([]);
  // Text mode was refused; the message stays until those keys are fixed.
  const [textRefused, setTextRefused] = useState(false);
  const showRefusal = textRefused && hasUnwritableKey(rows);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());
  // Rows edited in a multi-line box keep it, so removing the last newline
  // does not swap the box (and lose focus) mid-edit.
  const [multiline, setMultiline] = useState<ReadonlySet<string>>(new Set());
  const descriptionId = description ? `${baseId}-description` : undefined;
  const errorId = error ? `${baseId}-error` : undefined;
  const linesId = `${baseId}-lines`;
  const problemsId = `${baseId}-problems`;
  const hasRowProblems = problems !== undefined && problems.size > 0;
  const textInvalid = badLines.length > 0 || hasRowProblems || Boolean(error);
  const textDescribedBy =
    [badLines.length > 0 ? linesId : undefined, hasRowProblems ? problemsId : undefined, errorId]
      .filter(Boolean)
      .join(" ") || undefined;

  const update = (rowId: string, patch: Partial<KeyValueRow>) =>
    onChange(rows.map((row) => (row.id === rowId ? { ...row, ...patch } : row)));
  /** Text mode with `next` as its text: rows follow it, bad lines show and report invalid. */
  const showText = (next: string) => {
    const parsed = parseDotenv(next);
    const valid = parsed.badLines.length === 0;
    if (valid !== (badLines.length === 0)) onValidityChange?.(valid);
    setText(next);
    setBadLines(parsed.badLines);
    setMode("text");
    onChange(parsed.rows);
  };
  const switchMode = (next: Mode) => {
    if (next === mode) return;
    if (next === "text" && hasUnwritableKey(rows)) {
      // Such a key would be lost (or misread) after a trip through text.
      setTextRefused(true);
      return;
    }
    if (next === "text") setText(formatDotenv(rows));
    if (badLines.length > 0) onValidityChange?.(true);
    setBadLines([]);
    setMode(next);
  };
  const atMax = maxRows !== undefined && rows.length >= maxRows;

  return (
    <fieldset
      data-slot="key-value-editor"
      className={cn("flex min-w-0 flex-col gap-2", className)}
      disabled={disabled}
      aria-describedby={[descriptionId, errorId].filter(Boolean).join(" ") || undefined}
    >
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <legend className="text-sm font-medium">{label}</legend>
        <div className="flex items-center gap-1" role="group" aria-label={label}>
          {(["rows", "text"] as const).map((option) => (
            <Button
              key={option}
              type="button"
              size="touch"
              variant={mode === option ? "secondary" : "ghost"}
              aria-pressed={mode === option}
              onClick={() => switchMode(option)}
            >
              {option === "rows" ? labels.rowsMode : labels.textMode}
            </Button>
          ))}
        </div>
      </div>
      {description ? (
        <p id={descriptionId} className="text-xs text-muted-foreground">
          {description}
        </p>
      ) : null}
      {mode === "text" ? (
        <div className="flex min-w-0 flex-col gap-1">
          <Textarea
            id={`${baseId}-text`}
            aria-label={label}
            aria-invalid={textInvalid || undefined}
            aria-describedby={textDescribedBy}
            value={text}
            rows={Math.min(12, Math.max(4, text.split("\n").length + 1))}
            spellCheck={false}
            autoComplete="off"
            className="font-mono text-sm"
            placeholder="KEY=value"
            onChange={(event) => showText(event.target.value)}
          />
          <p className="text-xs text-muted-foreground">{labels.textHint}</p>
          {badLines.length > 0 ? (
            <div id={linesId} role="alert" className="text-sm text-destructive">
              {badLines.slice(0, 5).map((line) => (
                <p key={line}>{labels.lineProblem(line)}</p>
              ))}
            </div>
          ) : null}
          {problems && hasRowProblems ? (
            <div id={problemsId} role="alert" className="text-sm text-destructive">
              {rows
                .filter((row) => problems.has(row.id))
                .slice(0, 5)
                .map((row) => (
                  <p key={row.id}>
                    {labels.problem(problems.get(row.id) as KeyValueProblem, row.key.trim())}
                  </p>
                ))}
            </div>
          ) : null}
        </div>
      ) : (
        <div className="flex min-w-0 flex-col gap-2">
          {rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">{labels.empty}</p>
          ) : null}
          {rows.map((row, index) => {
            const problem = problems?.get(row.id);
            const problemId = problem ? `${baseId}-${row.id}-problem` : undefined;
            // A cleared value is the value box's problem; every other one is the key's.
            const valueProblem = problem === "valueCleared";
            const keyProblem = problem !== undefined && !valueProblem;
            const shown = !masked || revealed.has(row.id);
            const valueLines = row.value.split("\n").length;
            const multi = valueLines > 1 || multiline.has(row.id);
            const valueProps = {
              "aria-label": `${labels.value} ${index + 1}`,
              "aria-invalid": valueProblem ? true : undefined,
              "aria-describedby": valueProblem ? problemId : undefined,
              value: row.value,
              placeholder: valuePlaceholder ?? labels.value,
              autoComplete: "off",
              spellCheck: false,
            } as const;
            return (
              <div key={row.id} data-key-value-row="" className="flex min-w-0 flex-col gap-1">
                {/* Phones stack the key above its value so a name like NODE_VERSION
                    is never cut; from sm: key, value and remove share one row. */}
                <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-start gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_auto]">
                  <Input
                    id={index === 0 ? `${baseId}-first` : undefined}
                    aria-label={`${labels.key} ${index + 1}`}
                    aria-invalid={keyProblem ? true : undefined}
                    aria-describedby={keyProblem ? problemId : undefined}
                    value={row.key}
                    placeholder={keyPlaceholder ?? labels.key}
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    className={cn(
                      "col-start-1 row-start-1 min-h-11 font-mono sm:col-auto sm:row-auto",
                      keyInputClassName,
                    )}
                    onChange={(event) => update(row.id, { key: event.target.value })}
                    onPaste={(event) => {
                      // Pasting a whole .env into a key box fills the rows.
                      const pasted = event.clipboardData.getData("text");
                      if (!pasted.includes("\n") && !/^[^=\s]+=/.test(pasted)) return;
                      const parsed = parseDotenv(pasted);
                      if (parsed.rows.length === 0) return;
                      event.preventDefault();
                      const before = rows.slice(0, index);
                      const after = rows.slice(index + 1);
                      const keep = row.key || row.value ? [row] : [];
                      if (parsed.badLines.length > 0) {
                        // Never apply part of a paste: the whole text opens in
                        // text mode, where its unreadable lines show (and report).
                        showText(
                          [formatDotenv([...before, ...keep]), pasted, formatDotenv(after)]
                            .filter(Boolean)
                            .join("\n"),
                        );
                        return;
                      }
                      onChange([...before, ...keep, ...parsed.rows, ...after]);
                    }}
                  />
                  <div className="relative col-start-1 row-start-2 min-w-0 sm:col-auto sm:row-auto">
                    {multi && shown ? (
                      // A one-line box strips newlines, so a multi-line value
                      // (e.g. from pasted .env text) is edited in a textarea.
                      <Textarea
                        {...valueProps}
                        rows={Math.min(6, valueLines)}
                        className={cn("min-h-11 max-h-40 font-mono", masked && "pe-11")}
                        onChange={(event) => {
                          if (!multiline.has(row.id))
                            setMultiline((current) => new Set(current).add(row.id));
                          update(row.id, { value: event.target.value });
                        }}
                      />
                    ) : (
                      <Input
                        {...valueProps}
                        type={shown ? "text" : "password"}
                        // Editing a hidden multi-line value here would drop its
                        // newlines: reveal it to edit.
                        readOnly={multi}
                        className={cn("min-h-11 font-mono", masked && "pe-11")}
                        onChange={(event) => update(row.id, { value: event.target.value })}
                      />
                    )}
                    {masked ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-touch"
                        className="absolute end-0 top-0"
                        aria-label={shown ? labels.hide : labels.show}
                        aria-pressed={shown}
                        onClick={() =>
                          setRevealed((current) => {
                            const next = new Set(current);
                            if (next.has(row.id)) next.delete(row.id);
                            else next.add(row.id);
                            return next;
                          })
                        }
                      >
                        {shown ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                      </Button>
                    ) : null}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-touch"
                    className="col-start-2 row-span-2 row-start-1 self-center sm:col-auto sm:row-span-1 sm:row-auto sm:self-start"
                    aria-label={labels.remove(row.key.trim() || String(index + 1))}
                    onClick={() => onChange(rows.filter((candidate) => candidate.id !== row.id))}
                  >
                    <Trash2 aria-hidden="true" />
                  </Button>
                </div>
                {problem ? (
                  <p id={problemId} role="alert" className="text-sm text-destructive">
                    {labels.problem(problem, row.key.trim())}
                  </p>
                ) : null}
              </div>
            );
          })}
          <div>
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={atMax}
              onClick={() => onChange([...rows, newKeyValueRow()])}
            >
              <Plus aria-hidden="true" />
              {labels.add}
            </Button>
          </div>
          {showRefusal ? (
            <p role="alert" data-unwritable-keys="" className="text-sm text-destructive">
              {labels.unwritableKeys ?? UNWRITABLE_KEYS_DEFAULT}
            </p>
          ) : null}
        </div>
      )}
      {error ? (
        <p id={errorId} role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}
