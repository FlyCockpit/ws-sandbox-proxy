import type { KeyValueEntry } from "@wssp/ui/components/key-value-editor";
import { isUnparsedEntry } from "@wssp/ui/components/key-value-editor";
import type { FieldLike } from "@wssp/ui/components/text-field";
import { isBlankEntry, scanDotenv } from "@wssp/ui/lib/dotenv";

/**
 * Glue between the shared `KeyValueEditor` (`KeyValueEntry[]`) and the JSON
 * objects the API takes (envs, labels, build args).
 */

/**
 * Names no object can hold as data. The server refuses them for envs and
 * labels; the editor's default key rule accepts `__proto__`, so callers pass
 * these as `reservedKeys` and they are flagged inline.
 */
export const PROTOTYPE_NAMES = ["__proto__", "constructor", "prototype"] as const;

/**
 * Entries as an object: blank rows dropped, values exactly as typed (a value
 * may hold a newline; nothing goes through `.env` text). Null prototype: a
 * `__proto__` key stays an own key, so the server refuses it instead of it
 * vanishing. A later duplicate wins (the editor flags duplicates anyway).
 */
export function entriesToRecord(entries: readonly KeyValueEntry[]): Record<string, string> {
  const record = Object.create(null) as Record<string, string>;
  for (const entry of entries) if (!isBlankEntry(entry)) record[entry.key] = entry.value;
  return record;
}

/** An object as editor entries, in its key order. */
export function recordToEntries(
  record: Readonly<Record<string, string>> | null | undefined,
): KeyValueEntry[] {
  return Object.entries(record ?? {}).map(([key, value]) => ({ key, value }));
}

/** A `.env` line that did not parse, kept as a flagged row: never sent. */
export function isUnreadLine(entry: KeyValueEntry): boolean {
  return isUnparsedEntry(entry) && !isBlankEntry(entry);
}

/**
 * Whether every row survives the editor's `.env` text view. A key that text
 * cannot carry (a leading `#` reads as a comment and is dropped; `=`,
 * whitespace or quotes split or break the line) would be lost or turned into
 * an unread line there, so the caller keeps such a list in rows. Empty keys
 * and unread lines round-trip verbatim.
 */
export function entriesFitDotenvText(entries: readonly KeyValueEntry[]): boolean {
  return entries.every((entry) => {
    if (isBlankEntry(entry) || isUnparsedEntry(entry) || entry.key === "") return true;
    const [statement, ...rest] = scanDotenv(`${entry.key}=`);
    return rest.length === 0 && statement?.kind === "entry" && statement.entry.key === entry.key;
  });
}

/**
 * A field over page state, for the shared editors (which take a TanStack
 * `<form.Field>` object): `errors` show under the editor and mark it invalid
 * for `focusFirstInvalidField`.
 */
export function stateField<T>(
  name: string,
  value: T,
  errors: readonly string[],
  onChange: (next: T) => void,
): FieldLike<T> {
  return {
    name,
    state: { value, meta: { errors } },
    handleBlur: () => {},
    handleChange: onChange,
  };
}
