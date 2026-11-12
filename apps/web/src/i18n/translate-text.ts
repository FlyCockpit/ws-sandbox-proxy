import type { TFunction } from "i18next";

/** Keep display values opaque, including i18next syntax inside owner-entered labels.
 * i18next can replace an earlier inserted {{slug}} when resolving a later slot.
 * Translate marker values first, then substitute text in a single pass. Use only
 * for plain display strings; rich translations carry values as component children.
 */
export function translateText(
  t: TFunction,
  key: string,
  values: Record<string, string | number>,
): string {
  const markers = Object.fromEntries(
    Object.keys(values).map((name) => [name, `\uE000${name}\uE001`]),
  );
  return t(key, markers).replace(/\uE000([^\uE001]+)\uE001/g, (marker, name: string) =>
    Object.hasOwn(values, name) ? String(values[name]) : marker,
  );
}
