/** Pure shape and Unicode primitives shared by bounded environment maps. */
export function isSafeMapText(value: string): boolean {
  return (
    !value.includes("\0") &&
    Array.from(value).every((char) => {
      const point = char.codePointAt(0)!;
      return point < 0xd800 || point > 0xdfff;
    })
  );
}

export function isSafeMapName(name: string): boolean {
  return !["__proto__", "constructor", "prototype"].includes(name) && isSafeMapText(name);
}

/** Check own data properties before Zod can discard __proto__ or invoke accessors. */
export function isStringMapShape(value: unknown): value is Record<string, string> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== "string" || !isSafeMapName(key)) return false;
    const property = Object.getOwnPropertyDescriptor(value, key);
    return (
      property !== undefined &&
      property.enumerable === true &&
      "value" in property &&
      typeof property.value === "string" &&
      isSafeMapText(property.value)
    );
  });
}
