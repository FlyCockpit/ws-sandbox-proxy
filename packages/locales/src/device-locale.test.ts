import { expect, it } from "vitest";
import en from "./en-US/auth.json";
import es from "./es-MX/auth.json";

function paths(value: Record<string, unknown>, prefix = ""): string[] {
  return Object.entries(value)
    .flatMap(([key, child]) =>
      typeof child === "object" && child !== null
        ? paths(child as Record<string, unknown>, `${prefix}${key}.`)
        : [`${prefix}${key}`],
    )
    .sort();
}
it("device namespace has complete Spanish parity and nonempty translations", () => {
  expect(paths(es.device)).toEqual(paths(en.device));
  expect(JSON.stringify(es.device)).not.toContain(':""');
  expect(es.device.approve).not.toBe(en.device.approve);
});
