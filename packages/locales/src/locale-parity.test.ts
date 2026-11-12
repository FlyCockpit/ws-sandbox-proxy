import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { DEFAULT_LOCALE, SUPPORTED_LOCALES } from "@wssp/config/locales";
import { describe, expect, it } from "vitest";

const root = dirname(fileURLToPath(import.meta.url));

type Bundle = Record<string, unknown>;

function namespaces(locale: string): string[] {
  return readdirSync(join(root, locale))
    .filter((file) => file.endsWith(".json"))
    .map((file) => file.slice(0, -".json".length))
    .sort();
}

function bundle(locale: string, ns: string): Bundle {
  return JSON.parse(readFileSync(join(root, locale, `${ns}.json`), "utf8")) as Bundle;
}

/** Leaf key paths with their values, e.g. `nav.hosts` → "Hosts". */
function leaves(value: Bundle, prefix = ""): Map<string, unknown> {
  const out = new Map<string, unknown>();
  for (const [key, child] of Object.entries(value)) {
    if (typeof child === "object" && child !== null && !Array.isArray(child)) {
      for (const [path, leaf] of leaves(child as Bundle, `${prefix}${key}.`)) out.set(path, leaf);
    } else {
      out.set(`${prefix}${key}`, child);
    }
  }
  return out;
}

/** `{{name}}` interpolation variables and `<0>…</0>` Trans tags in a string. */
function placeholders(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return [...value.matchAll(/\{\{\s*([^}\s]+)\s*\}\}|<\/?(\d+)>/g)].map((m) => m[0]).sort();
}

const others = SUPPORTED_LOCALES.filter((locale) => locale !== DEFAULT_LOCALE);

describe("locale bundles — every supported locale matches the default locale", () => {
  it("every supported locale ships exactly the default locale's namespaces", () => {
    expect(namespaces(DEFAULT_LOCALE).length).toBeGreaterThan(0);
    for (const locale of others)
      expect(namespaces(locale), locale).toEqual(namespaces(DEFAULT_LOCALE));
  });

  it.each(
    others.flatMap((locale) => namespaces(DEFAULT_LOCALE).map((ns) => [locale, ns] as const)),
  )("%s/%s has the same keys, nonempty strings and the same placeholders", (locale, ns) => {
    const source = leaves(bundle(DEFAULT_LOCALE, ns));
    const target = leaves(bundle(locale, ns));
    expect([...target.keys()].sort()).toEqual([...source.keys()].sort());
    for (const [path, value] of target) {
      expect(typeof value === "string" && value.trim().length > 0, `${locale}/${ns}:${path}`).toBe(
        true,
      );
      expect(placeholders(value), `${locale}/${ns}:${path}`).toEqual(
        placeholders(source.get(path)),
      );
    }
  });
});

/**
 * One concept, one word (M7-S17): pages that name the same thing must use the
 * same term in every locale. Each group lists `namespace:key.path` entries
 * whose values must be identical.
 */
const SAME_TERM: readonly (readonly string[])[] = [
  ["hosts:drain.draining", "admin:observability.draining"],
  ["hosts:status.stale", "admin:observability.hostStatus.STALE"],
  ["hosts:tabs.hostCredentials", "hostCredentials:title", "hosts:enroll.tokenLink"],
  ["dashboard:nav.settings", "nav:items.settings", "settings:hub.title", "settings:hub.back"],
  ["dashboard:nav.activity", "operations:title"],
  ["settings:hub.items.logins.label", "settings:hub.groups.logins", "logins:title"],
  ["settings:hub.items.pools.label", "hosts:pools.title"],
  ["settings:navImages", "settings:hub.items.images.label"],
];

describe("terminology is consistent across pages", () => {
  it.each(
    SUPPORTED_LOCALES.flatMap((locale) => SAME_TERM.map((group) => [locale, group] as const)),
  )("%s: %j use one term", (locale, group) => {
    const values = group.map((ref) => {
      const [ns, path] = ref.split(":") as [string, string];
      return leaves(bundle(locale, ns)).get(path);
    });
    expect(values[0], `${locale} ${group[0]}`).toEqual(expect.any(String));
    for (const [index, value] of values.entries())
      expect(value, `${locale} ${group[index]}`).toBe(values[0]);
  });
});

describe("formatted dates never get a second period (M7-S18)", () => {
  // es-MX times end in "p.m.", so "…{{when}}." rendered "5:21 p.m..".
  it.each(
    SUPPORTED_LOCALES.flatMap((locale) => namespaces(locale).map((ns) => [locale, ns] as const)),
  )("%s/%s: no string ends with a date placeholder and a period", (locale, ns) => {
    for (const [path, value] of leaves(bundle(locale, ns)))
      expect(value, `${locale}/${ns}:${path}`).not.toMatch(/\{\{\s*(when|deadline)\s*\}\}\.$/);
  });
});

describe("template images are named by alias only (E-09)", () => {
  // Registration refuses fingerprints and digests; the requirements copy must
  // not offer them as a way to name the image.
  it.each(SUPPORTED_LOCALES)(
    "%s: requirements.image names an alias, not a fingerprint",
    (locale) => {
      const value = leaves(bundle(locale, "templates")).get("requirements.image");
      expect(value).toEqual(expect.any(String));
      expect(value).not.toMatch(/alias (or|o) (fingerprint|huella)/i);
    },
  );
});

describe("dashboard capacity hints match the real connect flags", () => {
  const fields = ["sandbox_memory_mib", "sandbox_vcpu_budget", "max_sandbox_cpu_count"] as const;
  const connect = readFileSync(join(root, "../../../apps/cli/src/commands/connect.rs"), "utf8");
  it.each(SUPPORTED_LOCALES)(
    "%s host and credential hints name supported optional flags",
    (locale) => {
      for (const field of fields) {
        // Clap derives a kebab-case flag only for a field marked `long`.
        expect(connect).toMatch(
          new RegExp(String.raw`#\[arg\(long[^\n]*\)\]\n    pub ${field}: Option<u32>`),
        );
        const flag = `--${field.replaceAll("_", "-")}`;
        for (const [ns, key] of [
          ["hosts", "connect.vmCapacityHint"],
          ["hostCredentials", "mint.vmCapacityHint"],
        ] as const) {
          const hint = leaves(bundle(locale, ns)).get(key);
          expect(hint).toContain(`<code>${flag}</code>`);
          expect(hint).toContain("<code>wssp connect</code>");
          expect(hint).toContain(
            locale === "en-US" ? "Each works alone" : "Cada uno funciona por separado",
          );
          expect(hint).toContain(
            locale === "en-US"
              ? "supply all three if all detection fails"
              : "usa los tres si falla toda la detección",
          );
        }
      }
    },
  );
  it("the dashboard guide uses those same flags", () => {
    const guide = readFileSync(join(root, "../../../docs/guide/hosts.md"), "utf8");
    for (const field of fields) expect(guide).toContain(`--${field.replaceAll("_", "-")}`);
    expect(guide).not.toContain("--memory-budget-mib");
    expect(guide).not.toContain("--max-cpu-count");
  });
});

describe("guide UI labels match en-US", () => {
  it.each([
    [
      "operations/templates.md",
      "templates",
      ["appendRevision", "appendWithSize", "manageRevision", "form.cpuCount", "form.memoryMiB"],
    ],
    ["guide/pools.md", "hosts", ["pools.members", "pools.add", "pools.create"]],
    ["guide/pools.md", "sandboxes", ["create.latest"]],
    ["guide/sandboxes.md", "sandboxes", ["create.latest", "create.size", "fields.allocation"]],
    ["guide/terminal.md", "terminal", ["actions.attach", "actions.reattach", "actions.copy"]],
  ] as const)("%s uses %s labels", (path, ns, keys) => {
    const guide = readFileSync(join(root, "../../../docs", path), "utf8").replace(/\s+/g, " ");
    for (const key of keys) {
      const label = leaves(bundle("en-US", ns)).get(key);
      expect(label).toEqual(expect.any(String));
      expect(guide).toContain(label);
    }
  });
});
