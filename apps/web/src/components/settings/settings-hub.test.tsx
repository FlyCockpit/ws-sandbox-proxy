import enSettings from "@wssp/locales/src/en-US/settings.json";
import esSettings from "@wssp/locales/src/es-MX/settings.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider } from "react-i18next";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string };
  }) => (
    <a className={className} href={to.replace("$lang", params?.lang ?? "$lang")}>
      {children}
    </a>
  ),
}));

import { settingsHubGroups } from "@/lib/nav-items";

import { AccountSettingsLayout } from "./account-settings-layout";
import { SettingsHub } from "./settings-hub";

const bundles = { "en-US": enSettings, "es-MX": esSettings } as const;
type Lang = keyof typeof bundles;
const instances = {} as Record<Lang, I18n>;
const missing: string[] = [];

beforeAll(async () => {
  for (const lang of Object.keys(bundles) as Lang[]) {
    const instance = createInstance();
    await instance.init({
      lng: lang,
      fallbackLng: false,
      ns: ["settings"],
      defaultNS: "settings",
      resources: { [lang]: { settings: bundles[lang] } },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
      saveMissing: true,
      missingKeyHandler: (_l, ns, key) => missing.push(`${lang}:${ns}:${key}`),
    });
    instances[lang] = instance;
  }
});

const render = (lang: Lang, node: ReactNode) =>
  renderToStaticMarkup(<I18nextProvider i18n={instances[lang]}>{node}</I18nextProvider>);
const anchors = (html: string) => [...html.matchAll(/<a\b[^>]*>/g)].map((m) => m[0]);
const href = (tag: string) => /href="([^"]+)"/.exec(tag)?.[1];

describe("settings hub", () => {
  it.each(["en-US", "es-MX"] as const)(
    "%s: one 44px card link per hub page, grouped, all translated",
    (lang) => {
      missing.length = 0;
      const html = render(lang, <SettingsHub lang={lang} />);
      const expected = settingsHubGroups.flatMap((group) =>
        group.items.map((item) => `/${lang}${item.path}`),
      );
      expect(anchors(html).map(href)).toEqual(expected);
      for (const tag of anchors(html)) expect(tag).toMatch(/\bmin-h-11\b/);
      expect(html.match(/<h2\b/g)).toHaveLength(settingsHubGroups.length);
      expect(html).toContain(bundles[lang].hub.items.pools.label.replace("&", "&amp;"));
      expect(missing).toEqual([]);
    },
  );

  it("account pages show the back link and the Profile · Security · Images tabs", () => {
    const html = render(
      "en-US",
      <AccountSettingsLayout lang="en-US">
        <p>body</p>
      </AccountSettingsLayout>,
    );
    expect(anchors(html).map(href)).toEqual([
      "/en-US/settings",
      "/en-US/settings/profile",
      "/en-US/settings/security",
      "/en-US/settings/images",
    ]);
    for (const tag of anchors(html)) expect(tag).toMatch(/\bmin-h-11\b/);
    expect(html).toContain(enSettings.hub.back);
    // In-page tabs, not a second nav landmark.
    expect(html).not.toContain("<nav");
  });
});
