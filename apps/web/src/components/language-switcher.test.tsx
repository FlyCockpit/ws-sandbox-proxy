// @vitest-environment jsdom

import { cleanup, render } from "@testing-library/react";
import enNav from "@wssp/locales/src/en-US/nav.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

/**
 * M7-S2: below `md` the language switcher is a 44 px icon-only button (label
 * and chevron hidden), as in the WMP reference. With its full "English (US)"
 * label the header's min-content was 378 px, so at 320 px the user menu and
 * the right edge of every page were clipped. Real layout needs a browser (the
 * M7 smoke re-check measures it); these assertions pin the classes that make
 * the switcher collapse, for both the eager shell and the lazy Select.
 */

vi.mock("@tanstack/react-router", () => ({ useRouter: () => ({ navigate: vi.fn() }) }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({ state: { status: "anonymous" }, meta: { isDegraded: false } }),
}));
vi.mock("@/utils/orpc", () => ({
  orpc: { auth: { updateLocale: { mutationOptions: () => ({ mutationFn: vi.fn() }) } } },
}));
vi.mock("@tanstack/react-query", () => ({ useMutation: () => ({ mutate: vi.fn() }) }));
vi.mock("@wssp/ui/components/select", () => ({
  Select: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SelectTrigger: ({ children, className }: { children: ReactNode; className?: string }) => (
    <button type="button" data-testid="select-trigger" className={className}>
      {children}
    </button>
  ),
  SelectValue: ({ children, className }: { children: ReactNode; className?: string }) => (
    <span data-testid="select-value" className={className}>
      {children}
    </span>
  ),
  SelectContent: () => null,
  SelectItem: () => null,
}));

import { LanguageSwitcher } from "./language-switcher";
import LanguageSwitcherSelect from "./language-switcher-select";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["nav"],
    defaultNS: "nav",
    resources: { "en-US": { nav: enNav } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});
afterEach(() => cleanup());

const classes = (element: Element | null) =>
  new Set((element?.getAttribute("class") ?? "").split(/\s+/));

describe("language switcher at phone width (M7-S2)", () => {
  it("the eager shell is a 44 px icon button below md, with label and chevron hidden", () => {
    const view = render(
      <I18nextProvider i18n={i18n}>
        <LanguageSwitcher />
      </I18nextProvider>,
    );
    const trigger = view.container.querySelector('[data-slot="select-trigger"]');
    expect(trigger?.getAttribute("aria-label")).toBe(enNav.languageLabel);
    for (const token of ["w-11!", "px-0", "md:w-fit!", "md:px-3"])
      expect(classes(trigger).has(token), token).toBe(true);
    const label = view.container.querySelector('[data-slot="select-value"]');
    expect(label?.textContent).toBe("English (US)");
    expect(classes(label).has("hidden!") && classes(label).has("md:flex!")).toBe(true);
    const svgs = trigger?.querySelectorAll("svg") ?? [];
    const chevron = svgs[svgs.length - 1] ?? null;
    expect(classes(chevron).has("hidden!") && classes(chevron).has("md:block!")).toBe(true);
  });

  it("the lazy Select keeps the same icon-only trigger below md", () => {
    const view = render(
      <I18nextProvider i18n={i18n}>
        <LanguageSwitcherSelect />
      </I18nextProvider>,
    );
    const trigger = view.getByTestId("select-trigger");
    for (const token of ["w-11!", "px-0", "md:w-fit!", "[&_svg:last-child]:hidden"])
      expect(classes(trigger).has(token), token).toBe(true);
    const value = view.getByTestId("select-value");
    expect(classes(value).has("hidden!") && classes(value).has("md:flex!")).toBe(true);
  });
});
