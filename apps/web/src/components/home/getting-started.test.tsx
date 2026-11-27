// @vitest-environment jsdom
import { cleanup, fireEvent, render as renderDom, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, className, children }: { to: string; className?: string; children: ReactNode }) => (
    <a data-to={to} className={className}>
      {children}
    </a>
  ),
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { message: vi.fn() } }));

const { GettingStarted } = await import("./getting-started");
type Step = Parameters<typeof GettingStarted>[0]["steps"][number];

const i18n = createInstance();
beforeAll(async () => {
  await i18n.init({
    lng: "en-US",
    defaultNS: "common",
    resources: { "en-US": { common: enCommon } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});
afterEach(() => vi.unstubAllGlobals());

const steps: Step[] = [
  {
    id: "create",
    title: "Create your first project",
    description: "Give it a name.",
    done: true,
    actions: [{ label: "Create project", link: { to: "/$lang/dashboard/sandboxes/new" } }],
  },
  {
    id: "two-factor",
    title: "Turn on two-factor authentication",
    description: "A code from your phone.",
    done: false,
    actions: [
      {
        label: "Open security settings",
        link: { to: "/$lang/settings/security", params: { lang: "en-US" } },
      },
    ],
  },
];

/** Render with a fake browser: `wide` is whether `(min-width: 40rem)` matches. */
function render(list: Step[], { wide = true, hidden = false } = {}) {
  const storage = new Map<string, string>(hidden ? [["wssp.getting-started.hidden.u1", "1"]] : []);
  vi.stubGlobal("window", {
    matchMedia: () => ({ matches: wide }),
    localStorage: { getItem: (key: string) => storage.get(key) ?? null },
    addEventListener: () => {},
    removeEventListener: () => {},
  });
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <GettingStarted steps={list} scope="u1" />
    </I18nextProvider>,
  );
}

describe("GettingStarted", () => {
  it("shows the progress as 'n of m done'", () => {
    expect(render(steps)).toContain(">1 of 2 done<");
  });

  it("marks done steps from their data and shows the next action only for open ones", () => {
    const html = render(steps);
    expect(html).toMatch(/data-step="create" data-done=""/);
    expect(html).toMatch(/data-step="two-factor" class=/);
    expect(html).toContain("(Done)");
    expect(html).toContain("(To do)");
    // The open step's action is a link to where it gets done.
    expect(html).toContain('data-to="/$lang/settings/security"');
    expect(html).toContain(">Open security settings<");
    // The done step offers no action any more.
    expect(html).not.toContain(">Create project<");
  });

  it("renders nothing once every step is done", () => {
    expect(render(steps.map((step) => ({ ...step, done: true })))).toBe("");
  });

  it("renders nothing for a user who hid it", () => {
    expect(render(steps, { hidden: true })).toBe("");
  });

  it("is a disclosure, expanded from sm up", () => {
    const html = render(steps, { wide: true });
    const button = html.match(
      /<button type="button" aria-expanded="([^"]*)" aria-controls="([^"]*)"/,
    );
    expect(button?.[1]).toBe("true");
    expect(html).toContain(`<div id="${button?.[2]}" class=`);
    expect(html).not.toMatch(/<div id="[^"]*" hidden/);
  });

  it("is collapsed below sm, keeping the title and the progress visible", () => {
    const html = render(steps, { wide: false });
    expect(html).toMatch(/aria-expanded="false"/);
    expect(html).toMatch(/<div id="[^"]*" hidden=""/);
    expect(html).toContain(">Get started<");
    expect(html).toContain(">1 of 2 done<");
  });

  it("shows a step waiting on an earlier one without a button", () => {
    const html = render([
      { ...steps[1]!, id: "first" },
      { id: "after", title: "After", description: "Finish the first.", done: false, actions: [] },
    ]);
    const after = html.slice(html.indexOf('data-step="after"'));
    expect(after).toContain("Finish the first.");
    expect(after).not.toContain("<a ");
  });

  it("fills a primary action and outlines the rest, 44px tall", () => {
    const html = render([
      {
        ...steps[1]!,
        actions: [
          { label: "Go", link: { to: "/$lang/dashboard/templates" }, primary: true },
          { label: "Other", link: { to: "/$lang/settings/pools" } },
        ],
      },
    ]);
    const go =
      html.match(/<a data-to="\/\$lang\/dashboard\/templates" class="([^"]*)"/)?.[1]?.split(" ") ??
      [];
    const other =
      html.match(/<a data-to="\/\$lang\/settings\/pools" class="([^"]*)"/)?.[1]?.split(" ") ?? [];
    expect(go).toEqual(expect.arrayContaining(["bg-primary", "h-11"]));
    expect(other).toEqual(expect.arrayContaining(["border-input", "h-11"]));
  });

  it("offers Hide with a name that starts with its visible text", () => {
    const html = render(steps);
    expect(html).toMatch(/aria-label="Hide the getting-started checklist"[^>]*>Hide</);
  });
});

it("keeps a visible way to restore the checklist after hiding it", async () => {
  window.localStorage.clear();
  window.matchMedia = () => ({ matches: true }) as MediaQueryList;
  renderDom(
    <I18nextProvider i18n={i18n}>
      <GettingStarted steps={steps} scope="dom-test" />
    </I18nextProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: enCommon.gettingStarted.hideAriaLabel }));
  const show = screen.getByRole("button", { name: enCommon.gettingStarted.show });
  expect(show.className).toContain("min-h-11");
  show.focus();
  await userEvent.setup().keyboard("{Enter}");
  expect(document.activeElement).toBe(screen.getByRole("button", { name: /Get started/ }));
  expect(screen.getByRole("button", { name: enCommon.gettingStarted.hideAriaLabel })).toBeTruthy();
  cleanup();
});
