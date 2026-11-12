// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, beforeAll, expect, it } from "vitest";

import { INERT_THEME_SCRIPT_TYPE, ThemeProvider, useTheme } from "./theme-provider";

const providerProps = {
  attribute: "class",
  defaultTheme: "system",
  enableSystem: true,
  disableTransitionOnChange: true,
  storageKey: "vite-ui-theme",
} as const;

beforeAll(() => {
  // jsdom has no matchMedia; next-themes reads it for the "system" theme.
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  document.documentElement.className = "";
});

it("server-renders next-themes' bootstrap only as an inert, non-executable data block", () => {
  const html = renderToString(
    <ThemeProvider {...providerProps}>
      <p>child</p>
    </ThemeProvider>,
  );
  const scripts = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
  // next-themes always emits one inline script; it must never be executable,
  // since script-src only allowlists THEME_INIT_SCRIPT's hash and the nonce.
  expect(scripts).toHaveLength(1);
  expect(scripts[0]).toContain(`type="${INERT_THEME_SCRIPT_TYPE}"`);
  // Never a nonce: the inert block needs none and must not borrow one.
  expect(scripts[0]).not.toMatch(/nonce="[^"]+"/);
});

function Toggle() {
  const { setTheme, resolvedTheme } = useTheme();
  return (
    <>
      <span data-testid="resolved">{resolvedTheme}</span>
      <button type="button" onClick={() => setTheme("dark")}>
        dark
      </button>
      <button type="button" onClick={() => setTheme("light")}>
        light
      </button>
    </>
  );
}

it("still applies and persists theme switches at runtime", () => {
  render(
    <ThemeProvider {...providerProps}>
      <Toggle />
    </ThemeProvider>,
  );
  act(() => screen.getByRole("button", { name: "dark" }).click());
  expect(document.documentElement.classList.contains("dark")).toBe(true);
  expect(localStorage.getItem("vite-ui-theme")).toBe("dark");
  act(() => screen.getByRole("button", { name: "light" }).click());
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  expect(localStorage.getItem("vite-ui-theme")).toBe("light");
});
