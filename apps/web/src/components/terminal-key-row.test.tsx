// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import en from "@wssp/locales/src/en-US/terminal.json";
import es from "@wssp/locales/src/es-MX/terminal.json";
import { afterEach, describe, expect, it, vi } from "vitest";

const locale = vi.hoisted(() => ({ value: "en-US" }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { state?: string }) => {
      const strings = locale.value === "es-MX" ? es : en;
      const path = key.replace("terminal:", "").split(".");
      let value: unknown = strings;
      for (const part of path) value = (value as Record<string, unknown>)[part];
      return typeof value === "string" ? value.replace("{{state}}", options?.state ?? "") : key;
    },
  }),
}));

import { TerminalKeyRow } from "./terminal-key-row";

afterEach(cleanup);
describe.each([
  ["en-US", en],
  ["es-MX", es],
] as const)("%s", (lang, strings) => {
  it("shows a short latch label while preserving the full accessible name", () => {
    locale.value = lang;
    render(
      <TerminalKeyRow
        terminal={{
          sendKeys: () => true,
          focus: vi.fn(),
          hasFocus: () => false,
          applicationCursorKeys: () => false,
          setKeyFilter: vi.fn(),
        }}
      />,
    );
    const ctrl = screen.getByRole("button", { name: `Ctrl (${strings.keys.latch.off})` });
    fireEvent.keyDown(ctrl, { key: "Enter" });
    expect(ctrl.getAttribute("aria-label")).toBe(`Ctrl (${strings.keys.latch.once})`);
    expect(ctrl.textContent).toContain(strings.keys.latch.onceShort);
    expect(ctrl.textContent).not.toContain(strings.keys.latch.once);
  });
});
