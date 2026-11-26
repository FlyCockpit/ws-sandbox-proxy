// @vitest-environment jsdom
import { THEME_INIT_SCRIPT } from "@wssp/config/theme-init";
import { afterEach, describe, expect, it } from "vitest";

import { useUiPreferences } from "./ui-preferences";

const attr = () => document.documentElement.getAttribute("data-sidebar");

afterEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-sidebar");
  useUiPreferences.setState({ sidebarCollapsed: false });
});

describe("sidebar width on the first frame", () => {
  it("the head bootstrap marks <html> from the persisted preference", () => {
    localStorage.setItem(
      "ui-preferences",
      JSON.stringify({ state: { sidebarCollapsed: true }, version: 0 }),
    );
    new Function(THEME_INIT_SCRIPT)();
    expect(attr()).toBe("collapsed");

    document.documentElement.removeAttribute("data-sidebar");
    localStorage.setItem(
      "ui-preferences",
      JSON.stringify({ state: { sidebarCollapsed: false }, version: 0 }),
    );
    new Function(THEME_INIT_SCRIPT)();
    expect(attr()).toBeNull();
  });

  it("survives a corrupt stored value", () => {
    localStorage.setItem("ui-preferences", "{not json");
    expect(() => new Function(THEME_INIT_SCRIPT)()).not.toThrow();
    expect(attr()).toBeNull();
  });

  it("the store keeps the attribute in step with the toggle and persists in the same shape", () => {
    useUiPreferences.getState().toggleSidebar();
    expect(attr()).toBe("collapsed");
    expect(JSON.parse(localStorage.getItem("ui-preferences") ?? "{}").state.sidebarCollapsed).toBe(
      true,
    );
    useUiPreferences.getState().toggleSidebar();
    expect(attr()).toBeNull();
    useUiPreferences.getState().setSidebarCollapsed(true);
    expect(attr()).toBe("collapsed");
  });
});
