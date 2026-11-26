import { describe, expect, it } from "vitest";

import {
  accountTabItems,
  getNavDirection,
  getNavItems,
  primaryNavItems,
  primarySectionFor,
  settingsHubGroups,
  stripLangPrefix,
  toLangRoute,
} from "./nav-items";

describe("nav-items", () => {
  it("returns public desktop items for signed-out visitors", () => {
    const items = getNavItems({
      placement: "desktop",
      isAuthenticated: false,
    }).map((item) => item.path);

    expect(items).toEqual(["/"]);
  });

  it("gives signed-in users no top-bar or extra mobile links (one nav surface)", () => {
    for (const placement of ["desktop", "mobile"] as const) {
      for (const showsAdmin of [false, true]) {
        expect(getNavItems({ placement, isAuthenticated: true, showsAdmin })).toEqual([]);
      }
    }
    expect(getNavItems({ placement: "mobile", isAuthenticated: false }).map((i) => i.path)).toEqual(
      ["/"],
    );
  });

  it("derives user-menu destinations from the shared nav model", () => {
    const userItems = getNavItems({
      placement: "userMenu",
      isAuthenticated: true,
      showsAdmin: false,
    }).map((item) => item.path);
    const adminItems = getNavItems({
      placement: "userMenu",
      isAuthenticated: true,
      showsAdmin: true,
    }).map((item) => item.path);

    expect(userItems).toEqual(["/settings"]);
    expect(adminItems).toEqual(["/settings", "/admin"]);
    expect(getNavItems({ placement: "userMenu", isAuthenticated: false })).toEqual([]);
  });

  it("builds typed locale-prefixed routes", () => {
    expect(toLangRoute("/")).toBe("/$lang");
    expect(toLangRoute("/dashboard/sandboxes")).toBe("/$lang/dashboard/sandboxes");
  });

  it("slides across primary sections in nav order", () => {
    expect(getNavDirection("/dashboard/sandboxes", "/settings")).toBe("forward");
    expect(getNavDirection("/settings", "/dashboard/templates")).toBe("back");
    expect(getNavDirection("/settings", "/")).toBe("back");
  });

  it("returns none for same-path navigation", () => {
    expect(getNavDirection("/settings", "/settings")).toBe("none");
  });

  it("returns forward for off-nav child routes", () => {
    expect(getNavDirection("/settings", "/settings/privacy")).toBe("forward");
  });

  it("returns back from child routes to their parent", () => {
    expect(getNavDirection("/settings/privacy", "/settings")).toBe("back");
  });

  it("slides across account tabs in tab order", () => {
    expect(getNavDirection("/settings/security", "/settings/profile")).toBe("back");
    expect(getNavDirection("/settings/profile", "/settings/images")).toBe("forward");
  });

  it("defaults unrelated routes to forward", () => {
    expect(getNavDirection("/dashboard/sandboxes", "/login")).toBe("forward");
  });

  it("strips the locale prefix from top-level routes", () => {
    expect(stripLangPrefix("/en-US/dashboard/sandboxes")).toBe("/dashboard/sandboxes");
  });

  it("returns root when only the locale segment is present", () => {
    expect(stripLangPrefix("/en-US")).toBe("/");
    expect(stripLangPrefix("/en-US/")).toBe("/");
  });

  it("preserves nested segments after stripping the locale prefix", () => {
    expect(stripLangPrefix("/en-US/settings/privacy")).toBe("/settings/privacy");
  });

  it("puts Sandboxes first, then Templates, Activity, Hosts, Terminals, and Settings at the bottom", () => {
    expect(primaryNavItems.map((item) => [item.id, item.path, item.group])).toEqual([
      ["sandboxes", "/dashboard/sandboxes", "main"],
      ["templates", "/dashboard/templates", "main"],
      ["activity", "/dashboard/operations", "main"],
      ["hosts", "/settings/hosts", "main"],
      ["terminals", "/dashboard/terminals", "main"],
      ["settings", "/settings", "footer"],
    ]);
    // Every section stays active on its children.
    expect(primaryNavItems.every((item) => !item.exact)).toBe(true);
    expect(new Set(primaryNavItems.map((item) => item.labelKey)).size).toBe(6);
  });

  it("pins Admin under Settings in the sidebar footer, for admins only", () => {
    const sidebar = (showsAdmin: boolean) =>
      getNavItems({ placement: "sidebar", isAuthenticated: true, showsAdmin }).map((i) => i.id);
    expect(sidebar(false)).toEqual([
      "sandboxes",
      "templates",
      "activity",
      "hosts",
      "terminals",
      "settings",
    ]);
    expect(sidebar(true)).toEqual([
      "sandboxes",
      "templates",
      "activity",
      "hosts",
      "terminals",
      "settings",
      "admin",
    ]);
    expect(getNavItems({ placement: "sidebar", isAuthenticated: false })).toEqual([]);
  });

  it("gives phones four tabs; the other sidebar sections go to More (five slots at most)", () => {
    for (const showsAdmin of [false, true]) {
      const tabs = getNavItems({ placement: "tabs", isAuthenticated: true, showsAdmin });
      expect(tabs.map((i) => i.id)).toEqual(["sandboxes", "templates", "activity", "settings"]);
      const sidebar = getNavItems({ placement: "sidebar", isAuthenticated: true, showsAdmin });
      const more = sidebar.filter((item) => !tabs.includes(item));
      expect(more.map((i) => i.id)).toEqual(
        showsAdmin ? ["hosts", "terminals", "admin"] : ["hosts", "terminals"],
      );
      expect(tabs.length + 1).toBeLessThanOrEqual(5);
    }
  });

  it.each([
    ["/en-US/dashboard/sandboxes", "sandboxes"],
    ["/es-MX/dashboard/sandboxes/abc", "sandboxes"],
    ["/en-US/dashboard/templates/builds/b1", "templates"],
    ["/en-US/dashboard/operations/op1", "activity"],
    ["/en-US/dashboard/terminals", "terminals"],
    ["/en-US/settings", "settings"],
    ["/en-US/settings/hosts", "hosts"],
    ["/en-US/settings/hosts/h1", "hosts"],
    ["/en-US/settings/host-credentials", "hosts"],
    ["/en-US/settings/hostsx", "settings"],
    ["/en-US/settings/pools", "settings"],
    ["/en-US/settings/logins/sessions/s1", "settings"],
    ["/settings/security", "settings"],
    ["/en-US/admin", "admin"],
    ["/en-US/admin/users", "admin"],
    ["/en-US/dashboard", null],
    ["/en-US/dashboard/sandboxesx", null],
    ["/en-US/administrator", null],
    ["/en-US", null],
  ])("maps %s to the %s section", (pathname, section) => {
    expect(primarySectionFor(pathname)).toBe(section);
  });

  it("groups every set-up-once page in the Settings hub, each once, under /settings", () => {
    const paths = settingsHubGroups.flatMap((group) => group.items.map((item) => item.path));
    expect(settingsHubGroups.map((group) => group.id)).toEqual([
      "infrastructure",
      "developer",
      "logins",
      "account",
    ]);
    expect(paths).toEqual([
      "/settings/hosts",
      "/settings/pools",
      "/settings/sdk-keys",
      "/settings/agent-tokens",
      "/settings/webhooks",
      "/settings/logins",
      "/settings/profile",
      "/settings/security",
      "/settings/images",
    ]);
    expect(accountTabItems.map((item) => item.path)).toEqual([
      "/settings/profile",
      "/settings/security",
      "/settings/images",
    ]);
  });

  it("builds locale routes for settings pages", () => {
    expect(toLangRoute("/settings/host-credentials")).toBe("/$lang/settings/host-credentials");
  });
});
