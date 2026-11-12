import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { hostsTabItems, primaryNavItems, settingsHubGroups } from "./nav-items";

/**
 * The generated route tree (`routeTree.gen.ts`, written by the web build) is
 * the registry the router actually serves. These checks tie it to the
 * navigation model: every primary section and Settings page is registered,
 * everything signed-in sits under the `_auth` gate, and the pre-move
 * `/dashboard/...` Settings paths survive only as redirect stubs.
 */
const src = join(dirname(fileURLToPath(import.meta.url)), "..");
const routeTree = readFileSync(join(src, "routeTree.gen.ts"), "utf8");
const authDir = join(src, "routes/$lang/_app/_auth");

function interfaceKeys(name: string): string[] {
  const start = routeTree.indexOf(`export interface ${name} {`);
  expect(start, `${name} missing from routeTree.gen.ts`).toBeGreaterThanOrEqual(0);
  const body = routeTree.slice(start, routeTree.indexOf("}", start));
  return [...body.matchAll(/^\s*'([^']+)':/gm)].map((match) => match[1] as string);
}

const routeIds = interfaceKeys("FileRoutesById");
const fullPaths = interfaceKeys("FileRoutesByFullPath");

function routeFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".tsx") && !file.split("/").some((p) => p.startsWith("-")))
    .map((file) => file.replace(/\.tsx$/, ""))
    .sort();
}

/** Real pages left under `/dashboard`: the three primary sections. */
const DASHBOARD_PAGES = [
  "operations",
  "operations/$operationId",
  "operations/index",
  "sandboxes",
  "sandboxes/$sandboxId",
  "sandboxes/index",
  "templates",
  "templates/builds/$buildId",
  "templates/builds/index",
  "templates/index",
];

const SETTINGS_PAGES = [
  "host-credentials",
  "hosts",
  "hosts/$hostId",
  "hosts/index",
  "images",
  "index",
  "logins",
  "logins/$loginId",
  "logins/index",
  "logins/sessions/$sessionId",
  "pools",
  "pools/index",
  "pools/invite",
  "profile",
  "sdk-keys",
  "security",
  "webhooks",
  "webhooks/$endpointId",
  "webhooks/index",
];

describe("signed-in routes in the generated route tree", () => {
  it("serves every primary section and every Settings hub page at a locale-prefixed URL", () => {
    for (const item of primaryNavItems)
      expect(fullPaths, item.path).toContain(`/$lang${item.path}`);
    const hubPaths = settingsHubGroups.flatMap((group) => group.items.map((item) => item.path));
    for (const path of [...hubPaths, ...hostsTabItems.map((item) => item.path)])
      expect(fullPaths, path).toContain(`/$lang${path}`);
    expect(fullPaths).toContain("/$lang/settings/");
    expect(fullPaths).toContain("/$lang/settings/hosts/$hostId");
    expect(fullPaths).toContain("/$lang/settings/pools/invite");
    expect(fullPaths).toContain("/$lang/settings/webhooks/$endpointId");
    expect(fullPaths).toContain("/$lang/settings/logins/sessions/$sessionId");
    expect(fullPaths).toContain("/$lang/dashboard/sandboxes/$sandboxId");
    expect(fullPaths).toContain("/$lang/dashboard/operations/$operationId");
  });

  it("puts every dashboard and settings route under the _auth session gate", () => {
    const appIds = routeIds.filter(
      (id) => /\/(dashboard|settings)(?:\/|$)/.test(id) && !id.startsWith("/$lang/_app/admin"),
    );
    expect(appIds.length).toBeGreaterThan(20);
    for (const id of appIds) expect(id.startsWith("/$lang/_app/_auth/"), id).toBe(true);
  });

  it("has exactly the expected route files under /dashboard and /settings", () => {
    expect(routeFiles(join(authDir, "dashboard"))).toEqual([...DASHBOARD_PAGES, "index"].sort());
    expect(routeFiles(join(authDir, "settings"))).toEqual(SETTINGS_PAGES);
  });

  it("redirects /dashboard to Sandboxes", () => {
    const file = readFileSync(join(authDir, "dashboard/index.tsx"), "utf8");
    expect(file).toContain(
      'throw redirect({ to: "/$lang/dashboard/sandboxes", params, replace: true });',
    );
    expect(file).not.toMatch(/component\s*:/);
  });

  it("mounts the app frame inside the forced-2FA gate, once, in _auth", () => {
    const authLayout = readFileSync(join(src, "routes/$lang/_app/_auth.tsx"), "utf8");
    expect(authLayout).toMatch(
      /<ForcedTwoFactorGate[^>]*>\s*<DashboardFrame lang=\{lang\} \/>\s*<\/ForcedTwoFactorGate>/,
    );
    for (const layout of ["dashboard.tsx", "settings.tsx"]) {
      const file = readFileSync(join(authDir, layout), "utf8");
      expect(file, layout).toContain("component: Outlet");
      expect(file, layout).not.toContain("DashboardFrame");
    }
  });

  it("keeps the _auth layout's login redirect carrying the intended href", () => {
    const authLayout = readFileSync(join(src, "routes/$lang/_app/_auth.tsx"), "utf8");
    expect(authLayout).toContain("decideProtectedRouteAccess(await getProtectedRouteSession())");
    expect(authLayout).toContain(
      "throw redirect(loginRedirect(params.lang, authRedirectHref(location)))",
    );
    // The invitation fragment is captured before any child (a stub) runs.
    expect(authLayout.indexOf("capturePoolInviteFragment()")).toBeLessThan(
      authLayout.indexOf("decideProtectedRouteAccess(await"),
    );
  });
});
