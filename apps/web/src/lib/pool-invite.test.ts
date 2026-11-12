// @vitest-environment jsdom
import { beforeEach, expect, it } from "vitest";
import {
  authRedirectHref,
  capturePoolInviteFragment,
  clearPoolInviteToken,
  poolInviteToken,
  postAuthHref,
} from "./pool-invite";

beforeEach(() => clearPoolInviteToken());
it("captures a bounded invitation in memory and removes the fragment before routing; reload needs the original link", () => {
  const token = `wssp_inv_${"a".repeat(43)}`;
  window.history.replaceState(null, "", `/es-MX/settings/pools/invite#${token}`);
  capturePoolInviteFragment();
  expect(window.location.hash).toBe("");
  expect(window.location.search).toBe("");
  expect(window.history.state).toBeNull();
  expect(poolInviteToken()).toBe(token);
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
  clearPoolInviteToken();
  capturePoolInviteFragment();
  expect(poolInviteToken()).toBeUndefined();
});
it("scrubs malformed fragments without accepting query tokens or tokens on unrelated paths", () => {
  window.history.replaceState(null, "", "/en-US/settings/pools/invite?token=never#bad");
  capturePoolInviteFragment();
  expect(window.location.href).not.toContain("bad");
  expect(window.location.search).toBe("");
  expect(poolInviteToken()).toBeUndefined();
  window.history.replaceState(null, "", `/en-US/login#wssp_inv_${"b".repeat(43)}`);
  capturePoolInviteFragment();
  expect(poolInviteToken()).toBeUndefined();
});

it("preserves router history metadata while removing the invitation fragment", () => {
  const state = { __TSR_index: 2, key: "route-key" };
  window.history.replaceState(state, "", `/en-US/settings/pools/invite#wssp_inv_${"h".repeat(43)}`);
  capturePoolInviteFragment();
  expect(window.history.state).toEqual(state);
  expect(window.location.hash).toBe("");
});

it("keeps ordinary intended hrefs and refuses all invitation secrets in redirect parameters", () => {
  expect(
    authRedirectHref({
      pathname: "/en-US/dashboard/sandboxes/id",
      href: "/en-US/dashboard/sandboxes/id?tab=files#entry",
    }),
  ).toBe("/en-US/dashboard/sandboxes/id?tab=files#entry");
  expect(
    authRedirectHref({
      pathname: "/es-MX/settings/pools/invite",
      href: "/es-MX/settings/pools/invite?token=discard#discard",
    }),
  ).toBe("/es-MX/settings/pools/invite");
});

it("carries the in-memory invitation across the post-sign-in reload as a same-origin fragment only", () => {
  const token = `wssp_inv_${"d".repeat(43)}`;
  // Signed out: no token yet, every target unchanged.
  expect(postAuthHref("/en-US/settings/pools/invite", "en-US")).toBe(
    "/en-US/settings/pools/invite",
  );
  window.history.replaceState(null, "", `/en-US/settings/pools/invite#${token}`);
  capturePoolInviteFragment();
  // The login redirect parameter never carries it…
  expect(
    authRedirectHref({
      pathname: "/en-US/settings/pools/invite",
      href: `/en-US/settings/pools/invite#${token}`,
    }),
  ).toBe("/en-US/settings/pools/invite");
  // …but the post-auth navigation back to the invitation does, as a fragment.
  for (const section of ["settings"]) {
    const target = `/en-US/${section}/pools/invite`;
    const href = postAuthHref(target, "en-US");
    expect(href).toBe(`${target}#${token}`);
    expect(new URL(href, "https://app.example").search).toBe("");
  }
  // Never onto another page, a query-bearing target, another locale or origin.
  for (const target of [
    "/en-US/dashboard",
    "/en-US/settings/pools/invite?x=1",
    "/es-MX/settings/pools/invite",
    "https://evil.example/en-US/settings/pools/invite",
    "//evil.example/en-US/settings/pools/invite",
  ]) {
    expect(postAuthHref(target, "en-US")).toBe(target);
  }
  // The reloaded invitation page takes it back into memory and scrubs it.
  const reloaded = postAuthHref("/en-US/settings/pools/invite", "en-US");
  clearPoolInviteToken(); // the reload drops module memory
  window.history.replaceState(null, "", reloaded);
  capturePoolInviteFragment();
  expect(poolInviteToken()).toBe(token);
  expect(window.location.hash).toBe("");
  expect(sessionStorage.length).toBe(0);
  expect(localStorage.length).toBe(0);
});

it("login's full-page post-auth navigations all go through postAuthHref", async () => {
  const { readFileSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const source = readFileSync(
    resolve(import.meta.dirname, "../routes/$lang/_app/login.tsx"),
    "utf8",
  );
  const assigns = source.match(/window\.location\.assign\([^)]*\)/g) ?? [];
  expect(assigns.length).toBeGreaterThan(0);
  for (const call of assigns) expect(call).toMatch(/^window\.location\.assign\(postAuthHref\(/);
});
