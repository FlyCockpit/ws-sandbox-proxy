import { isRedirect } from "@tanstack/react-router";
import { describe, expect, it } from "vitest";
import { Route as DashboardIndex } from "@/routes/$lang/_app/_auth/dashboard/index";

type Stub = { options: { beforeLoad?: unknown; component?: unknown } };

/** Runs a stub's `beforeLoad` and returns the redirect it throws. */
function redirectOf(route: Stub, params: Record<string, string>, search: Record<string, unknown>) {
  const beforeLoad = route.options.beforeLoad as (ctx: unknown) => unknown;
  try {
    beforeLoad({ params, search });
  } catch (thrown) {
    expect(isRedirect(thrown)).toBe(true);
    return (thrown as { options: Record<string, unknown> }).options;
  }
  throw new Error("beforeLoad did not redirect");
}

describe("/dashboard index", () => {
  it("sends /dashboard to Sandboxes", () => {
    expect(DashboardIndex.options.component).toBeUndefined();
    expect(redirectOf(DashboardIndex, { lang: "en-US" }, {})).toMatchObject({
      to: "/$lang/dashboard/sandboxes",
      params: { lang: "en-US" },
      replace: true,
    });
  });
});
