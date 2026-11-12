// @vitest-environment jsdom
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
  useRouterState,
} from "@tanstack/react-router";
import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAIN_SCROLLER_ID, MAIN_SCROLLER_SELECTOR } from "@/lib/main-scroller";
import { useHashTargetScroll } from "./use-hash-target-scroll";

const scrolled: string[] = [];
const originalScrollIntoView = Element.prototype.scrollIntoView;
const originalScrollTo = Element.prototype.scrollTo;
beforeEach(() => {
  scrolled.length = 0;
  Element.prototype.scrollIntoView = function (this: Element) {
    scrolled.push(this.id);
  };
  vi.stubGlobal("scrollTo", vi.fn());
  vi.stubGlobal("scrollX", 0);
  vi.stubGlobal("scrollY", 0);
  Element.prototype.scrollTo = function (this: Element, options?: ScrollToOptions | number) {
    if (typeof options === "object") {
      this.scrollTop = options.top ?? 0;
      this.scrollLeft = options.left ?? 0;
    }
  };
});
afterEach(() => {
  cleanup();
  Element.prototype.scrollIntoView = originalScrollIntoView;
  Element.prototype.scrollTo = originalScrollTo;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Root() {
  useHashTargetScroll();
  const group = useRouterState({
    select: (state) => (state.location.pathname === "/a" ? "app" : "public"),
  });
  return (
    <main key={group} id="main-content" tabIndex={-1} data-scroll-restoration-id={MAIN_SCROLLER_ID}>
      <Outlet />
    </main>
  );
}
function setup() {
  const root = createRootRoute({ component: Root });
  const routes = [
    createRoute({ getParentRoute: () => root, path: "/a", component: () => <p>A</p> }),
    createRoute({
      getParentRoute: () => root,
      path: "/b",
      component: () => (
        <>
          <a href="#main-content">Skip</a>
          <button type="button" id="target">
            Target
          </button>
          <section id="second">Second</section>
        </>
      ),
    }),
  ];
  const router = createRouter({
    routeTree: root.addChildren(routes),
    history: createMemoryHistory({ initialEntries: ["/a"] }),
    scrollRestoration: true,
    scrollToTopSelectors: [MAIN_SCROLLER_SELECTOR],
    defaultHashScrollIntoView: false,
  });
  render(<RouterProvider router={router} />);
  return router;
}
const main = () => document.querySelector<HTMLElement>(MAIN_SCROLLER_SELECTOR)!;
const read = (offset: number) => {
  main().scrollTop = offset;
  fireEvent.scroll(main());
};

describe("main scroller and hash integration", () => {
  it("resets new pages, restores Back/Forward offsets across layout remounts, and preserves in-place filters", async () => {
    const router = setup();
    await waitFor(() => expect(main()).toBeTruthy());
    read(320);
    const first = main();
    await act(() => router.navigate({ href: "/b" }));
    expect(main()).not.toBe(first);
    expect(main().scrollTop).toBe(0);
    read(640);
    await act(async () => {
      router.history.back();
    });
    await waitFor(() => expect(router.state.location.pathname).toBe("/a"));
    expect(main().scrollTop).toBe(320);
    await act(async () => {
      router.history.forward();
    });
    await waitFor(() => expect(router.state.location.pathname).toBe("/b"));
    expect(main().scrollTop).toBe(640);
    await act(() =>
      router.navigate({ href: "/b?filter=active", replace: true, resetScroll: false }),
    );
    expect(main().scrollTop).toBe(640);
  });
  it("reveals a router hash target, focuses it, and leaves POP restoration alone", async () => {
    const router = setup();
    await waitFor(() => expect(main()).toBeTruthy());
    await act(() => router.navigate({ href: "/b#target" }));
    await waitFor(() => expect(scrolled).toEqual(["target"]));
    expect(document.activeElement?.id).toBe("target");
    read(450);
    await act(() => router.navigate({ href: "/a" }));
    await act(async () => {
      router.history.back();
    });
    await waitFor(() => expect(router.state.location.pathname).toBe("/b"));
    expect(scrolled).toEqual(["target"]);
    expect(main().scrollTop).toBe(450);
  });
  it("focuses main for repeated skip activation without adding duplicate history entries", async () => {
    const router = setup();
    await waitFor(() => expect(main()).toBeTruthy());
    await act(() => router.navigate({ href: "/b" }));
    const anchor = document.querySelector<HTMLAnchorElement>('a[href="#main-content"]')!;
    await act(async () => {
      anchor.click();
    });
    expect(document.activeElement).toBe(main());
    const length = router.history.length;
    document.querySelector<HTMLButtonElement>("#target")!.focus();
    await act(async () => {
      anchor.click();
    });
    expect(document.activeElement).toBe(main());
    expect(router.history.length).toBe(length);
  });
});
