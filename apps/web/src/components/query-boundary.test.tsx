import enCommon from "@wssp/locales/src/en-US/common.json";
import enErrors from "@wssp/locales/src/en-US/errors.json";
import { createInstance } from "i18next";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const network = vi.hoisted(() => ({ online: true }));
vi.mock("@/hooks/use-network-status", () => ({ useNetworkStatus: () => network.online }));

import { QueryBoundary } from "@/components/query-boundary";

/**
 * The regression this file guards: TanStack Query keeps the last successful
 * `data` when a background refetch (or `fetchNextPage`) fails, and sets
 * `status: "error"` at the same time. An `if (isError)` branch that runs before
 * the data check throws the already-rendered list away.
 */
describe("QueryBoundary", () => {
  const i18n = createInstance();

  beforeAll(async () => {
    await i18n.init({
      lng: "en-US",
      fallbackLng: "en-US",
      ns: ["common", "errors"],
      defaultNS: "common",
      resources: { "en-US": { common: enCommon, errors: enErrors } },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
    });
  });

  afterEach(() => {
    network.online = true;
  });

  function render(query: {
    data: string[] | undefined;
    isPending: boolean;
    isError: boolean;
    error?: unknown;
    fetchStatus?: "fetching" | "paused" | "idle";
  }): string {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryBoundary
          query={{ error: null, fetchStatus: "idle", ...query, refetch: () => undefined }}
          skeleton={<div>SKELETON</div>}
          errorMessage="Failed to load posts."
          isEmpty={(data) => data.length === 0}
          empty={<div>EMPTY</div>}
        >
          {(data) => (
            <ul>
              {data.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          )}
        </QueryBoundary>
      </I18nextProvider>,
    );
  }

  it("renders the skeleton while pending", () => {
    const html = render({ data: undefined, isPending: true, isError: false });
    expect(html).toContain("SKELETON");
    expect(html).not.toContain("Failed to load posts.");
  });

  it("renders the retry card when the first load fails", () => {
    const html = render({ data: undefined, isPending: false, isError: true });
    expect(html).toContain("Failed to load posts.");
    expect(html).toContain("Try again");
    expect(html).not.toContain("EMPTY");
  });

  it("keeps rendered data when a refetch fails, and shows retry above it", () => {
    const html = render({ data: ["alpha", "beta"], isPending: false, isError: true });
    expect(html).toContain("alpha");
    expect(html).toContain("beta");
    expect(html).toContain("Failed to load posts.");
    // The retry banner precedes the content it belongs to.
    expect(html.indexOf("Failed to load posts.")).toBeLessThan(html.indexOf("alpha"));
  });

  it("renders the empty state when a refetch fails over an empty result", () => {
    const html = render({ data: [], isPending: false, isError: true });
    expect(html).toContain("EMPTY");
    expect(html).toContain("Failed to load posts.");
  });

  it.each([
    { status: 401 },
    { status: 403 },
    { status: 404 },
    { code: "UNAUTHORIZED" },
    { code: "FORBIDDEN" },
    { code: "NOT_FOUND" },
    { data: { code: "NOT_FOUND" } },
    { data: { code: "sandbox.not_found" } },
  ])("hides retained private data on denial: %j", (error) => {
    const html = render({ data: ["private-name"], isPending: false, isError: true, error });
    expect(html).not.toContain("private-name");
    expect(html).toContain("Try again");
  });

  it("renders children on success", () => {
    const html = render({ data: ["alpha"], isPending: false, isError: false });
    expect(html).toContain("alpha");
    expect(html).not.toContain("Failed to load posts.");
  });

  it("renders the empty state on an empty success", () => {
    const html = render({ data: [], isPending: false, isError: false });
    expect(html).toContain("EMPTY");
  });

  describe("offline", () => {
    // As rendered markup: the apostrophe is escaped.
    const offlineCopy = enErrors.offlineContent.replace("'", "&#x27;");

    it("says a first load paused for the network will load on reconnect, not a skeleton forever", () => {
      network.online = false;
      const html = render({
        data: undefined,
        isPending: true,
        isError: false,
        fetchStatus: "paused",
      });
      expect(html).toContain(offlineCopy);
      expect(html).not.toContain("SKELETON");
    });

    it("keeps the skeleton while a first load is actually fetching", () => {
      const html = render({
        data: undefined,
        isPending: true,
        isError: false,
        fetchStatus: "fetching",
      });
      expect(html).toContain("SKELETON");
    });

    it("uses the offline copy for a first load that failed offline", () => {
      network.online = false;
      const html = render({ data: undefined, isPending: false, isError: true });
      expect(html).toContain(offlineCopy);
      expect(html).not.toContain("Failed to load posts.");
    });

    it("keeps retained content when a refetch fails offline, with the offline copy above it", () => {
      network.online = false;
      const html = render({
        data: ["alpha"],
        isPending: false,
        isError: true,
        error: new TypeError("Failed to fetch"),
      });
      expect(html).toContain("alpha");
      expect(html.indexOf(offlineCopy)).toBeLessThan(html.indexOf("alpha"));
    });
  });
});
