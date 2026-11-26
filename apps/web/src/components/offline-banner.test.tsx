// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { time?: string }) =>
      options?.time ? `${key} ${options.time}` : key,
    i18n: { language: "en-US" },
  }),
}));

import { newestDataAt, OfflineBanner } from "./offline-banner";

let online = true;
beforeEach(() => {
  online = true;
  vi.spyOn(window.navigator, "onLine", "get").mockImplementation(() => online);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function goOffline() {
  online = false;
  act(() => {
    window.dispatchEvent(new Event("offline"));
  });
}

describe("offline banner", () => {
  it("picks the newest cached data, or none", () => {
    expect(newestDataAt([])).toBeNull();
    expect(newestDataAt([0, 0])).toBeNull();
    expect(newestDataAt([5, 20, 10])).toBe(20);
  });

  it("is absent online and says how old the shown data is once offline", () => {
    const client = new QueryClient();
    const at = new Date(2026, 10, 25, 12, 1).getTime();
    client.setQueryData(["sandboxes"], [], { updatedAt: at });
    render(
      <QueryClientProvider client={client}>
        <OfflineBanner />
      </QueryClientProvider>,
    );
    expect(screen.queryByRole("status")).toBeNull();

    goOffline();
    const banner = screen.getByRole("status");
    const time = new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(
      at,
    );
    expect(banner.textContent).toBe(`offline.showingDataFrom ${time}`);

    online = true;
    act(() => {
      window.dispatchEvent(new Event("online"));
    });
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("says plainly that nothing is cached yet", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <OfflineBanner />
      </QueryClientProvider>,
    );
    goOffline();
    expect(screen.getByRole("status").textContent).toBe("offline.noData");
  });
});
