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

import { BACK_ONLINE_MS } from "@/lib/connectivity-notice";

import { newestDataAt, OfflineBanner } from "./offline-banner";

let online = true;
beforeEach(() => {
  online = true;
  vi.spyOn(window.navigator, "onLine", "get").mockImplementation(() => online);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function goOnline() {
  online = true;
  act(() => {
    window.dispatchEvent(new Event("online"));
  });
}

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

  it("is empty online and says how old the shown data is once offline", () => {
    const client = new QueryClient();
    const at = new Date(2026, 10, 25, 12, 1).getTime();
    client.setQueryData(["sandboxes"], [], { updatedAt: at });
    render(
      <QueryClientProvider client={client}>
        <OfflineBanner />
      </QueryClientProvider>,
    );
    // The live region stays mounted, empty, so the change is announced.
    const region = screen.getByRole("status");
    expect(region.textContent).toBe("");
    expect(region.getAttribute("aria-live")).toBe("polite");

    goOffline();
    const time = new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(
      at,
    );
    expect(screen.getByRole("status").textContent).toBe(`offline.showingDataFrom ${time}`);
  });

  it("says Back online on reconnect, then empties", () => {
    vi.useFakeTimers();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <OfflineBanner />
      </QueryClientProvider>,
    );
    goOffline();
    goOnline();
    const region = screen.getByRole("status");
    expect(region.textContent).toBe("offline.backOnline");
    expect(region.dataset.offlineBanner).toBe("back-online");

    act(() => {
      vi.advanceTimersByTime(BACK_ONLINE_MS);
    });
    expect(screen.getByRole("status").textContent).toBe("");
  });

  it("does not say Back online for an online event without an outage", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <OfflineBanner />
      </QueryClientProvider>,
    );
    goOnline();
    expect(screen.getByRole("status").textContent).toBe("");
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
