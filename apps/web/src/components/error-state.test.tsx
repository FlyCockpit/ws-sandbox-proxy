// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  router: { invalidate: vi.fn() },
  online: true,
  reconnect: { retry: undefined as (() => void) | undefined, offline: false },
}));
vi.mock("@tanstack/react-router", () => ({ useRouter: () => fixture.router }));
vi.mock("@/hooks/use-route-import-failure", () => ({ useRouteImportFailure: () => undefined }));
vi.mock("@/hooks/use-network-status", () => ({ useNetworkStatus: () => fixture.online }));
vi.mock("@/hooks/use-retry-on-reconnect", () => ({
  useRetryOnReconnect: (retry: () => void, offline: boolean) => {
    fixture.reconnect = { retry, offline };
  },
}));
vi.mock("@/utils/friendly-error", () => ({ friendly: () => "friendly copy" }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

import ErrorState from "./error-state";

const router = fixture.router;

afterEach(() => {
  cleanup();
  router.invalidate.mockReset();
  fixture.online = true;
});

it("Try again re-runs the route (re-importing a failed chunk) before resetting the boundary", async () => {
  let finish: (() => void) | undefined;
  router.invalidate.mockReturnValue(
    new Promise<void>((resolve) => {
      finish = resolve;
    }),
  );
  const reset = vi.fn();
  render(<ErrorState error={new Error("boom")} reset={reset} />);
  expect(screen.getByRole("alert").textContent).toContain("friendly copy");

  const tryAgain = screen.getByRole("button", { name: "common:actions.tryAgain" });
  fireEvent.click(tryAgain);
  expect(router.invalidate).toHaveBeenCalledOnce();
  expect(reset).not.toHaveBeenCalled();
  expect((tryAgain as HTMLButtonElement).disabled).toBe(true);

  finish?.();
  await waitFor(() => expect(reset).toHaveBeenCalledOnce());
});

it("still resets when the retry fails, so the error screen shows the new error", async () => {
  router.invalidate.mockRejectedValue(new Error("offline"));
  const reset = vi.fn();
  render(<ErrorState error={new Error("x")} reset={reset} />);
  fireEvent.click(screen.getByRole("button", { name: "common:actions.tryAgain" }));
  await waitFor(() => expect(reset).toHaveBeenCalledOnce());
});

describe("network failures", () => {
  it("offline: says the page loads on reconnect, offers no Reload, and retries on reconnect", async () => {
    fixture.online = false;
    router.invalidate.mockResolvedValue(undefined);
    const reset = vi.fn();
    render(
      <ErrorState
        error={new TypeError("Failed to fetch dynamically imported module: /a.js")}
        reset={reset}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.dataset.networkFailure).toBe("offline");
    expect(alert.textContent).toContain("errors:offlinePage.title");
    expect(alert.textContent).toContain("errors:offlinePage.description");
    expect(alert.textContent).not.toContain("common:somethingWentWrong");
    expect(screen.queryByRole("button", { name: "common:actions.reload" })).toBeNull();
    expect(fixture.reconnect.offline).toBe(true);

    fixture.reconnect.retry?.();
    expect(router.invalidate).toHaveBeenCalledOnce();
    await waitFor(() => expect(reset).toHaveBeenCalledOnce());
  });

  it("online fetch failure: says the server could not be reached", () => {
    render(<ErrorState error={new TypeError("Failed to fetch")} reset={vi.fn()} />);
    const alert = screen.getByRole("alert");
    expect(alert.dataset.networkFailure).toBe("unreachable");
    expect(alert.textContent).toContain("errors:unreachablePage.title");
    expect(fixture.reconnect.offline).toBe(false);
  });

  it("anything else online: the generic error with Try again and Reload", () => {
    render(<ErrorState error={new Error("boom")} reset={vi.fn()} />);
    expect(screen.getByRole("alert").textContent).toContain("common:somethingWentWrong");
    expect(screen.getByRole("button", { name: "common:actions.reload" })).toBeTruthy();
  });
});
