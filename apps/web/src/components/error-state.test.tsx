// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const router = vi.hoisted(() => ({ invalidate: vi.fn() }));
vi.mock("@tanstack/react-router", () => ({ useRouter: () => router }));
vi.mock("@/hooks/use-route-import-failure", () => ({ useRouteImportFailure: () => undefined }));
vi.mock("@/utils/friendly-error", () => ({ friendly: () => "Couldn't reach the server." }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

import ErrorState from "./error-state";

afterEach(() => {
  cleanup();
  router.invalidate.mockReset();
});

it("Try again re-runs the route (re-importing a failed chunk) before resetting the boundary", async () => {
  let finish: (() => void) | undefined;
  router.invalidate.mockReturnValue(
    new Promise<void>((resolve) => {
      finish = resolve;
    }),
  );
  const reset = vi.fn();
  render(<ErrorState error={new Error("Failed to fetch")} reset={reset} />);
  expect(screen.getByRole("alert").textContent).toContain("Couldn't reach the server.");

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
