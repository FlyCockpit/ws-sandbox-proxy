// @vitest-environment jsdom

import { invokeToastAction, Toaster, toast } from "@wssp/ui/components/sileo";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("sileo/styles.css", () => ({}));

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: () => ({
      matches: false,
      addEventListener() {},
      removeEventListener() {},
    }),
  });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    toast.clear();
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
});

async function mountToaster(
  titles?: Record<"message" | "success" | "error" | "info" | "warning", string>,
) {
  await act(async () => {
    root.render(<Toaster position="bottom-center" titles={titles} />);
  });
}

describe("Toaster action nesting", () => {
  it("renders action toasts as a single button control with no nested interactive descendants", async () => {
    await mountToaster();
    const onUndo = vi.fn();

    let toastId = "";
    act(() => {
      toastId = toast.success("User archived", {
        duration: 8000,
        action: { label: "Undo", onClick: onUndo },
      });
    });

    const toastEl = container.querySelector<HTMLButtonElement>("[data-sileo-toast]");
    expect(toastEl).not.toBeNull();
    expect(toastEl?.tagName).toBe("BUTTON");
    expect(toastEl?.getAttribute("aria-label")).toBe("User archived — Undo");
    expect(toastEl?.querySelectorAll("a, button, [role='button'], [tabindex]")).toHaveLength(0);

    const actionPill = toastEl?.querySelector<HTMLElement>("[data-sileo-button]");
    expect(actionPill?.tagName).toBe("SPAN");
    expect(actionPill?.getAttribute("data-state")).toBe("success");
    expect(actionPill?.getAttribute("data-toast-action-id")).toBe(toastId);
    expect(actionPill?.textContent).toBe("Undo");

    act(() => {
      actionPill?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(onUndo).toHaveBeenCalledTimes(1);

    act(() => {
      toastEl?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(onUndo).toHaveBeenCalledTimes(2);

    // Exiting (dismissed) toasts ignore late clicks.
    toastEl?.setAttribute("data-exiting", "true");
    act(() => {
      toastEl?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(onUndo).toHaveBeenCalledTimes(2);

    // Clearing removes registered action handlers.
    act(() => {
      toast.clear();
    });
    invokeToastAction(toastId);
    expect(onUndo).toHaveBeenCalledTimes(2);
  });

  it("keeps overflowing message text alongside the action pill and preserves kindTitles", async () => {
    await mountToaster({
      message: "Notice",
      success: "Done",
      error: "Something went wrong",
      info: "Info",
      warning: "Warning",
    });
    const onRetry = vi.fn();
    const long = "We couldn't reach the server while saving your changes. Try again.";

    act(() => {
      toast.error(long, { action: { label: "Try again", onClick: onRetry } });
    });

    const toastEl = container.querySelector<HTMLButtonElement>("[data-sileo-toast]");
    expect(toastEl?.getAttribute("aria-label")).toBe(`${long} — Try again`);
    expect(toastEl?.querySelector("[data-sileo-title]")?.textContent).toBe("Something went wrong");
    const desc = toastEl?.querySelector("[data-sileo-description]");
    expect(desc?.textContent).toContain(long);
    const actionPill = desc?.querySelector("[data-sileo-button]");
    expect(actionPill?.textContent).toBe("Try again");
    expect(toastEl?.querySelectorAll("a, button, [role='button'], [tabindex]")).toHaveLength(0);

    act(() => {
      actionPill?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
