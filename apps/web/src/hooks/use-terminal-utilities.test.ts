// @vitest-environment jsdom

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const keyboard = vi.hoisted(() => ({ open: true }));
vi.mock("./use-mobile-keyboard", () => ({ useMobileKeyboard: () => keyboard.open }));

import { useKeyboardInset } from "./use-terminal-utilities";

/** A visualViewport whose geometry the test moves, firing the real events. */
class FakeViewport extends EventTarget {
  offsetTop = 0;
  height = 800;
  move(offsetTop: number, height: number) {
    this.offsetTop = offsetTop;
    this.height = height;
    this.dispatchEvent(new Event("resize"));
  }
}

let viewport: FakeViewport;
let terminal: HTMLTextAreaElement;
let wrap: HTMLDivElement;

beforeEach(() => {
  keyboard.open = true;
  viewport = new FakeViewport();
  vi.stubGlobal("visualViewport", viewport);
  vi.stubGlobal("innerHeight", 800);
  wrap = document.createElement("div");
  terminal = document.createElement("textarea");
  wrap.append(terminal);
  document.body.append(wrap);
});

afterEach(() => {
  wrap.remove();
  vi.unstubAllGlobals();
});

describe("useKeyboardInset", () => {
  it("measures the keyboard at the bottom and the pan at the top from visualViewport events", () => {
    terminal.focus();
    const { result } = renderHook(() => useKeyboardInset({ current: wrap }, true));
    expect(result.current).toEqual({ top: 0, bottom: 0 });
    // The keyboard opens: 400 px visible, panned 100 px down (layout 800).
    act(() => viewport.move(100, 400));
    expect(result.current).toEqual({ top: 100, bottom: 300 });
    act(() => viewport.move(0, 450));
    expect(result.current).toEqual({ top: 0, bottom: 350 });
    act(() => {
      viewport.offsetTop = 40;
      viewport.dispatchEvent(new Event("scroll"));
    });
    expect(result.current).toEqual({ top: 40, bottom: 310 });
  });

  it("is zero while the focus is outside the terminal, while disabled, and while the keyboard is closed", () => {
    const outside = document.createElement("input");
    document.body.append(outside);
    outside.focus();
    viewport.move(100, 400);
    const { result, rerender } = renderHook(
      ({ enabled }) => useKeyboardInset({ current: wrap }, enabled),
      { initialProps: { enabled: true } },
    );
    expect(result.current).toEqual({ top: 0, bottom: 0 });
    act(() => terminal.focus());
    expect(result.current).toEqual({ top: 100, bottom: 300 });
    rerender({ enabled: false });
    expect(result.current).toEqual({ top: 0, bottom: 0 });
    keyboard.open = false;
    rerender({ enabled: true });
    expect(result.current).toEqual({ top: 0, bottom: 0 });
    outside.remove();
  });
});
