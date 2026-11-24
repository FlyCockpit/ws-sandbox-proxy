import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import {
  applyModifiers,
  consumeLatches,
  type Latches,
  latchedModifiers,
  type ModifierName,
  NO_LATCHES,
  nextLatch,
  pinchFontSize,
} from "@/lib/terminal-keys";

import { useMobileKeyboard } from "./use-mobile-keyboard";

/**
 * Latched Ctrl/Alt from the on-screen key row. While the row is mounted its
 * filter rewrites what the phone keyboard types (the received characters,
 * not keydown: mobile keyboards often send none), so tap Ctrl then type `c`
 * sends ^C. One-shot latches clear after one key; a double-tap locks.
 */
export function useTerminalLatches({
  setKeyFilter,
  applicationCursorKeys,
}: {
  setKeyFilter: (filter: ((data: string) => string) | null) => void;
  applicationCursorKeys: () => boolean;
}) {
  const [latches, setLatches] = useState<Latches>(NO_LATCHES);
  const latchesRef = useRef<Latches>(NO_LATCHES);
  const tappedAt = useRef<Record<ModifierName, number>>({ ctrl: 0, alt: 0 });
  const cursorRef = useRef(applicationCursorKeys);
  cursorRef.current = applicationCursorKeys;

  const update = useCallback((next: Latches) => {
    latchesRef.current = next;
    setLatches(next);
  }, []);

  useEffect(() => {
    setKeyFilter((data) => {
      const current = latchesRef.current;
      if (current.ctrl === "off" && current.alt === "off") return data;
      const result = applyModifiers(data, latchedModifiers(current), cursorRef.current());
      if (result.used) update(consumeLatches(current));
      return result.data;
    });
    return () => setKeyFilter(null);
  }, [setKeyFilter, update]);

  const tap = useCallback(
    (name: ModifierName) => {
      const now = performance.now();
      const current = latchesRef.current;
      const next = { ...current, [name]: nextLatch(current[name], now, tappedAt.current[name]) };
      tappedAt.current[name] = now;
      update(next);
    },
    [update],
  );

  /**
   * The latched modifiers for one key from the row, consuming one-shot
   * latches at once: a swipe that sends several arrows in one move applies a
   * one-shot Ctrl to the first only.
   */
  const take = useCallback(() => {
    const current = latchesRef.current;
    if (current.ctrl === "off" && current.alt === "off") return {};
    update(consumeLatches(current));
    return latchedModifiers(current);
  }, [update]);

  return { latches, tap, take };
}

/**
 * Two-finger pinch on the terminal changes the text size in whole px. One
 * finger is left to xterm (scroll, tap to focus, selection); only a second
 * finger starts a pinch. The page itself does not zoom there: two-finger
 * moves are cancelled and iOS `gesture*` events too (the container also has
 * `touch-action: pan-x pan-y`). Pinch-zoom elsewhere on the page still works.
 */
export function useTerminalPinch(
  ref: RefObject<HTMLElement | null>,
  {
    enabled,
    currentSize,
    onPreview,
    onCommit,
  }: {
    enabled: boolean;
    currentSize: () => number;
    /** A whole-px size while fingers move (not remembered yet). */
    onPreview: (size: number) => void;
    /** The final size when the pinch ends (remembered). */
    onCommit: (size: number) => void;
  },
) {
  const handlers = useRef({ currentSize, onPreview, onCommit });
  handlers.current = { currentSize, onPreview, onCommit };

  useEffect(() => {
    const element = ref.current;
    if (!element || !enabled) return;
    let pinch: { d0: number; s0: number; last: number } | null = null;
    const distance = (touches: TouchList) => {
      const [a, b] = [touches[0], touches[1]];
      return a && b ? Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY) : 0;
    };
    const finish = () => {
      if (!pinch) return;
      const { last, s0 } = pinch;
      pinch = null;
      // A previewed size is always remembered, however the pinch ends.
      if (last !== s0) handlers.current.onCommit(last);
    };
    const start = (event: TouchEvent) => {
      if (event.touches.length === 2) {
        const size = handlers.current.currentSize();
        pinch = { d0: Math.max(1, distance(event.touches)), s0: size, last: size };
        if (event.cancelable) event.preventDefault();
      } else if (event.touches.length > 2) finish();
    };
    const move = (event: TouchEvent) => {
      if (!pinch || event.touches.length !== 2) return;
      if (event.cancelable) event.preventDefault();
      event.stopPropagation();
      const size = pinchFontSize(pinch.s0, pinch.d0, distance(event.touches));
      if (size !== pinch.last) {
        pinch.last = size;
        handlers.current.onPreview(size);
      }
    };
    const end = (event: TouchEvent) => {
      if (event.touches.length < 2) finish();
    };
    const gesture = (event: Event) => event.preventDefault();
    const capture = { capture: true, passive: false } as const;
    element.addEventListener("touchstart", start, capture);
    element.addEventListener("touchmove", move, capture);
    element.addEventListener("touchend", end, true);
    element.addEventListener("touchcancel", end, true);
    for (const type of ["gesturestart", "gesturechange", "gestureend"])
      element.addEventListener(type, gesture, { passive: false });
    return () => {
      element.removeEventListener("touchstart", start, capture);
      element.removeEventListener("touchmove", move, capture);
      element.removeEventListener("touchend", end, true);
      element.removeEventListener("touchcancel", end, true);
      for (const type of ["gesturestart", "gesturechange", "gestureend"])
        element.removeEventListener(type, gesture);
    };
  }, [ref, enabled]);
}

/** The layout viewport's hidden bands while the keyboard is open (px). */
export type KeyboardInset = {
  /** Covered by the on-screen keyboard at the bottom. */
  bottom: number;
  /** Panned out of view at the top (the visual viewport's `offsetTop`). */
  top: number;
};
const NO_INSET: KeyboardInset = { bottom: 0, top: 0 };

/**
 * How far the on-screen keyboard covers the bottom of the layout viewport,
 * and how far the visible area is panned down from its top (px), while the
 * app's proven mobile-keyboard rule says it is open and the focus is inside
 * `ref` (the terminal). Zero otherwise. A key row pinned with
 * `bottom: <bottom>` then sits right above the keyboard; a fixed panel with
 * `top: <top>; bottom: <bottom>` fills exactly the visible area.
 */
export function useKeyboardInset(
  ref: RefObject<HTMLElement | null>,
  enabled: boolean,
): KeyboardInset {
  const keyboardOpen = useMobileKeyboard();
  const [inset, setInset] = useState<KeyboardInset>(NO_INSET);

  useEffect(() => {
    const element = ref.current;
    const viewport = window.visualViewport;
    if (!enabled || !keyboardOpen || !element || !viewport) {
      setInset(NO_INSET);
      return;
    }
    const measure = () => {
      const focused = element.contains(document.activeElement);
      const top = Math.max(0, Math.round(viewport.offsetTop));
      const bottom = Math.max(
        0,
        Math.round(window.innerHeight - (viewport.offsetTop + viewport.height)),
      );
      setInset((previous) =>
        !focused
          ? NO_INSET
          : previous.top === top && previous.bottom === bottom
            ? previous
            : { top, bottom },
      );
    };
    measure();
    viewport.addEventListener("resize", measure);
    viewport.addEventListener("scroll", measure);
    element.addEventListener("focusin", measure);
    element.addEventListener("focusout", measure);
    return () => {
      viewport.removeEventListener("resize", measure);
      viewport.removeEventListener("scroll", measure);
      element.removeEventListener("focusin", measure);
      element.removeEventListener("focusout", measure);
    };
  }, [ref, enabled, keyboardOpen]);

  return enabled && keyboardOpen ? inset : NO_INSET;
}
