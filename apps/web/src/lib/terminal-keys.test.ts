import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyModifiers,
  bracketedPaste,
  clampFontSize,
  consumeLatches,
  ctrlChar,
  dataToKey,
  encodeKey,
  FONT_SIZE_MAX,
  FONT_SIZE_MIN,
  gridLayout,
  HOLD_GRID_MS,
  HoldGesture,
  LATCH_DOUBLE_TAP_MS,
  latchedModifiers,
  nextLatch,
  photoGuestPath,
  pinchFontSize,
  SwipeTracker,
  shellQuote,
} from "./terminal-keys";

const ESC = "\x1b";

describe("encodeKey", () => {
  it("sends arrows as CSI in normal cursor mode and SS3 in application cursor mode", () => {
    expect(encodeKey("Up")).toBe(`${ESC}[A`);
    expect(encodeKey("Down")).toBe(`${ESC}[B`);
    expect(encodeKey("Right")).toBe(`${ESC}[C`);
    expect(encodeKey("Left")).toBe(`${ESC}[D`);
    expect(encodeKey("Up", {}, true)).toBe(`${ESC}OA`);
    expect(encodeKey("Left", {}, true)).toBe(`${ESC}OD`);
    expect(encodeKey("Home", {}, true)).toBe(`${ESC}OH`);
  });

  it("encodes modified arrows with the xterm modifier parameter, whatever the cursor mode", () => {
    expect(encodeKey("Up", { ctrl: true })).toBe(`${ESC}[1;5A`);
    expect(encodeKey("Left", { alt: true }, true)).toBe(`${ESC}[1;3D`);
    expect(encodeKey("Right", { ctrl: true, alt: true })).toBe(`${ESC}[1;7C`);
    expect(encodeKey("Down", { shift: true })).toBe(`${ESC}[1;2B`);
  });

  it("encodes tilde keys with and without modifiers", () => {
    expect(encodeKey("Delete")).toBe(`${ESC}[3~`);
    expect(encodeKey("PgUp", { ctrl: true })).toBe(`${ESC}[5;5~`);
  });

  it("maps Ctrl+letter and Ctrl+punctuation to C0 controls", () => {
    expect(encodeKey("c", { ctrl: true })).toBe("\x03");
    expect(encodeKey("C", { ctrl: true })).toBe("\x03");
    expect(encodeKey("a", { ctrl: true })).toBe("\x01");
    expect(encodeKey("z", { ctrl: true })).toBe("\x1a");
    expect(encodeKey("[", { ctrl: true })).toBe(ESC);
    expect(encodeKey("\\", { ctrl: true })).toBe("\x1c");
    expect(encodeKey("_", { ctrl: true })).toBe("\x1f");
    expect(encodeKey("@", { ctrl: true })).toBe("\x00");
    // No Ctrl form: the character is sent as is.
    expect(encodeKey(".", { ctrl: true })).toBe(".");
    expect(ctrlChar("é")).toBeNull();
  });

  it("sends Alt as an ESC prefix", () => {
    expect(encodeKey("x", { alt: true })).toBe(`${ESC}x`);
    expect(encodeKey(".", { alt: true })).toBe(`${ESC}.`);
    expect(encodeKey("b", { alt: true })).toBe(`${ESC}b`);
    expect(encodeKey("c", { ctrl: true, alt: true })).toBe(`${ESC}\x03`);
    expect(encodeKey("Esc", { alt: true })).toBe(`${ESC}${ESC}`);
  });

  it("encodes Esc, Tab, Shift+Tab, Enter, Backspace and Space", () => {
    expect(encodeKey("Esc")).toBe(ESC);
    expect(encodeKey("Tab")).toBe("\t");
    expect(encodeKey("Tab", { shift: true })).toBe(`${ESC}[Z`);
    expect(encodeKey("Enter")).toBe("\r");
    expect(encodeKey("Enter", { ctrl: true })).toBe("\n");
    expect(encodeKey("Enter", { shift: true })).toBe("\n");
    expect(encodeKey("Enter", { alt: true })).toBe("\x1b\r");
    expect(encodeKey("Backspace")).toBe("\x7f");
    expect(encodeKey("Backspace", { ctrl: true })).toBe("\x08");
    expect(encodeKey("Space", { ctrl: true })).toBe("\x00");
    expect(encodeKey("Space")).toBe(" ");
  });
});

describe("applyModifiers (latched keys on phone-keyboard data)", () => {
  it("passes data through when nothing is latched", () => {
    expect(applyModifiers("c", {})).toEqual({ data: "c", used: false });
  });

  it("applies Ctrl and Alt to a received character", () => {
    expect(applyModifiers("c", { ctrl: true })).toEqual({ data: "\x03", used: true });
    expect(applyModifiers("x", { alt: true })).toEqual({ data: `${ESC}x`, used: true });
  });

  it("re-encodes received special keys", () => {
    expect(dataToKey("\r")).toBe("Enter");
    expect(dataToKey(`${ESC}OA`)).toBe("Up");
    expect(dataToKey(`${ESC}[3~`)).toBe("Delete");
    expect(dataToKey(`${ESC}[99~`)).toBeNull();
    expect(applyModifiers(`${ESC}[A`, { ctrl: true })).toEqual({
      data: `${ESC}[1;5A`,
      used: true,
    });
    expect(applyModifiers("\x7f", { alt: true })).toEqual({ data: `${ESC}\x7f`, used: true });
  });

  it("applies the modifier to the first character of an autocompleted word only", () => {
    expect(applyModifiers("cat", { ctrl: true })).toEqual({ data: "\x03at", used: true });
  });

  it("a latched Ctrl turns the phone keyboard's Return into LF", () => {
    expect(applyModifiers("\r", { ctrl: true })).toEqual({ data: "\n", used: true });
  });

  it("leaves unknown escape sequences alone", () => {
    expect(applyModifiers(`${ESC}[200~`, { ctrl: true })).toEqual({
      data: `${ESC}[200~`,
      used: false,
    });
  });
});

describe("bracketedPaste", () => {
  it("wraps in ESC[200~ … ESC[201~ only when the program enabled it, with CR line breaks", () => {
    expect(bracketedPaste("a\nb", true)).toBe(`${ESC}[200~a\rb${ESC}[201~`);
    expect(bracketedPaste("a\r\nb", false)).toBe("a\rb");
  });
});

describe("modifier latches", () => {
  it("tap latches once, a quick second tap locks, a slow one turns it off", () => {
    expect(nextLatch("off", 1000, 0)).toBe("once");
    expect(nextLatch("once", 1000 + LATCH_DOUBLE_TAP_MS - 1, 1000)).toBe("lock");
    expect(nextLatch("once", 1000 + LATCH_DOUBLE_TAP_MS, 1000)).toBe("off");
    expect(nextLatch("lock", 5000, 1000)).toBe("off");
  });

  it("one-shot latches clear after a key, locked ones stay", () => {
    expect(consumeLatches({ ctrl: "once", alt: "lock" })).toEqual({ ctrl: "off", alt: "lock" });
    expect(latchedModifiers({ ctrl: "off", alt: "lock" })).toEqual({ ctrl: false, alt: true });
  });
});

describe("HoldGesture", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const make = () => {
    const calls: string[] = [];
    const gesture = new HoldGesture({
      onOpen: () => calls.push("open"),
      onClose: () => calls.push("close"),
      onTap: () => calls.push("tap"),
      onSend: (key) => calls.push(`send:${key}`),
    });
    return { gesture, calls };
  };

  it("a short press is a tap (latch), no grid", () => {
    const { gesture, calls } = make();
    gesture.down();
    vi.advanceTimersByTime(HOLD_GRID_MS - 1);
    gesture.up();
    vi.advanceTimersByTime(1000);
    expect(calls).toEqual(["tap"]);
  });

  it("a hold opens the grid, sliding to a key and lifting sends it", () => {
    const { gesture, calls } = make();
    gesture.down();
    vi.advanceTimersByTime(HOLD_GRID_MS);
    expect(gesture.open).toBe(true);
    gesture.over("r");
    gesture.over("c");
    expect(gesture.highlighted).toBe("c");
    gesture.up();
    expect(calls).toEqual(["open", "close", "send:c"]);
    expect(gesture.open).toBe(false);
  });

  it("lifting off the grid, or a cancel, sends nothing", () => {
    const { gesture, calls } = make();
    gesture.down();
    vi.advanceTimersByTime(HOLD_GRID_MS);
    gesture.over("c");
    gesture.over(null);
    gesture.up();
    gesture.down();
    vi.advanceTimersByTime(HOLD_GRID_MS);
    gesture.over("d");
    gesture.cancel();
    expect(calls).toEqual(["open", "close", "open", "close"]);
  });

  it("a cancel before the hold neither taps nor opens", () => {
    const { gesture, calls } = make();
    gesture.down();
    gesture.cancel();
    vi.advanceTimersByTime(HOLD_GRID_MS * 2);
    gesture.up();
    expect(calls).toEqual([]);
  });
});

describe("SwipeTracker", () => {
  it("sends one arrow per 20 px along the axis chosen first", () => {
    const swipe = new SwipeTracker();
    swipe.start(100, 100);
    expect(swipe.move(105, 101)).toEqual([]);
    expect(swipe.move(121, 104)).toEqual(["Right"]);
    expect(swipe.move(161, 130)).toEqual(["Right", "Right"]);
    expect(swipe.move(141, 90)).toEqual([]);
    expect(swipe.move(139, 90)).toEqual(["Left"]);
    swipe.end();
    expect(swipe.move(300, 300)).toEqual([]);
  });

  it("vertical swipes send Up and Down", () => {
    const swipe = new SwipeTracker();
    swipe.start(0, 0);
    expect(swipe.move(2, -45)).toEqual(["Up", "Up"]);
    expect(swipe.move(2, 0)).toEqual(["Down", "Down"]);
  });
});

describe("text size", () => {
  it("clamps to 1–20 px in whole px (minimum 1 px)", () => {
    expect(FONT_SIZE_MIN).toBe(1);
    expect(clampFontSize(0)).toBe(1);
    expect(clampFontSize(-4)).toBe(1);
    expect(clampFontSize(1)).toBe(1);
    expect(clampFontSize(1.4)).toBe(1);
    expect(clampFontSize(8)).toBe(8);
    expect(clampFontSize(25)).toBe(FONT_SIZE_MAX);
    expect(clampFontSize(14.6)).toBe(15);
  });

  it("damps a pinch with a square root, additively", () => {
    expect(pinchFontSize(14, 100, 100)).toBe(14);
    // Twice the spread adds 5 px; closing the fingers takes at most 5 px off.
    expect(pinchFontSize(14, 100, 200)).toBe(19);
    expect(pinchFontSize(14, 100, 150)).toBe(18);
    expect(pinchFontSize(14, 200, 100)).toBe(10);
    expect(pinchFontSize(14, 100, 0)).toBe(9);
    expect(pinchFontSize(20, 100, 400)).toBe(FONT_SIZE_MAX);
  });

  it("pinches at 1 px: never below it, and spreading grows it again", () => {
    expect(pinchFontSize(1, 100, 0)).toBe(1);
    expect(pinchFontSize(3, 100, 0)).toBe(1);
    expect(pinchFontSize(1, 100, 200)).toBe(6);
    expect(pinchFontSize(1, 100, 125)).toBe(4);
  });
});

describe("photo paths", () => {
  it("puts the photo under ~/.uploads with a time stamp and the type's extension", () => {
    const at = new Date(2026, 10, 23, 9, 5, 7);
    expect(photoGuestPath("/home/user/", "image/jpeg", at, "ab12cd34")).toBe(
      "/home/user/.uploads/paste-20261123-090507-ab12cd34.jpg",
    );
    expect(photoGuestPath("/root", "image/png", at, "x")).toBe(
      "/root/.uploads/paste-20261123-090507-x.png",
    );
  });

  it("quotes a path only when the shell needs it", () => {
    expect(shellQuote("/home/user/.uploads/a.png")).toBe("/home/user/.uploads/a.png");
    expect(shellQuote("/home/my user/a.png")).toBe("'/home/my user/a.png'");
    expect(shellQuote("/home/o'neil/a.png")).toBe(`'/home/o'\\''neil/a.png'`);
  });
});

describe("gridLayout", () => {
  it("keeps 44 px cells when the grid fits above the row", () => {
    // 390 px row: 372 px inside → 7 columns, 5 rows.
    expect(gridLayout(400, 390)).toEqual({ columns: 7, cell: 44 });
  });

  it("derives columns from the grid's inner width and fits the rows in the visible space", () => {
    // 252 px row: 234 px inside → 4 columns (not 5), 9 rows.
    expect(gridLayout(500, 252)).toEqual({ columns: 4, cell: 44 });
    expect(gridLayout(400, 252)).toEqual({ columns: 4, cell: 36 });
    // 320 px row: 6 columns, 6 rows; 300 px above → 39 px cells, never below 32.
    expect(gridLayout(300, 320)).toEqual({ columns: 6, cell: 39 });
    expect(gridLayout(120, 320)).toEqual({ columns: 6, cell: 32 });
  });
});
