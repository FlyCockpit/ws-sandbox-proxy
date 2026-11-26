/**
 * Terminal utilities (on-screen keys, modifiers, text size): the byte
 * encoding and the gesture state machines, framework-free and free of xterm
 * so they stay out of the lazy xterm chunk and are unit-tested directly.
 *
 * The encoding follows what xterm.js itself sends for a physical keyboard:
 * arrows honour application cursor mode (`ESC O A` instead of `ESC [ A`), a
 * modified arrow is `ESC [ 1 ; <mod> A`, Alt is an ESC prefix, and Ctrl maps
 * letters and the usual punctuation to C0 controls.
 */

export type Modifiers = { ctrl?: boolean; alt?: boolean; shift?: boolean };
export type ModifierName = "ctrl" | "alt";
export type ArrowKey = "Up" | "Down" | "Left" | "Right";
type NamedKey =
  | ArrowKey
  | "Esc"
  | "Tab"
  | "Enter"
  | "Space"
  | "Backspace"
  | "Home"
  | "End"
  | "Insert"
  | "Delete"
  | "PgUp"
  | "PgDn";

const LETTER_KEYS: Partial<Record<NamedKey, string>> = {
  Up: "A",
  Down: "B",
  Right: "C",
  Left: "D",
  Home: "H",
  End: "F",
};
const TILDE_KEYS: Partial<Record<NamedKey, number>> = {
  Insert: 2,
  Delete: 3,
  PgUp: 5,
  PgDn: 6,
};
const NAMED = new Set<string>([
  "Up",
  "Down",
  "Left",
  "Right",
  "Esc",
  "Tab",
  "Enter",
  "Space",
  "Backspace",
  "Home",
  "End",
  "Insert",
  "Delete",
  "PgUp",
  "PgDn",
]);

/** Control bytes for punctuation with Ctrl (xterm's table). */
const CTRL_PUNCT: Record<string, number> = {
  "@": 0,
  " ": 0,
  "2": 0,
  "[": 27,
  "3": 27,
  "\\": 28,
  "4": 28,
  "]": 29,
  "5": 29,
  "^": 30,
  "6": 30,
  _: 31,
  "-": 31,
  "7": 31,
  "/": 31,
  "?": 127,
  "8": 127,
};

/** The C0 control for Ctrl+`char`, or null when the character has none. */
export function ctrlChar(char: string): string | null {
  const lower = char.toLowerCase();
  if (lower.length === 1 && lower >= "a" && lower <= "z")
    return String.fromCharCode(lower.charCodeAt(0) - 96);
  const code = CTRL_PUNCT[char];
  return code === undefined ? null : String.fromCharCode(code);
}

const modParam = (m: Modifiers) => 1 + (m.shift ? 1 : 0) + (m.alt ? 2 : 0) + (m.ctrl ? 4 : 0);

/**
 * The bytes for a named key or a single character with modifiers.
 * `applicationCursor` is the program's DECCKM state (xterm's
 * `modes.applicationCursorKeysMode`).
 */
export function encodeKey(key: string, m: Modifiers = {}, applicationCursor = false): string {
  const param = modParam(m);
  if (NAMED.has(key)) {
    const named = key as NamedKey;
    const letter = LETTER_KEYS[named];
    if (letter) {
      if (param === 1) return (applicationCursor ? "\x1bO" : "\x1b[") + letter;
      return `\x1b[1;${param}${letter}`;
    }
    const tilde = TILDE_KEYS[named];
    if (tilde !== undefined) return `\x1b[${tilde}${param === 1 ? "" : `;${param}`}~`;
  }
  const esc = m.alt ? "\x1b" : "";
  switch (key) {
    case "Esc":
      return `${esc}\x1b`;
    case "Tab":
      return m.shift ? `${esc}\x1b[Z` : `${esc}\t`;
    case "Enter":
      // Shift/Ctrl+Enter: LF, a new line in Claude Code / Codex (the demo's encoding).
      return esc + (m.shift || m.ctrl ? "\n" : "\r");
    case "Backspace":
      return esc + (m.ctrl ? "\x08" : "\x7f");
    case "Space":
      return esc + (m.ctrl ? "\x00" : " ");
  }
  let char = key;
  if (m.shift && [...char].length === 1) char = char.toUpperCase();
  if (m.ctrl) char = ctrlChar(char) ?? char;
  return esc + char;
}

/** The key a chunk of keyboard data stands for, so latched modifiers can apply to it. */
export function dataToKey(data: string): string | null {
  if (data === "\r") return "Enter";
  if (data === "\x7f" || data === "\b") return "Backspace";
  if (data === "\t") return "Tab";
  if (data === "\x1b") return "Esc";
  if (data === " ") return "Space";
  const FINALS: Record<string, string> = {
    A: "Up",
    B: "Down",
    C: "Right",
    D: "Left",
    H: "Home",
    F: "End",
  };
  if (data.length === 3 && data[0] === "\x1b" && (data[1] === "[" || data[1] === "O")) {
    const named = FINALS[data[2] ?? ""];
    if (named) return named;
  }
  if (data.startsWith("\x1b[") && data.endsWith("~") && /^\d+$/.test(data.slice(2, -1))) {
    const number = Number(data.slice(2, -1));
    return (
      (Object.keys(TILDE_KEYS) as NamedKey[]).find((key) => TILDE_KEYS[key] === number) ?? null
    );
  }
  return [...data].length === 1 ? data : null;
}

/**
 * Apply latched modifiers to data typed on the phone keyboard. Mobile
 * keyboards often send no usable keydown, so this works on what xterm
 * received (`onData`), not on key events. A keyboard that inserts a whole
 * word at once (autocomplete) has the modifier applied to its first
 * character only. Unknown escape sequences pass through unchanged.
 * Returns whether the modifiers were used (so one-shot latches clear).
 */
export function applyModifiers(
  data: string,
  m: Modifiers,
  applicationCursor = false,
): { data: string; used: boolean } {
  if (!m.ctrl && !m.alt && !m.shift) return { data, used: false };
  const key = dataToKey(data);
  if (key !== null) return { data: encodeKey(key, m, applicationCursor), used: true };
  if (!data.startsWith("\x1b") && data.length > 1) {
    const [first = "", ...rest] = [...data];
    return { data: encodeKey(first, m, applicationCursor) + rest.join(""), used: true };
  }
  return { data, used: false };
}

/**
 * Text for a bracketed paste: what xterm's `paste()` sends when the program
 * enabled bracketed paste (DECSET 2004), line breaks normalised to CR.
 * The app never builds this itself (xterm does); it documents and tests the
 * bytes the shell receives.
 */
export function bracketedPaste(text: string, bracketed: boolean): string {
  const normalized = text.replace(/\r?\n/g, "\r");
  return bracketed ? `\x1b[200~${normalized}\x1b[201~` : normalized;
}

// -- modifier latches -------------------------------------------------------

export type LatchState = "off" | "once" | "lock";
/** A second tap within this window locks the modifier (the demo's double-tap). */
export const LATCH_DOUBLE_TAP_MS = 400;

/** Tap on Ctrl/Alt: off → once (next key) → lock on a quick second tap, else off. */
export function nextLatch(state: LatchState, now: number, lastTapAt: number): LatchState {
  if (state === "off") return "once";
  if (state === "once") return now - lastTapAt < LATCH_DOUBLE_TAP_MS ? "lock" : "off";
  return "off";
}

export type Latches = Record<ModifierName, LatchState>;
export const NO_LATCHES: Latches = { ctrl: "off", alt: "off" };

export function latchedModifiers(latches: Latches): Modifiers {
  return { ctrl: latches.ctrl !== "off", alt: latches.alt !== "off" };
}

/** After a key used the latches: one-shot ones clear, locked ones stay. */
export function consumeLatches(latches: Latches): Latches {
  return {
    ctrl: latches.ctrl === "once" ? "off" : latches.ctrl,
    alt: latches.alt === "once" ? "off" : latches.alt,
  };
}

// -- hold-for-grid ----------------------------------------------------------

/** Hold Ctrl/Alt this long to open the letter grid. */
export const HOLD_GRID_MS = 400;
/** Keys in the hold grid, in display order. */
export const GRID_KEYS = [..."abcdefghijklmnopqrstuvwxyz", "[", "\\", "]", "_", "@", ".", "/"];

/**
 * Press state of a hold-able modifier key, driven by pointer events and one
 * timer. `tap` latches the modifier; `send` is a grid key chosen by sliding
 * onto it and lifting; a release off the grid (or a cancel) sends nothing.
 */
export class HoldGesture {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private held = false;
  private hot: string | null = null;

  constructor(
    private readonly handlers: {
      onOpen: () => void;
      onClose: () => void;
      onTap: () => void;
      onSend: (key: string) => void;
    },
    private readonly holdMs = HOLD_GRID_MS,
  ) {}

  get open(): boolean {
    return this.held;
  }

  down(): void {
    this.cancelTimer();
    this.held = false;
    this.hot = null;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.held = true;
      this.handlers.onOpen();
    }, this.holdMs);
  }

  /** The grid key under the pointer (null when off the grid). */
  over(key: string | null): void {
    if (this.held) this.hot = key;
  }

  get highlighted(): string | null {
    return this.hot;
  }

  up(): void {
    const wasHeld = this.held;
    const pending = this.timer !== undefined;
    this.cancelTimer();
    if (wasHeld) {
      const key = this.hot;
      this.reset();
      this.handlers.onClose();
      if (key !== null) this.handlers.onSend(key);
    } else if (pending) this.handlers.onTap();
  }

  cancel(): void {
    const wasHeld = this.held;
    this.cancelTimer();
    this.reset();
    if (wasHeld) this.handlers.onClose();
  }

  private reset() {
    this.held = false;
    this.hot = null;
  }

  private cancelTimer() {
    clearTimeout(this.timer);
    this.timer = undefined;
  }
}

/** Grid layout: 44 px cells, 4 px gaps, 8 px padding, 1 px border, one 20 px title line. */
const GRID_CELL_PX = 44;
const GRID_CELL_MIN_PX = 32;
const GRID_GAP_PX = 4;
const GRID_INSET_PX = 8 + 1;
const GRID_TITLE_PX = 20 + 4;

/**
 * Layout of the hold grid for a key row `width` px wide with `available` px
 * of visible page above it (above the on-screen keyboard): as many 44 px
 * columns as fit in the grid's inner width, and a cell height that fits the
 * rows in `available` — 44 px when it fits, never below 32 px.
 */
export function gridLayout(available: number, width: number): { columns: number; cell: number } {
  const inner = width - 2 * GRID_INSET_PX;
  const columns = Math.max(1, Math.floor((inner + GRID_GAP_PX) / (GRID_CELL_PX + GRID_GAP_PX)));
  const rows = Math.ceil(GRID_KEYS.length / columns);
  const fit = Math.floor(
    (available - 2 * GRID_INSET_PX - GRID_TITLE_PX + GRID_GAP_PX) / rows - GRID_GAP_PX,
  );
  return { columns, cell: Math.min(GRID_CELL_PX, Math.max(GRID_CELL_MIN_PX, fit)) };
}

// -- swipe pad --------------------------------------------------------------

/** Pixels of travel per arrow key on the swipe pad. */
const SWIPE_STEP_PX = 20;
/** Travel before the pad picks an axis. */
const SWIPE_AXIS_PX = 10;

/**
 * The swipe pad: one arrow per `SWIPE_STEP_PX` along the axis chosen by the
 * first `SWIPE_AXIS_PX` of travel. `move` returns the arrows to send now.
 */
export class SwipeTracker {
  private x0 = 0;
  private y0 = 0;
  private axis: "x" | "y" | null = null;
  private active = false;

  constructor(private readonly step = SWIPE_STEP_PX) {}

  start(x: number, y: number): void {
    this.x0 = x;
    this.y0 = y;
    this.axis = null;
    this.active = true;
  }

  move(x: number, y: number): ArrowKey[] {
    if (!this.active) return [];
    const dx = x - this.x0;
    const dy = y - this.y0;
    if (!this.axis && Math.max(Math.abs(dx), Math.abs(dy)) >= SWIPE_AXIS_PX)
      this.axis = Math.abs(dx) >= Math.abs(dy) ? "x" : "y";
    if (!this.axis) return [];
    const keys: ArrowKey[] = [];
    let travel = this.axis === "x" ? dx : dy;
    while (Math.abs(travel) >= this.step) {
      const sign = Math.sign(travel);
      keys.push(this.axis === "x" ? (sign > 0 ? "Right" : "Left") : sign > 0 ? "Down" : "Up");
      if (this.axis === "x") this.x0 += sign * this.step;
      else this.y0 += sign * this.step;
      travel -= sign * this.step;
    }
    return keys;
  }

  end(): void {
    this.active = false;
    this.axis = null;
  }
}

// -- text size --------------------------------------------------------------

/**
 * 1 px: a phone can shrink the text far enough to fit a wide
 * program. The cols × rows that follow are clamped to the relay contract's
 * PTY bounds (`clampTerminalSize`: 1024 × 512) before anything is sent.
 */
export const FONT_SIZE_MIN = 1;
export const FONT_SIZE_MAX = 20;
/** The view's default (`TERMINAL_OPTIONS.fontSize` in `xterm-view.ts`). */
export const FONT_SIZE_DEFAULT = 14;

export function clampFontSize(size: number): number {
  return Math.min(FONT_SIZE_MAX, Math.max(FONT_SIZE_MIN, Math.round(size)));
}

/**
 * Two-finger pinch → font size, whole px. Additive with square-root damping
 * (the demo's curve): doubling the finger distance adds 5 px and closing it
 * fully takes at most 5 px off, whatever the start size, so a pinch still
 * works at 1 px, where a multiplicative zoom would barely move.
 */
export function pinchFontSize(startSize: number, startDistance: number, distance: number): number {
  const ratio = Math.max(distance, 0) / Math.max(startDistance, 1);
  const delta = Math.sign(ratio - 1) * Math.sqrt(Math.abs(ratio - 1)) * 5;
  return clampFontSize(startSize + delta);
}

// -- photo paths ------------------------------------------------------------

/** Image types a photo upload accepts, with the extension they are saved under. */
export const PHOTO_TYPES: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};
/** The largest photo uploaded from the terminal (a 48 MP phone JPEG fits). */
export const PHOTO_MAX_BYTES = 16 * 1024 * 1024;

const pad2 = (n: number) => String(n).padStart(2, "0");

/** `<home>/.uploads/paste-YYYYMMDD-HHMMSS-<rand>.<ext>` in the guest. */
export function photoGuestPath(home: string, type: string, at: Date, suffix: string): string {
  const ext = PHOTO_TYPES[type] ?? "img";
  const stamp =
    `${at.getFullYear()}${pad2(at.getMonth() + 1)}${pad2(at.getDate())}-` +
    `${pad2(at.getHours())}${pad2(at.getMinutes())}${pad2(at.getSeconds())}`;
  return `${home.replace(/\/+$/, "")}/.uploads/paste-${stamp}-${suffix}.${ext}`;
}

/** A path as one shell word: unchanged when it is safe bare, else single-quoted. */
export function shellQuote(path: string): string {
  if (/^[A-Za-z0-9_./@%+=:,-]+$/.test(path)) return path;
  return `'${path.replace(/'/g, `'\\''`)}'`;
}
