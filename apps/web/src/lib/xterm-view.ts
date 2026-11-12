import "@xterm/xterm/css/xterm.css";

import { FitAddon } from "@xterm/addon-fit";
import { type IDisposable, type ITerminalOptions, Terminal } from "@xterm/xterm";

import type { TerminalView } from "./terminal-client";
import { clampTerminalSize } from "./terminal-protocol";

/**
 * The xterm-backed terminal view (C54). Only ever reached through a dynamic
 * `import()` on the owner's explicit attach, so xterm and its stylesheet stay
 * out of every initial chunk (`scripts/check-lazy-xterm.mjs`).
 *
 * Hardening. Bytes from a sandbox are untrusted:
 * - OSC 8 hyperlinks, OSC 52 clipboard, and the iTerm2 / kitty file-transfer
 *   and clipboard escapes are swallowed by parser handlers before xterm (or
 *   any addon) can act on them. No web-links addon is loaded, so plain-text
 *   URLs are never links either.
 * - The link handler is inert: activating a link does nothing (xterm's
 *   default would `confirm()` and open a window).
 * - Native copy, cut and drag-and-drop events on the terminal are cancelled:
 *   copy happens only through the explicit button.
 * - Native paste (Ctrl/Cmd+V, the context menu) is allowed but never reaches
 *   xterm directly (C55, user decision): the event is cancelled before xterm
 *   reads it and its `text/plain` is handed to `onNativePaste`, so it takes
 *   the same path as the Paste button (`TerminalClient.paste`: bracketed
 *   marker stripping and the size cap).
 * - Window manipulation reports (`windowOptions`) stay at xterm's all-off
 *   default; proposed APIs stay off.
 */

/** OSC identifiers that are consumed without effect. */
export const NEUTRALIZED_OSC = [
  8, // hyperlinks
  52, // clipboard read/write
  1337, // iTerm2 file transfer and clipboard
  5113, // kitty file transfer
  5522, // kitty clipboard
] as const;

/** Native events that would move data between the system clipboard and the PTY. */
export const BLOCKED_NATIVE_EVENTS = ["copy", "cut", "drop", "dragover"] as const;

export const TERMINAL_OPTIONS: ITerminalOptions = {
  allowProposedApi: false,
  cursorBlink: true,
  fontFamily:
    'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
  fontSize: 14,
  // Bounded: output lives only in this buffer and is never persisted.
  scrollback: 2000,
  linkHandler: {
    activate: () => {},
    allowNonHttpProtocols: false,
  },
  rightClickSelectsWord: false,
};

/**
 * Swallow the neutralized OSC sequences. xterm runs the most recently
 * registered handler first and stops at the first that returns true, so these
 * shadow xterm's own handlers (registered at construction) and any added
 * earlier.
 */
export function hardenTerminal(terminal: Terminal): IDisposable[] {
  return NEUTRALIZED_OSC.map((ident) => terminal.parser.registerOscHandler(ident, () => true));
}

export function createTerminalView(): TerminalView {
  const terminal = new Terminal(TERMINAL_OPTIONS);
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  const parserHandlers = hardenTerminal(terminal);
  let container: HTMLElement | null = null;
  const block = (event: Event) => {
    event.preventDefault();
    event.stopPropagation();
  };
  const pasteListeners = new Set<(text: string) => void>();
  // Capture phase on the container: runs before xterm's own textarea handler,
  // which never sees the event, so the raw clipboard never bypasses the client.
  const onPaste = (event: Event) => {
    block(event);
    const text = (event as ClipboardEvent).clipboardData?.getData("text/plain") ?? "";
    for (const listener of pasteListeners) listener(text);
  };

  return {
    open(element) {
      container = element;
      for (const type of BLOCKED_NATIVE_EVENTS) element.addEventListener(type, block, true);
      element.addEventListener("paste", onPaste, true);
      terminal.open(element);
    },
    write(data) {
      terminal.write(data);
    },
    onData(listener) {
      return terminal.onData(listener);
    },
    onBinary(listener) {
      return terminal.onBinary(listener);
    },
    onNativePaste(listener) {
      pasteListeners.add(listener);
      return { dispose: () => pasteListeners.delete(listener) };
    },
    fit() {
      const size = clampTerminalSize(fit.proposeDimensions());
      if (!size) return null;
      if (size.rows !== terminal.rows || size.cols !== terminal.cols)
        terminal.resize(size.cols, size.rows);
      return size;
    },
    selection() {
      return terminal.getSelection();
    },
    paste(text) {
      terminal.paste(text);
    },
    focus() {
      terminal.focus();
    },
    dispose() {
      if (container) {
        for (const type of BLOCKED_NATIVE_EVENTS) container.removeEventListener(type, block, true);
        container.removeEventListener("paste", onPaste, true);
        container = null;
      }
      pasteListeners.clear();
      for (const handler of parserHandlers) handler.dispose();
      terminal.dispose();
    },
  };
}
