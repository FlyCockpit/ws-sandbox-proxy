vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: { status: "authenticated", session: { session: { impersonatedBy: null } } },
  }),
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enTerminal from "@wssp/locales/src/en-US/terminal.json";
import { createInstance, type i18n as I18n } from "i18next";
import { type ReactNode, StrictMode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  FakeTerminalView,
  FakeWebSocket,
  fakeSession,
  fakeTicket,
  flush,
} from "@/test/terminal-fakes";

/**
 * The sandbox terminal card (C54) with the real hook and client, a mocked
 * xterm view module (its dynamic import is observable), a mocked oRPC client
 * and a scripted WebSocket that doubles as the backend.
 */

const createSession = vi.hoisted(() => vi.fn());
const loadedView = vi.hoisted(() => ({ count: 0 }));
const redirect = vi.hoisted(() => vi.fn(() => false));

vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@/utils/orpc", () => ({
  orpc: { sandboxTerminals: { createSession: { call: createSession } } },
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => redirect }));
vi.mock("@/lib/xterm-view", async () => {
  const { FakeTerminalView: View } = await import("@/test/terminal-fakes");
  loadedView.count += 1;
  return { createTerminalView: () => new View() };
});

import { TerminalPanel } from "../terminal-panel";
import { SandboxTerminal } from "./sandbox-terminal";

class FakeResizeObserver {
  static instances: FakeResizeObserver[] = [];
  observing = 0;
  constructor(readonly callback: () => void) {
    FakeResizeObserver.instances.push(this);
  }
  observe() {
    this.observing += 1;
  }
  unobserve() {}
  disconnect() {
    this.observing = 0;
  }
}

const clipboard = { writeText: vi.fn(async () => {}), readText: vi.fn(async () => "") };
let i18n: I18n;
let queryClient: QueryClient;
let minted = 0;

beforeAll(async () => {
  configure({ asyncUtilTimeout: 3000 });
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: "en-US",
    ns: ["terminal"],
    resources: { "en-US": { terminal: enTerminal } },
    interpolation: { escapeValue: false },
  });
});

/** `userEvent.setup()` installs its own clipboard stub; put ours back after it. */
function installClipboard() {
  Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true });
}

beforeEach(() => {
  FakeWebSocket.reset();
  FakeTerminalView.reset();
  FakeResizeObserver.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubGlobal("ResizeObserver", FakeResizeObserver);
  minted = 0;
  createSession.mockReset();
  createSession.mockImplementation(async (input: { sandboxId: string }) => {
    minted += 1;
    return fakeSession(input.sandboxId, fakeTicket(minted));
  });
  redirect.mockClear();
  clipboard.writeText.mockClear();
  clipboard.readText.mockReset();
  clipboard.readText.mockImplementation(async () => "");
  queryClient = new QueryClient();
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function wrap(children: ReactNode) {
  return (
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>{children}</I18nextProvider>
    </QueryClientProvider>
  );
}

function renderTerminal(available = true, strict = false) {
  const tree = wrap(<SandboxTerminal sandboxId="sbx_1" lang="en-US" available={available} />);
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

const toggle = () => screen.getByRole("button", { name: /attach|disconnect/i });

async function attach(user = userEvent.setup()) {
  await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
  await waitFor(() => expect(FakeWebSocket.instances.length).toBeGreaterThan(0));
  const socket = FakeWebSocket.last();
  act(() => {
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
  });
  await screen.findByText("Attached (100 × 30).");
  return { user, socket, view: FakeTerminalView.last() };
}

function cacheDump() {
  return JSON.stringify([
    queryClient
      .getQueryCache()
      .getAll()
      .map((query) => [query.queryKey, query.state.data]),
    queryClient
      .getMutationCache()
      .getAll()
      .map((mutation) => [mutation.options.mutationKey, mutation.state.data]),
  ]);
}

function storageDump() {
  const dump: string[] = [];
  for (const store of [localStorage, sessionStorage]) {
    for (let index = 0; index < store.length; index += 1) {
      const key = store.key(index) ?? "";
      dump.push(key, store.getItem(key) ?? "");
    }
  }
  return dump.join("\n");
}

describe("explicit attach", () => {
  it("opens nothing on mount: no ticket, no socket, no xterm", async () => {
    renderTerminal();
    await act(async () => {
      await flush(10);
    });
    expect(createSession).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(FakeTerminalView.instances).toHaveLength(0);
    expect(loadedView.count).toBe(0);
    expect(screen.getByText(enTerminal.status.idle)).toBeTruthy();
  });

  it("attaches on click: loads xterm, mints one ticket, connects, focuses the terminal", async () => {
    renderTerminal();
    const { socket, view } = await attach();
    expect(loadedView.count).toBe(1);
    expect(createSession).toHaveBeenCalledWith({
      sandboxId: "sbx_1",
      rows: 30,
      cols: 100,
      version: 2,
    });
    expect(socket.url).toBe("wss://app.example.test/api/dashboard/sandboxes/sbx_1/terminal/ws");
    expect(socket.protocols[1]).toBe(`wssp.terminal.ticket.${fakeTicket(1)}`);
    expect(view.focused).toBeGreaterThan(0);
    act(() => socket.serverBinary("$ "));
    expect(view.written).toEqual(["$ "]);
  });

  it("cannot attach while the sandbox is not Ready", async () => {
    renderTerminal(false);
    const button = screen.getByRole("button", { name: enTerminal.actions.attach });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(enTerminal.unavailable)).toBeTruthy();
  });
});

describe("the ticket (C53-CO-6)", () => {
  it("never reaches a query cache, storage, the URL or the DOM", async () => {
    renderTerminal();
    const { socket } = await attach();
    const ticket = fakeTicket(1);
    expect(cacheDump()).not.toContain(ticket);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(storageDump()).not.toContain(ticket);
    expect(socket.url).not.toContain(ticket);
    expect(window.location.href).not.toContain(ticket);
    expect(document.documentElement.outerHTML).not.toContain(ticket);
  });
});

describe("detach and re-attach", () => {
  it("disconnect sends CloseIntent, tears the socket down, and the backend sees the close", async () => {
    renderTerminal();
    const { user, socket, view } = await attach();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.detach }));
    expect(socket.sentText.at(-1)).toMatchObject({ type: "close" });
    expect(socket.closedByClient).toEqual({ code: 1000 });
    expect(socket.sessionClosed).toBe(true);
    expect(socket.listenerCount()).toBe(0);
    expect(view.listenerCount()).toBe(0);
    expect(FakeWebSocket.live()).toHaveLength(0);
    expect(screen.getByText(enTerminal.notice.client)).toBeTruthy();
    // The buffer stays readable until the next attach.
    expect(view.disposed).toBe(false);

    await user.click(screen.getByRole("button", { name: enTerminal.actions.reattach }));
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2));
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.last().protocols[1]).toBe(`wssp.terminal.ticket.${fakeTicket(2)}`);
    expect(view.disposed).toBe(true);
  });

  it("a relay drop shows Reconnecting and keeps the view; Disconnect cancels it (WP8)", async () => {
    renderTerminal();
    const { socket, view, user } = await attach();
    const terminalId = `t${"0".repeat(31)}1`;
    act(() => {
      socket.serverText({ type: "ready", rows: 30, cols: 100, terminalId, outputSeq: 0 });
      socket.serverText({ type: "reconnecting", terminalId, graceMs: 120_000 });
      socket.serverClose(4402);
    });
    expect(await screen.findByText(enTerminal.status.reconnecting)).toBeTruthy();
    expect(view.disposed).toBe(false);
    await user.click(screen.getByRole("button", { name: enTerminal.actions.detach }));
    expect(screen.getByText(enTerminal.notice.client)).toBeTruthy();
    expect(createSession).toHaveBeenCalledTimes(1);
  });

  it("a 4401 is final and shown by its intent; nothing reconnects", async () => {
    renderTerminal();
    const { socket } = await attach();
    act(() => socket.serverCloseIntent({ intent: "revoked" }, "sandbox_destroyed"));
    expect((await screen.findByRole("alert")).textContent).toBe(enTerminal.notice.revoked);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(createSession).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(screen.getByRole("button", { name: enTerminal.actions.reattach })).toBeTruthy();
  });

  it("a refused upgrade (1006 before open) is classified once, not retried", async () => {
    createSession
      .mockImplementationOnce(async () => fakeSession("sbx_1", fakeTicket(1)))
      .mockImplementationOnce(async () => {
        throw Object.assign(new Error("not running"), { code: "CONFLICT", status: 409 });
      });
    renderTerminal();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    act(() => FakeWebSocket.last().serverClose(1006));
    expect((await screen.findByRole("alert")).textContent).toBe(enTerminal.notice.notReady);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("explains a sandbox without a recorded guest identity (C52-CO-5)", async () => {
    renderTerminal();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.last();
    act(() => {
      socket.serverOpen();
      socket.serverCloseIntent({
        error: { code: "unsupported_capability", message: "no recorded terminal identity" },
      });
    });
    expect((await screen.findByRole("alert")).textContent).toBe(
      enTerminal.notice.noTerminalIdentity,
    );
  });

  it("a backpressure detach shows its reason and offers an explicit re-attach", async () => {
    renderTerminal();
    const { socket } = await attach();
    act(() =>
      socket.serverCloseIntent({
        intent: "backpressure",
        error: { code: "rate_limited", message: "slow consumer" },
      }),
    );
    expect((await screen.findByRole("alert")).textContent).toBe(enTerminal.notice.backpressure);
    expect(screen.getByRole("button", { name: enTerminal.actions.reattach })).toBeTruthy();
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("passes a refused createSession to the 2FA redirect", async () => {
    const error = Object.assign(new Error("2fa"), { code: "FORBIDDEN" });
    createSession.mockImplementationOnce(async () => {
      throw error;
    });
    renderTerminal();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    expect((await screen.findByRole("alert")).textContent).toBe(enTerminal.notice.forbidden);
    expect(redirect).toHaveBeenCalledWith(error);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});

describe("lifecycle", () => {
  it("Strict Mode double mount leaves no socket, listener, observer or view behind", async () => {
    const { unmount } = renderTerminal(true, true);
    await act(async () => {
      await flush(10);
    });
    expect(FakeWebSocket.instances).toHaveLength(0);
    const { socket, view } = await attach();
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeResizeObserver.instances.filter((observer) => observer.observing > 0)).toHaveLength(
      1,
    );
    unmount();
    expect(socket.sentText.at(-1)).toMatchObject({ type: "close" });
    expect(FakeWebSocket.live()).toHaveLength(0);
    expect(socket.listenerCount()).toBe(0);
    expect(view.listenerCount()).toBe(0);
    expect(view.disposed).toBe(true);
    expect(FakeResizeObserver.instances.filter((observer) => observer.observing > 0)).toHaveLength(
      0,
    );
    expect(FakeTerminalView.instances.filter((candidate) => !candidate.disposed)).toHaveLength(0);
  });

  it("unmounting while the ticket is being minted never opens a socket", async () => {
    let release!: () => void;
    createSession.mockImplementationOnce(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return fakeSession("sbx_1", fakeTicket(1));
    });
    const { unmount } = renderTerminal(true, true);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    await waitFor(() => expect(createSession).toHaveBeenCalledTimes(1));
    unmount();
    release();
    await act(async () => {
      await flush(10);
    });
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(FakeTerminalView.instances.every((view) => view.disposed)).toBe(true);
  });
});

describe("keyboard and focus", () => {
  it("attach and disconnect work from the keyboard, and focus stays on the toggle", async () => {
    renderTerminal();
    const user = userEvent.setup();
    await user.tab();
    expect(document.activeElement).toBe(toggle());
    await user.keyboard("{Enter}");
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.last();
    act(() => {
      socket.serverOpen();
      socket.serverText({ type: "ready", rows: 30, cols: 100 });
    });
    await screen.findByText("Attached (100 × 30).");
    expect(FakeTerminalView.last().focused).toBeGreaterThan(0);
    toggle().focus();
    await user.keyboard("{Enter}");
    expect(socket.sessionClosed).toBe(true);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: enTerminal.actions.reattach }),
    );
  });
});

describe("clipboard", () => {
  it("copies the selection only when Copy is pressed", async () => {
    renderTerminal();
    const { user, view } = await attach();
    installClipboard();
    view.selectionText = "secret output";
    expect(clipboard.writeText).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.copy }));
    expect(clipboard.writeText).toHaveBeenCalledWith("secret output");
    expect(await screen.findByText(enTerminal.clipboard.copied)).toBeTruthy();
  });

  it("pastes the clipboard into the PTY only when Paste is pressed", async () => {
    clipboard.readText.mockImplementation(async () => "echo hi");
    renderTerminal();
    const { user, socket, view } = await attach();
    installClipboard();
    expect(clipboard.readText).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.paste }));
    expect(view.pasted).toEqual(["echo hi"]);
    expect(new TextDecoder().decode(socket.sentBinary.at(-1))).toBe("echo hi");
  });

  it("refuses an oversized paste with a message and sends nothing", async () => {
    clipboard.readText.mockImplementation(async () => "a".repeat(65_537));
    renderTerminal();
    const { user, socket, view } = await attach();
    installClipboard();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.paste }));
    expect(await screen.findByText(enTerminal.clipboard.pasteTooLarge)).toBeTruthy();
    expect(screen.queryByText(enTerminal.clipboard.pasted)).toBeNull();
    expect(view.pasted).toEqual([]);
    expect(socket.sentBinary).toHaveLength(0);
  });

  it("a native paste (Ctrl/Cmd+V) is sent like the button's, and an oversized one is refused with a message", async () => {
    renderTerminal();
    const { socket, view } = await attach();
    act(() => view.nativePaste("echo native"));
    expect(view.pasted).toEqual(["echo native"]);
    expect(new TextDecoder().decode(socket.sentBinary.at(-1))).toBe("echo native");
    expect(await screen.findByText(enTerminal.clipboard.pasted)).toBeTruthy();
    const sent = socket.sentBinary.length;
    act(() => view.nativePaste("a".repeat(65_537)));
    expect(await screen.findByText(enTerminal.clipboard.pasteTooLarge)).toBeTruthy();
    expect(view.pasted).toHaveLength(1);
    expect(socket.sentBinary).toHaveLength(sent);
  });

  it("does not say Pasted when the paste detached the terminal for backpressure", async () => {
    clipboard.readText.mockImplementation(async () => "echo hi");
    renderTerminal();
    const { user, socket } = await attach();
    installClipboard();
    socket.bufferedAmount = 1024 * 1024 - 2;
    await user.click(screen.getByRole("button", { name: enTerminal.actions.paste }));
    expect(await screen.findByText(enTerminal.notice.backpressure)).toBeTruthy();
    expect(screen.queryByText(enTerminal.clipboard.pasted)).toBeNull();
  });

  it("E-22: a taken-over terminal shows the reason, not the stale Pasted line; a copy after the end is shown", async () => {
    clipboard.readText.mockImplementation(async () => "echo hi");
    renderTerminal();
    const { user, socket, view } = await attach();
    installClipboard();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.paste }));
    expect(await screen.findByText(enTerminal.clipboard.pasted)).toBeTruthy();
    act(() => socket.serverCloseIntent({ intent: "replaced" }));
    expect((await screen.findByRole("alert")).textContent).toBe(enTerminal.notice.replaced);
    expect(screen.queryByText(enTerminal.clipboard.pasted)).toBeNull();
    // The ended buffer can still be copied, and that result is shown.
    view.selectionText = "last output";
    await user.click(screen.getByRole("button", { name: enTerminal.actions.copy }));
    expect(clipboard.writeText).toHaveBeenCalledWith("last output");
    expect(await screen.findByText(enTerminal.clipboard.copied)).toBeTruthy();
  });

  it("an empty selection copies nothing", async () => {
    renderTerminal();
    const { user } = await attach();
    installClipboard();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.copy }));
    expect(clipboard.writeText).not.toHaveBeenCalled();
    expect(await screen.findByText(enTerminal.clipboard.copyEmpty)).toBeTruthy();
  });
});

describe("layout (mobile keyboard)", () => {
  it("the terminal box is bounded in small-viewport units and clips both axes", async () => {
    renderTerminal();
    await attach();
    const box = screen.getByRole("region", { name: enTerminal.regionLabel });
    const classes = box.className.split(/\s+/);
    expect(classes).toContain("overflow-hidden");
    expect(classes).toContain("h-[min(28rem,50svh)]");
    expect(classes.some((name) => /^(fixed|sticky|absolute)$/.test(name))).toBe(false);
    expect(classes.some((name) => /^overflow-y-/.test(name))).toBe(false);
    // No transition utility at all on the box (the policy bans the "all" form).
    expect(classes.some((name) => /^transition/.test(name))).toBe(false);
    for (const button of screen.getAllByRole("button")) {
      expect(button.getAttribute("data-size") ?? "touch").toBe("touch");
    }
  });
});

it("host panels use host availability and region copy", () => {
  render(wrap(<TerminalPanel hostId="host-1" lang="en-US" available={false} />));
  expect(screen.getByText(enTerminal.host.unavailable)).toBeTruthy();
  expect(screen.queryByText(enTerminal.unavailable)).toBeNull();
  expect(document.querySelector('[role="region"]')?.getAttribute("aria-label")).toBe(
    enTerminal.host.regionLabel,
  );
});

it.each([
  ["pool_access_removed", enTerminal.notice.poolAccessRemoved],
  ["host_terminals_disabled", enTerminal.notice.hostTerminalsDisabled],
] as const)("displays %s close copy from the real browser client", async (reason, message) => {
  renderTerminal();
  const { socket } = await attach();
  act(() => {
    socket.serverText({ type: "close", code: 4401, intent: "revoked", reason });
    socket.serverClose(4401);
  });
  expect((await screen.findByRole("alert")).textContent).toBe(message);
});
