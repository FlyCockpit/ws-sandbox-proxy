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
const getOperation = vi.hoisted(() => vi.fn());
const uploadToSandbox = vi.hoisted(() => vi.fn());
vi.mock("@/utils/orpc", async () => {
  const { skipToken } = await import("@tanstack/react-query");
  return {
    orpc: {
      sandboxTerminals: { createSession: { call: createSession } },
      sandboxes: { getOperation: { call: getOperation } },
      sandboxTemplates: {
        getTemplateRevision: {
          queryOptions: ({ input }: { input: unknown }) => ({
            queryKey: ["templateRevision", input],
            queryFn: input === skipToken ? skipToken : async () => ({ guestHome: "/home/user" }),
          }),
        },
      },
    },
  };
});
vi.mock("@/lib/sandbox-transfers", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/sandbox-transfers")>()),
  uploadToSandbox,
}));
// The keyboard inset the real hook measures from visualViewport (0: no keyboard).
const keyboard = vi.hoisted(() => ({ inset: 0, top: 0 }));
vi.mock("@/hooks/use-terminal-utilities", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/use-terminal-utilities")>();
  return {
    ...actual,
    useKeyboardInset: (...args: Parameters<typeof actual.useKeyboardInset>) => {
      const measured = actual.useKeyboardInset(...args);
      return args[1] && keyboard.inset > 0
        ? { bottom: keyboard.inset, top: keyboard.top }
        : measured;
    },
  };
});
const toastMessage = vi.hoisted(() => vi.fn());
vi.mock("@wssp/ui/components/sileo", () => ({
  toast: {
    message: toastMessage,
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
  },
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => redirect }));
// The phone picker's "New terminal…" is a router Link; a plain anchor here.
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    to,
    params,
    ...rest
  }: { to: string; params?: { lang?: string } } & Record<string, unknown>) => (
    <a href={to.replace("$lang", params?.lang ?? "")} {...rest} />
  ),
}));
vi.mock("@/lib/xterm-view", async () => {
  const { FakeTerminalView: View } = await import("@/test/terminal-fakes");
  loadedView.count += 1;
  return { createTerminalView: () => new View() };
});

import { HOLD_GRID_MS } from "@/lib/terminal-keys";
import { useTerminalPreferences } from "@/stores/terminal-preferences";
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
  uploadToSandbox.mockReset();
  getOperation.mockReset();
  clipboard.writeText.mockClear();
  clipboard.readText.mockReset();
  clipboard.readText.mockImplementation(async () => "");
  queryClient = new QueryClient();
  useTerminalPreferences.setState({ keysShown: false, fontSize: null });
  keyboard.inset = 0;
  keyboard.top = 0;
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

const toggle = () => screen.getByRole("button", { name: /attach|end session/i });

/** End session asks first: the confirmation dialog, then its End session button. */
async function endSession(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: enTerminal.actions.endSession }));
  const dialog = await screen.findByRole("alertdialog");
  expect(dialog.textContent).toContain(enTerminal.endDialog.title);
  await user.click(screen.getByRole("button", { name: enTerminal.endDialog.confirm }));
}

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
  it("End session asks first; Cancel keeps the shell", async () => {
    renderTerminal();
    const { user, socket } = await attach();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.endSession }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(socket.sentText.some((frame) => (frame as { type?: string }).type === "close")).toBe(
      false,
    );
    await user.click(screen.getByRole("button", { name: enTerminal.endDialog.cancel }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(socket.sessionClosed).toBe(false);
    expect(screen.getByText("Attached (100 × 30).")).toBeTruthy();
  });

  it("End session sends CloseIntent, tears the socket down, and the backend sees the close", async () => {
    renderTerminal();
    const { user, socket, view } = await attach();
    await endSession(user);
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

  it("a relay drop shows Reconnecting and keeps the view; End session cancels it (WP8)", async () => {
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
    await endSession(user);
    expect(await screen.findByText(enTerminal.notice.client)).toBeTruthy();
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

  it("explains a sandbox without a recorded guest identity", async () => {
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
  it("attach and End session work from the keyboard, and focus comes back to the toggle", async () => {
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
    await screen.findByRole("alertdialog");
    // The dialog starts on Cancel; Tab reaches End session.
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("button", { name: enTerminal.endDialog.cancel }),
      ),
    );
    await user.tab();
    await user.keyboard("{Enter}");
    expect(socket.sessionClosed).toBe(true);
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("button", { name: enTerminal.actions.reattach }),
      ),
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

describe("utilities (design D)", () => {
  const decode = (bytes: Uint8Array | undefined) => new TextDecoder().decode(bytes);
  const openUtilities = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(screen.getByRole("button", { name: enTerminal.utilities.button }));
    return screen.findByRole("menu");
  };
  const pointer = (element: Element, type: string, x = 0, y = 0) => {
    const event = new MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y });
    Object.defineProperty(event, "pointerId", { value: 1 });
    act(() => {
      element.dispatchEvent(event);
    });
    return event;
  };

  it("the key row is hidden by default; Show keys shows it and is remembered on this device", async () => {
    const first = renderTerminal();
    const { user } = await attach();
    expect(document.querySelector("[data-terminal-keys]")).toBeNull();
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.showKeys }));
    expect(document.querySelector("[data-terminal-keys]")).not.toBeNull();
    expect(localStorage.getItem("terminal-preferences")).toContain('"keysShown":true');
    first.unmount();
    // A reload: the in-memory store starts over and reads this device's storage.
    const stored = localStorage.getItem("terminal-preferences") ?? "";
    useTerminalPreferences.setState({ keysShown: false });
    localStorage.setItem("terminal-preferences", stored);
    await useTerminalPreferences.persist.rehydrate();
    renderTerminal();
    await attach();
    expect(document.querySelector("[data-terminal-keys]")).not.toBeNull();
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.hideKeys }));
    expect(document.querySelector("[data-terminal-keys]")).toBeNull();
  });

  it("Esc, Tab and the swipe pad send their bytes, arrows following application cursor mode", async () => {
    useTerminalPreferences.setState({ keysShown: true });
    renderTerminal();
    const { user, socket, view } = await attach();
    view.hasFocusValue = true;
    await user.click(screen.getByRole("button", { name: "Esc" }));
    expect(decode(socket.sentBinary.at(-1))).toBe("\x1b");
    await user.click(screen.getByRole("button", { name: "Tab" }));
    expect(decode(socket.sentBinary.at(-1))).toBe("\t");
    // The keys never take focus: the terminal is focused again after a tap.
    expect(view.focused).toBeGreaterThan(0);
    const pad = screen.getByRole("slider", { name: enTerminal.keys.swipeLabel });
    const before = socket.sentBinary.length;
    pointer(pad, "pointerdown", 100, 100);
    pointer(pad, "pointermove", 145, 102);
    expect(socket.sentBinary.slice(before).map(decode)).toEqual(["\x1b[C", "\x1b[C"]);
    pointer(pad, "pointerup", 145, 102);
    view.applicationCursor = true;
    pointer(pad, "pointerdown", 100, 100);
    pointer(pad, "pointermove", 100, 78);
    expect(decode(socket.sentBinary.at(-1))).toBe("\x1bOA");
    pointer(pad, "pointerup", 100, 78);
  });

  it("a tapped Ctrl or Alt applies to the next typed character only; a paste is never modified", async () => {
    useTerminalPreferences.setState({ keysShown: true });
    renderTerminal();
    const { user, socket, view } = await attach();
    const ctrl = screen.getByRole("button", { name: /^Ctrl/ });
    await user.click(ctrl);
    expect(ctrl.getAttribute("data-latch")).toBe("once");
    act(() => view.type("c"));
    expect(decode(socket.sentBinary.at(-1))).toBe("\x03");
    expect(ctrl.getAttribute("data-latch")).toBe("off");
    act(() => view.type("c"));
    expect(decode(socket.sentBinary.at(-1))).toBe("c");
    await user.click(screen.getByRole("button", { name: /^Alt/ }));
    act(() => view.nativePaste("x"));
    expect(decode(socket.sentBinary.at(-1))).toBe("x");
    act(() => view.type("x"));
    expect(decode(socket.sentBinary.at(-1))).toBe("\x1bx");
  });

  it("holding Ctrl opens the letter grid; sliding to a key and lifting sends the combination", async () => {
    // Real time (the gesture timer itself is covered with fake timers in terminal-keys.test.ts).
    const elementFromPoint = document.elementFromPoint;
    try {
      useTerminalPreferences.setState({ keysShown: true });
      renderTerminal();
      const { socket } = await attach();
      const ctrl = screen.getByRole("button", { name: /^Ctrl/ });
      pointer(ctrl, "pointerdown");
      await act(() => new Promise((resolve) => setTimeout(resolve, HOLD_GRID_MS + 50)));
      const cell = document.querySelector('[data-grid-key="c"]');
      expect(cell).not.toBeNull();
      document.elementFromPoint = () => cell;
      pointer(ctrl, "pointermove", 10, 10);
      pointer(ctrl, "pointerup", 10, 10);
      expect(decode(socket.sentBinary.at(-1))).toBe("\x03");
      expect(document.querySelector("[data-terminal-key-grid]")).toBeNull();
      expect(ctrl.getAttribute("data-latch")).toBe("off");
    } finally {
      document.elementFromPoint = elementFromPoint;
    }
  });

  it("Paste… sends the text through the bracketed paste path, then Enter when asked", async () => {
    renderTerminal();
    const { user, socket, view } = await attach();
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.paste }));
    const dialog = await screen.findByRole("dialog");
    await user.type(
      screen.getByRole("textbox", { name: enTerminal.pasteDialog.text }),
      "echo a{Enter}echo b",
    );
    expect(dialog.textContent).toContain("2 lines, 13 bytes.");
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: enTerminal.pasteDialog.send }));
    expect(view.pasted).toEqual(["echo a\necho b"]);
    expect(socket.sentBinary.slice(-2).map(decode)).toEqual(["echo a\necho b", "\r"]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Paste from clipboard says clearly when the browser blocks it", async () => {
    renderTerminal();
    const { user } = await attach();
    installClipboard();
    clipboard.readText.mockImplementation(async () => {
      throw new DOMException("denied", "NotAllowedError");
    });
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.paste }));
    await user.click(
      await screen.findByRole("button", { name: enTerminal.pasteDialog.fromClipboard }),
    );
    expect(await screen.findByText(enTerminal.pasteDialog.clipboardBlocked)).toBeTruthy();
  });

  it("A+ / A− / Reset change the text size, refit and are remembered", async () => {
    renderTerminal();
    const { user, view } = await attach();
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.larger }));
    await waitFor(() => expect(view.fontSize).toBe(15));
    expect(localStorage.getItem("terminal-preferences")).toContain('"fontSize":15');
    // The menu stays open for further steps.
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.smaller }));
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.smaller }));
    await waitFor(() => expect(view.fontSize).toBe(13));
    expect(await screen.findByText("13 px · 100×30")).toBeTruthy();
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.reset }));
    await waitFor(() => expect(view.fontSize).toBe(14));
    expect(localStorage.getItem("terminal-preferences")).toContain('"fontSize":null');
  });

  it("a remembered text size applies to the next attach before the first fit", async () => {
    // As stored by an earlier visit on this device.
    localStorage.setItem(
      "terminal-preferences",
      JSON.stringify({ state: { keysShown: false, fontSize: 18 }, version: 1 }),
    );
    await useTerminalPreferences.persist.rehydrate();
    renderTerminal();
    const { view } = await attach();
    expect(view.fontSize).toBe(18);
  });

  it("Photo uploads into ~/.uploads, waits for the write, then types the path and a space", async () => {
    uploadToSandbox.mockResolvedValue({ transferId: "t", operationId: "op_1", sha256: "" });
    getOperation.mockResolvedValueOnce({ state: "RUNNING" }).mockResolvedValue({
      state: "SUCCEEDED",
    });
    URL.createObjectURL = () => "blob:photo";
    URL.revokeObjectURL = () => {};
    render(
      wrap(
        <SandboxTerminal
          sandboxId="sbx_1"
          lang="en-US"
          available
          photo={{ sandboxId: "sbx_1", guestHome: "/home/user" }}
        />,
      ),
    );
    const { user, view } = await attach();
    await openUtilities(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.photo }));
    const take = (await screen.findByRole("dialog")).querySelector(
      '[data-photo-input="take"]',
    ) as HTMLInputElement;
    expect(take.getAttribute("capture")).toBe("environment");
    await user.upload(take, new File(["jpeg"], "IMG_1.jpg", { type: "image/jpeg" }));
    await user.click(screen.getByRole("button", { name: enTerminal.photo.send }));
    await waitFor(() => expect(view.pasted).toHaveLength(1), { timeout: 4000 });
    const [call] = uploadToSandbox.mock.calls;
    expect(call?.[1].sandboxId).toBe("sbx_1");
    expect(call?.[1].guestPath).toMatch(/^\/home\/user\/\.uploads\/paste-\d{8}-\d{6}-\w+\.jpg$/);
    expect(view.pasted[0]).toBe(`${call?.[1].guestPath} `);
    expect(getOperation).toHaveBeenCalledWith({ operationId: "op_1" }, expect.anything());
  });

  it("Photo is not offered on host terminals", async () => {
    render(wrap(<TerminalPanel hostId="host-1" lang="en-US" available={false} />));
    const user = userEvent.setup();
    await openUtilities(user);
    expect(screen.queryByRole("menuitem", { name: enTerminal.utilities.photo })).toBeNull();
  });
});

it("Photo refuses a file that is not a PNG, JPEG, WebP or GIF image", async () => {
  URL.createObjectURL = () => "blob:photo";
  URL.revokeObjectURL = () => {};
  render(
    wrap(
      <SandboxTerminal
        sandboxId="sbx_1"
        lang="en-US"
        available
        photo={{ sandboxId: "sbx_1", guestHome: "/home/user" }}
      />,
    ),
  );
  const { user } = await attach();
  await user.click(screen.getByRole("button", { name: enTerminal.utilities.button }));
  await user.click(await screen.findByRole("menuitem", { name: enTerminal.utilities.photo }));
  const choose = (await screen.findByRole("dialog")).querySelector(
    '[data-photo-input="choose"]',
  ) as HTMLInputElement;
  // `image/heic` matches the picker's `image/*` but is not a type agents read.
  await user.upload(choose, new File(["x"], "notes.heic", { type: "image/heic" }));
  expect(await screen.findByText(enTerminal.photo.badType)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: enTerminal.photo.send }) as HTMLButtonElement).disabled,
  ).toBe(true);
  expect(uploadToSandbox).not.toHaveBeenCalled();
});

it("a one-shot Ctrl applies to the first arrow of a multi-arrow swipe only", async () => {
  useTerminalPreferences.setState({ keysShown: true });
  renderTerminal();
  const { user, socket } = await attach();
  await user.click(screen.getByRole("button", { name: /^Ctrl/ }));
  const pad = screen.getByRole("slider", { name: enTerminal.keys.swipeLabel });
  const before = socket.sentBinary.length;
  for (const [type, x] of [
    ["pointerdown", 100],
    ["pointermove", 145],
    ["pointerup", 145],
  ] as const) {
    const event = new MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: 0 });
    Object.defineProperty(event, "pointerId", { value: 1 });
    act(() => {
      pad.dispatchEvent(event);
    });
  }
  expect(socket.sentBinary.slice(before).map((b) => new TextDecoder().decode(b))).toEqual([
    "\x1b[1;5C",
    "\x1b[C",
  ]);
  expect(screen.getByRole("button", { name: /^Ctrl/ }).getAttribute("data-latch")).toBe("off");
});

it("a photo written while the terminal is not attached keeps its path for Type path", async () => {
  uploadToSandbox.mockResolvedValue({ transferId: "t", operationId: "op_2", sha256: "" });
  let finishWrite: (value: { state: string }) => void = () => {};
  getOperation.mockImplementation(
    () =>
      new Promise((resolve) => {
        finishWrite = resolve;
      }),
  );
  render(
    wrap(
      <SandboxTerminal
        sandboxId="sbx_1"
        lang="en-US"
        available
        photo={{ sandboxId: "sbx_1", guestHome: "/home/user" }}
      />,
    ),
  );
  const { user, socket, view } = await attach();
  await user.click(screen.getByRole("button", { name: enTerminal.utilities.button }));
  await user.click(await screen.findByRole("menuitem", { name: enTerminal.utilities.photo }));
  const choose = (await screen.findByRole("dialog")).querySelector(
    '[data-photo-input="choose"]',
  ) as HTMLInputElement;
  await user.upload(choose, new File(["png"], "a.png", { type: "image/png" }));
  await user.click(screen.getByRole("button", { name: enTerminal.photo.send }));
  await waitFor(() => expect(getOperation).toHaveBeenCalled());
  // The session ends while the sandbox writes the file.
  act(() => {
    socket.serverText({ type: "close", code: 4401, intent: "detached" });
    socket.serverClose(4401);
  });
  await act(async () => finishWrite({ state: "SUCCEEDED" }));
  expect(await screen.findByText(enTerminal.photo.placed, { exact: false })).toBeTruthy();
  expect(document.querySelector('[data-photo-phase="placed"] code')?.textContent).toMatch(
    /^\/home\/user\/\.uploads\/paste-\d{8}-\d{6}-\w+\.png$/,
  );
  expect(screen.getByRole("button", { name: enTerminal.photo.typePath })).toBeTruthy();
  expect(view.pasted).toEqual([]);
});

it("a paste the terminal cannot take keeps the dialog and the draft", async () => {
  renderTerminal();
  const { user, socket } = await attach();
  await user.click(screen.getByRole("button", { name: enTerminal.utilities.button }));
  await user.click(await screen.findByRole("menuitem", { name: enTerminal.utilities.paste }));
  await user.type(
    await screen.findByRole("textbox", { name: enTerminal.pasteDialog.text }),
    "keep me",
  );
  act(() => {
    socket.serverText({ type: "close", code: 4401, intent: "detached" });
    socket.serverClose(4401);
  });
  await user.click(screen.getByRole("button", { name: enTerminal.pasteDialog.send }));
  expect(await screen.findByText(enTerminal.pasteDialog.notAttached)).toBeTruthy();
  expect(
    (screen.getByRole("textbox", { name: enTerminal.pasteDialog.text }) as HTMLTextAreaElement)
      .value,
  ).toBe("keep me");
});

describe("phone header (one row, one menu)", () => {
  const PHONE = "(max-width: 640px)";
  beforeEach(() => {
    vi.stubGlobal(
      "matchMedia",
      (query: string) =>
        ({
          matches: query === PHONE,
          media: query,
          onchange: null,
          addListener() {},
          removeListener() {},
          addEventListener() {},
          removeEventListener() {},
          dispatchEvent: () => false,
        }) as unknown as MediaQueryList,
    );
  });

  const renderPhone = (props: Partial<Parameters<typeof SandboxTerminal>[0]> = {}) =>
    render(
      wrap(
        <SandboxTerminal sandboxId="sbx_1" name="build-box" lang="en-US" available {...props} />,
      ),
    );
  const indicator = () =>
    document
      .querySelector("[data-terminal-picker] [data-terminal-indicator]")
      ?.getAttribute("data-terminal-indicator");
  const openMore = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(screen.getByRole("button", { name: enTerminal.header.more }));
    return screen.findByRole("menu");
  };
  const decode = (bytes: Uint8Array | undefined) => new TextDecoder().decode(bytes);

  it("before attach shows only Attach; once shown, one row: picker, ⋯, Maximize, and no status line", async () => {
    renderPhone();
    expect(document.querySelector("[data-terminal-header]")).toBeNull();
    expect(screen.getByRole("button", { name: enTerminal.actions.attach })).toBeTruthy();
    await attach();
    const row = document.querySelector("[data-terminal-header]") as HTMLElement;
    expect(row).not.toBeNull();
    const buttons = [...row.querySelectorAll("button")].map(
      (button) =>
        button.getAttribute("data-terminal-picker") ??
        (button.hasAttribute("data-terminal-more")
          ? "more"
          : button.getAttribute("data-terminal-maximize")),
    );
    expect(buttons).toEqual(["", "more", "maximize"]);
    expect(row.textContent).toContain("build-box");
    // No old actions row: no End session / Copy / Utilities buttons outside the menus.
    expect(screen.queryByRole("button", { name: enTerminal.actions.endSession })).toBeNull();
    expect(screen.queryByRole("button", { name: enTerminal.utilities.button })).toBeNull();
    expect(document.querySelector("[data-terminal-copy]")).toBeNull();
    // The status is for screen readers only.
    expect(document.querySelector("[data-terminal-state]")?.className).toBe("sr-only");
    expect(indicator()).toBe("typing-connected");
  });

  it("the picker lists this terminal with its state and offers New terminal… where wssp opens terminals", async () => {
    renderPhone();
    const { user } = await attach();
    const picker = document.querySelector("[data-terminal-picker]") as HTMLElement;
    expect(picker.getAttribute("aria-label")).toBe(
      "Terminal: build-box, Connected · typing. Switch terminal",
    );
    await user.click(picker);
    const menu = await screen.findByRole("menu");
    expect(menu.textContent).toContain(enTerminal.header.openTerminals);
    const current = menu.querySelector('[data-terminal-picker-item="current"]') as HTMLElement;
    expect(current.getAttribute("aria-checked")).toBe("true");
    expect(current.textContent).toContain("build-box");
    expect(current.textContent).toContain(enTerminal.header.state.typing);
    const create = menu.querySelector("[data-terminal-new]") as HTMLAnchorElement;
    expect(create.getAttribute("href")).toBe("/en-US/dashboard/sandboxes");
    expect(create.textContent).toContain(enTerminal.header.newTerminal);
    // Leaving the page ends this terminal: said before you go.
    expect(create.textContent).toContain(enTerminal.header.newTerminalLeaves);
    // Picking the current terminal just closes the list.
    await user.click(current);
    await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
    expect(FakeWebSocket.live()).toHaveLength(1);
  });

  it("inside a dialog (maximizable=false) there is no Maximize, on phones or wide", async () => {
    render(wrap(<TerminalPanel sandboxId="sbx_1" lang="en-US" available maximizable={false} />));
    await attach();
    expect(document.querySelector("[data-terminal-header]")).not.toBeNull();
    expect(document.querySelector("[data-terminal-maximize]")).toBeNull();
  });

  it("a host terminal's New terminal… goes to Hosts", async () => {
    render(wrap(<TerminalPanel hostId="host-1" name="halo-0" lang="en-US" available />));
    createSession.mockClear();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    // The host mint is refused here (no host mock): the header shows the red refusal.
    await waitFor(() => expect(document.querySelector("[data-terminal-header]")).not.toBeNull());
    await user.click(document.querySelector("[data-terminal-picker]") as HTMLElement);
    const menu = await screen.findByRole("menu");
    expect(menu.querySelector("[data-terminal-new]")?.getAttribute("href")).toBe(
      "/en-US/settings/hosts",
    );
  });

  it("⋯ has the Type & view group, then the Session group with End session last (red)", async () => {
    renderPhone({ photo: { sandboxId: "sbx_1", guestHome: "/home/user" }, typeCommand: "claude" });
    const { user } = await attach();
    const menu = await openMore(user);
    const typeView = menu.querySelector('[data-menu-group="type-view"]') as HTMLElement;
    const session = menu.querySelector('[data-menu-group="session"]') as HTMLElement;
    expect(typeView.textContent).toContain(enTerminal.header.typeView);
    expect(session.textContent).toContain(enTerminal.header.session);
    const items = (group: HTMLElement) =>
      [...group.querySelectorAll("[data-utility],[data-session]")].map(
        (item) => item.getAttribute("data-utility") ?? item.getAttribute("data-session"),
      );
    expect(items(typeView)).toEqual([
      "keys",
      "paste",
      "photo",
      "smaller",
      "larger",
      "reset",
      "select",
      "copy",
      "type",
    ]);
    expect(items(session)).toEqual(["end"]);
    const end = session.querySelector('[data-session="end"]') as HTMLElement;
    expect(end.hasAttribute("data-danger")).toBe(true);
    // Important classes: the shared menu recolours focused items and their icons.
    expect(end.className).toContain("text-destructive!");
    expect(end.className).toContain("*:[svg]:text-destructive!");
    // Groups come in order: Type & view first.
    expect(
      typeView.compareDocumentPosition(session) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("every Type & view item works from ⋯: keys, paste, text size, select, copy, type", async () => {
    renderPhone({ typeCommand: "claude login" });
    const { user, view, socket } = await attach();
    // Show keys.
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.showKeys }));
    expect(await screen.findByRole("toolbar", { name: enTerminal.keys.label })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: enTerminal.keys.name.esc }));
    expect(decode(socket.sentBinary.at(-1))).toBe("\x1b");
    // Paste… dialog.
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.paste }));
    const dialog = await screen.findByRole("dialog");
    await user.type(dialog.querySelector("textarea") as HTMLTextAreaElement, "ls");
    await user.click(screen.getByRole("button", { name: enTerminal.pasteDialog.send }));
    await waitFor(() => expect(view.pasted).toEqual(["ls"]));
    // Text size.
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.larger }));
    await waitFor(() => expect(view.fontSize).toBe(15));
    await user.keyboard("{Escape}");
    // Type it for me.
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.actions.type }));
    await waitFor(() => expect(view.pasted.at(-1)).toBe("claude login"));
    // Copy selection.
    view.selectionText = "picked";
    installClipboard();
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.actions.copy }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith("picked"));
  });

  it("Select text shows the terminal's text; Copy takes only a selection inside it, native copy stays blocked", async () => {
    renderPhone();
    const { user, view } = await attach();
    act(() => view.write(new TextEncoder().encode("hello world")));
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.header.selectText }));
    const box = (await screen.findByLabelText(enTerminal.selectText.label)) as HTMLElement;
    expect(box.textContent).toBe("hello world");
    installClipboard();
    // Nothing selected: says so, copies nothing.
    window.getSelection()?.removeAllRanges();
    await user.click(screen.getByRole("button", { name: enTerminal.selectText.copy }));
    expect(clipboard.writeText).not.toHaveBeenCalled();
    expect(document.querySelector("[data-terminal-select] [role=status]")?.textContent).toBe(
      enTerminal.clipboard.copyEmpty,
    );
    // A selection inside the box is copied by the button.
    const range = document.createRange();
    const textNode = box.firstChild as Text;
    range.setStart(textNode, 0);
    range.setEnd(textNode, 5);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
    await user.click(screen.getByRole("button", { name: enTerminal.selectText.copy }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith("hello"));
    const copy = new Event("copy", { bubbles: true, cancelable: true });
    box.dispatchEvent(copy);
    expect(copy.defaultPrevented).toBe(true);
    await user.click(screen.getByRole("button", { name: enTerminal.selectText.done }));
    expect(document.querySelector("[data-terminal-select]")).toBeNull();
  });

  it("End session from ⋯ asks first; then grey, the reason and Attach again inside the terminal area", async () => {
    renderPhone();
    const { user, socket, view } = await attach();
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.header.endSession }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("build-box");
    expect(socket.sessionClosed).toBe(false);
    await user.click(screen.getByRole("button", { name: enTerminal.endDialog.confirm }));
    await waitFor(() => expect(socket.sessionClosed).toBe(true));
    expect(socket.sentText.some((frame) => (frame as { type?: string }).type === "close")).toBe(
      true,
    );
    await waitFor(() => expect(indicator()).toBe("typing-ended"));
    // The notice sits inside the terminal area, with Attach again.
    const notice = document.querySelector('[data-terminal-notice="client"]') as HTMLElement;
    expect(notice.closest(".relative")?.querySelector("[data-terminal-view]")).not.toBeNull();
    expect(notice.textContent).toContain(enTerminal.notice.client);
    // Session on an ended terminal: Attach again and Close, no End session.
    const menu = await openMore(user);
    const session = menu.querySelector('[data-menu-group="session"]') as HTMLElement;
    expect(session.querySelector('[data-session="end"]')).toBeNull();
    await user.click(screen.getByRole("menuitem", { name: enTerminal.header.close }));
    // Close: the ended view goes and the panel is idle again.
    await waitFor(() => expect(document.querySelector("[data-terminal-header]")).toBeNull());
    expect(view.disposed).toBe(true);
    expect(screen.getByRole("button", { name: enTerminal.actions.attach })).toBeTruthy();
    expect(createSession).toHaveBeenCalledTimes(1);
  });

  it("Attach again inside the terminal area starts a new session", async () => {
    renderPhone();
    const { socket } = await attach();
    act(() => socket.serverCloseIntent({ intent: "replaced" }));
    const notice = await waitFor(() => {
      const element = document.querySelector('[data-terminal-notice="replaced"]');
      if (!element) throw new Error("no notice yet");
      return element as HTMLElement;
    });
    expect(notice.getAttribute("role")).toBe("alert");
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.reattach }));
    await waitFor(() => expect(createSession).toHaveBeenCalledTimes(2));
  });

  it("reconnecting is the eye (view only, amber), and typing reaches nothing", async () => {
    renderPhone();
    const { socket, view } = await attach();
    const terminalId = `t${"0".repeat(31)}1`;
    act(() => {
      socket.serverText({ type: "ready", rows: 30, cols: 100, terminalId, outputSeq: 0 });
      socket.serverText({ type: "reconnecting", terminalId, graceMs: 120_000 });
      socket.serverClose(4402);
    });
    await waitFor(() => expect(indicator()).toBe("viewing-opening"));
    const sent = socket.sentBinary.length;
    view.type("rm -rf x\r");
    expect(socket.sentBinary.length).toBe(sent);
    expect(
      (document.querySelector("[data-terminal-picker]") as HTMLElement).getAttribute("aria-label"),
    ).toContain(enTerminal.header.state.viewing);
  });

  it("a refused terminal is red", async () => {
    createSession.mockImplementationOnce(async () => {
      throw Object.assign(new Error("not found"), { code: "NOT_FOUND" });
    });
    renderPhone();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.attach }));
    await waitFor(() => expect(indicator()).toBe("typing-refused"));
  });

  it("Maximize fills the screen and Restore puts it back, at every width", async () => {
    renderPhone();
    const { user } = await attach();
    const section = document.querySelector("[data-terminal-status]") as HTMLElement;
    expect(section.hasAttribute("data-terminal-maximized")).toBe(false);
    await user.click(screen.getByRole("button", { name: enTerminal.header.maximize }));
    expect(section.hasAttribute("data-terminal-maximized")).toBe(true);
    expect(section.className).toContain("fixed");
    expect(section.className).toContain("inset-0");
    const restore = screen.getByRole("button", { name: enTerminal.header.restore });
    expect(restore.getAttribute("aria-pressed")).toBe("true");
    await user.click(restore);
    expect(section.hasAttribute("data-terminal-maximized")).toBe(false);
  });

  it("maximized with the phone keyboard up, the panel ends at the keyboard and the key row stays inside it", async () => {
    useTerminalPreferences.setState({ keysShown: true });
    renderPhone();
    const { user } = await attach();
    const section = document.querySelector("[data-terminal-status]") as HTMLElement;
    // The row's outer element (what is pinned).
    const keys = () =>
      screen.getByRole("toolbar", { name: enTerminal.keys.label }).parentElement as HTMLElement;
    keyboard.inset = 300;
    // Not maximized: the key row is pinned above the keyboard (design D).
    await user.click(screen.getByRole("button", { name: enTerminal.header.maximize }));
    expect(section.style.bottom).toBe("300px");
    expect(section.style.top).toBe("0px");
    expect(keys().className).not.toContain("fixed");
    expect(document.querySelector("[data-terminal-keys-placeholder]")).toBeNull();
    await user.click(screen.getByRole("button", { name: enTerminal.header.restore }));
    expect(section.style.bottom).toBe("");
    expect(keys().className).toContain("fixed");
    expect(keys().style.bottom).toBe("300px");
  });

  it("maximized while the browser pans the visible area down, the panel follows it (top and bottom), keys hidden too", async () => {
    renderPhone();
    const { user } = await attach();
    const section = document.querySelector("[data-terminal-status]") as HTMLElement;
    keyboard.inset = 300;
    keyboard.top = 100;
    await user.click(screen.getByRole("button", { name: enTerminal.header.maximize }));
    expect(section.style.top).toBe("100px");
    expect(section.style.bottom).toBe("300px");
    expect(document.querySelector("[data-terminal-keys]")).toBeNull();
  });

  it("text size goes down to 1 px and no further, from ⋯ as from Utilities", async () => {
    useTerminalPreferences.setState({ fontSize: 2 });
    renderPhone();
    const { user, view } = await attach();
    expect(view.fontSize).toBe(2);
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.smaller }));
    await waitFor(() => expect(view.fontSize).toBe(1));
    expect(useTerminalPreferences.getState().fontSize).toBe(1);
    const smaller = screen.getByRole("menuitem", { name: enTerminal.utilities.smaller });
    expect(
      smaller.getAttribute("aria-disabled") ?? smaller.getAttribute("data-disabled"),
    ).not.toBeNull();
    expect(await screen.findByText("1 px · 100×30")).toBeTruthy();
  });

  it("a dialog opened from ⋯ while typing gives the terminal its focus back when cancelled, not ⋯", async () => {
    renderPhone();
    const { user, view } = await attach();
    const more = screen.getByRole("button", { name: enTerminal.header.more });
    view.hasFocusValue = true;
    await openMore(user);
    view.hasFocusValue = false;
    await user.click(screen.getByRole("menuitem", { name: enTerminal.utilities.paste }));
    await screen.findByRole("dialog");
    const before = view.focused;
    await user.click(screen.getByRole("button", { name: enTerminal.pasteDialog.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(view.focused).toBeGreaterThan(before));
    expect(document.activeElement).not.toBe(more);
  });

  it("a clipboard result is a toast on phones, not a status line", async () => {
    renderPhone();
    const { user, view } = await attach();
    view.selectionText = "";
    await openMore(user);
    await user.click(screen.getByRole("menuitem", { name: enTerminal.actions.copy }));
    await waitFor(() => expect(toastMessage).toHaveBeenCalledWith(enTerminal.clipboard.copyEmpty));
    expect(document.querySelector("[data-terminal-state]")?.textContent).not.toContain(
      enTerminal.clipboard.copyEmpty,
    );
  });
});

describe("crossing the phone breakpoint (rotation)", () => {
  it("an open Paste dialog and its draft survive the switch from the wide row to the phone header", async () => {
    let phone = false;
    const listeners = new Set<() => void>();
    vi.stubGlobal(
      "matchMedia",
      (query: string) =>
        ({
          get matches() {
            return query === "(max-width: 640px)" && phone;
          },
          media: query,
          addEventListener: (_: string, listener: () => void) => listeners.add(listener),
          removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
        }) as unknown as MediaQueryList,
    );
    renderTerminal();
    const { user, view } = await attach();
    await user.click(screen.getByRole("button", { name: enTerminal.utilities.button }));
    await user.click(await screen.findByRole("menuitem", { name: enTerminal.utilities.paste }));
    const textarea = (await screen.findByRole("dialog")).querySelector(
      "textarea",
    ) as HTMLTextAreaElement;
    await user.type(textarea, "draft");
    // Rotate to portrait.
    phone = true;
    act(() => {
      for (const listener of listeners) listener();
    });
    await waitFor(() => expect(document.querySelector("[data-terminal-header]")).not.toBeNull());
    const dialog = screen.getByRole("dialog");
    expect((dialog.querySelector("textarea") as HTMLTextAreaElement).value).toBe("draft");
    await user.click(screen.getByRole("button", { name: enTerminal.pasteDialog.send }));
    await waitFor(() => expect(view.pasted).toEqual(["draft"]));
  });
});

describe("wide layout (> 640 px)", () => {
  it("no Maximize in the actions row where the panel cannot be maximized", async () => {
    render(wrap(<TerminalPanel sandboxId="sbx_1" lang="en-US" available maximizable={false} />));
    await attach();
    expect(screen.getByRole("button", { name: enTerminal.actions.endSession })).toBeTruthy();
    expect(document.querySelector("[data-terminal-maximize]")).toBeNull();
  });

  it("an End session confirmation left open when the session ends by itself is gone, and stays gone on the next attach", async () => {
    renderTerminal();
    const { user, socket } = await attach();
    await user.click(screen.getByRole("button", { name: enTerminal.actions.endSession }));
    await screen.findByRole("alertdialog");
    act(() => socket.serverCloseIntent({ intent: "replaced" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    await user.click(screen.getByRole("button", { name: enTerminal.actions.reattach }));
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2));
    act(() => {
      FakeWebSocket.last().serverOpen();
      FakeWebSocket.last().serverText({ type: "ready", rows: 30, cols: 100 });
    });
    await screen.findByText("Attached (100 × 30).");
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("keeps the actions row; End session asks first and Maximize sits at its end", async () => {
    renderTerminal();
    const { user } = await attach();
    expect(document.querySelector("[data-terminal-header]")).toBeNull();
    const row = screen.getByRole("group", { name: enTerminal.actionsLabel });
    const labels = [...row.querySelectorAll("button")].map(
      (button) => button.textContent || button.getAttribute("aria-label"),
    );
    expect(labels).toEqual([
      enTerminal.actions.endSession,
      enTerminal.actions.copy,
      enTerminal.actions.paste,
      enTerminal.utilities.button,
      enTerminal.header.maximize,
    ]);
    await user.click(screen.getByRole("button", { name: enTerminal.actions.endSession }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
  });
});
