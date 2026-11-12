// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import en from "@wssp/locales/src/en-US/terminal.json";
import es from "@wssp/locales/src/es-MX/terminal.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FakeTerminalView, FakeWebSocket, flush } from "@/test/terminal-fakes";

const mint = vi.hoisted(() => vi.fn());
const raise = vi.hoisted(() => vi.fn());
const factor = vi.hoisted(() => ({ enabled: true }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: { status: "authenticated", session: { user: { twoFactorEnabled: factor.enabled } } },
  }),
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@/hooks/use-sensitive-access-unavailable", () => ({
  useSensitiveAccessUnavailable: () => false,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => () => false }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: React.ReactNode }) => (
    <a href="/en-US/settings/security">{children}</a>
  ),
}));
vi.mock("./hosts-page", () => ({ HostCard: () => null }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxHosts: { getHost: { key: () => ["host"] } },
    hostTerminals: {
      createSession: { call: mint },
      raiseHostTerminalTotp: { mutationOptions: () => ({ mutationFn: raise }) },
    },
  },
}));
vi.mock("@/lib/xterm-view", async () => {
  const { FakeTerminalView: View } = await import("@/test/terminal-fakes");
  return { createTerminalView: () => new View() };
});

import { HostTerminal } from "./host-detail-page";

beforeEach(() => {
  factor.enabled = true;
  mint.mockReset();
  raise.mockReset();
  FakeWebSocket.reset();
  FakeTerminalView.reset();
  vi.stubGlobal("WebSocket", FakeWebSocket);
});
it.each(["en-US", "es-MX"])(
  "%s shows enrollment as the blocker on an enabled host",
  async (lang) => {
    factor.enabled = false;
    const copy = lang === "en-US" ? en : es;
    await mount(true, lang);
    expect(screen.getByText(copy.host.enrollment)).toBeTruthy();
    expect(screen.queryByText(copy.host.unavailable)).toBeNull();
    expect(screen.getByRole("button", { name: copy.actions.attach }).hasAttribute("disabled")).toBe(
      true,
    );
    expect(mint).not.toHaveBeenCalled();
  },
);
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
async function mount(required = true, lang = "en-US", policy = true) {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    resources: { "en-US": { terminal: en }, "es-MX": { terminal: es } },
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <HostTerminal
          hostId="host-1"
          lang={lang}
          policy={
            policy
              ? { hostTerminal: true, requireHostTerminalTotp: required, policyRevision: 3 }
              : null
          }
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
it.each(["en-US", "es-MX"])(
  "%s requires explicit attach, clears proof on refusal, explains enrollment/cooldown and leaves no secret in caches",
  async (lang) => {
    const copy = lang === "en-US" ? en : es;
    const user = userEvent.setup();
    mint.mockRejectedValueOnce({ code: "FORBIDDEN", data: { reason: "cooldown" } });
    const { client } = await mount(true, lang);
    expect(mint).not.toHaveBeenCalled();
    expect(FakeTerminalView.instances).toHaveLength(0);
    expect(screen.getByRole("link", { name: copy.host.enroll })).toBeTruthy();
    const code = screen.getByLabelText(copy.host.code);
    expect(code.getAttribute("autocomplete")).toBe("one-time-code");
    await user.type(code, "654321");
    await user.click(screen.getByRole("button", { name: copy.actions.attach }));
    await screen.findByText(copy.host.cooldown);
    expect((screen.getByLabelText(copy.host.code) as HTMLInputElement).value).toBe("");
    expect(mint).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain("654321");
    expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain("654321");
    expect(document.body.textContent).not.toContain("654321");
  },
);
it("a refused host upgrade never classifies by minting another proof; manual retry needs a new code and ticket", async () => {
  const user = userEvent.setup();
  mint.mockResolvedValue({
    path: "/api/dashboard/hosts/host-1/terminal/ws",
    protocols: ["wssp.terminal.v1", "wssp.host-terminal.ticket.transient"],
  });
  const { client } = await mount();
  await user.type(screen.getByLabelText(en.host.code), "123456");
  await user.click(screen.getByRole("button", { name: en.actions.attach }));
  await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
  await act(async () => {
    FakeWebSocket.last().serverClose(1006);
    await flush();
  });
  expect(mint).toHaveBeenCalledTimes(1);
  expect(
    (screen.getByRole("button", { name: en.actions.reattach }) as HTMLButtonElement).disabled,
  ).toBe(true);
  await user.type(screen.getByLabelText(en.host.code), "234567");
  await user.click(screen.getByRole("button", { name: en.actions.reattach }));
  await waitFor(() => expect(mint).toHaveBeenCalledTimes(2));
  expect(mint.mock.calls[1]?.[0].code).toBe("234567");
  expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain("transient");
  expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain("transient");
});
it("optional mode attaches without a code and online raise stays unconfirmed until ACK; offline raise is unavailable", async () => {
  const user = userEvent.setup();
  mint.mockRejectedValue({ code: "FORBIDDEN" });
  let acknowledge: () => void = () => {};
  raise.mockImplementation(
    () =>
      new Promise<{ confirmed: boolean }>((resolve) => {
        acknowledge = () => resolve({ confirmed: true });
      }),
  );
  const view = await mount(false);
  expect(screen.queryByLabelText(en.host.code)).toBeNull();
  await user.click(screen.getByRole("button", { name: en.actions.attach }));
  await waitFor(() => expect(mint).toHaveBeenCalledTimes(1));
  expect(mint.mock.calls[0]?.[0]).not.toHaveProperty("code");
  await user.click(screen.getByRole("button", { name: en.host.raise }));
  await screen.findByText(en.host.unconfirmed);
  expect(screen.queryByText(en.host.confirmed)).toBeNull();
  await act(async () => acknowledge());
  await screen.findByText(en.host.confirmed);
  view.unmount();
  await mount(false, "en-US", false);
  expect(screen.queryByRole("button", { name: en.host.raise })).toBeNull();
});

it("a timeout response with confirmed false remains unconfirmed", async () => {
  raise.mockResolvedValue({ confirmed: false });
  const user = userEvent.setup();
  await mount(false);
  await user.click(screen.getByRole("button", { name: en.host.raise }));
  await screen.findByText(en.host.unconfirmed);
  expect(screen.queryByText(en.host.confirmed)).toBeNull();
});
