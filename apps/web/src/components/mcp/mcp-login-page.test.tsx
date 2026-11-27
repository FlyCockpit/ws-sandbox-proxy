// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import en from "@wssp/locales/src/en-US/agents.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import es from "@wssp/locales/src/es-MX/agents.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const fake = vi.hoisted(() => ({
  authenticated: false,
  sessionError: false,
  refetch: vi.fn(),
  proceed: vi.fn(),
  signOut: vi.fn(),
  undo: vi.fn(),
  leave: vi.fn(),
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: { oauth2: { continue: fake.proceed }, signOut: fake.signOut },
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: {
      status: fake.sessionError ? "error" : fake.authenticated ? "authenticated" : "anonymous",
    },
    actions: { refetch: fake.refetch },
  }),
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ search, children }: { search: { redirectTo: string }; children: React.ReactNode }) => (
    <a href="/en-US/login" data-redirect={search.redirectTo}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib/document-identity", () => ({
  markExplicitSignOut: () => fake.undo,
  leaveDocument: fake.leave,
}));

import { McpLoginPage } from "./mcp-login-page";

afterEach(() => {
  cleanup();
  fake.authenticated = false;
  fake.sessionError = false;
  vi.clearAllMocks();
  window.history.replaceState(null, "", "/");
});
async function mount(
  lang = "en-US",
  search: Record<string, unknown> = { client_id: "client", scope: "sandboxes:read", sig: "signed" },
) {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    resources: {
      "en-US": { agents: en, common: enCommon },
      "es-MX": { agents: es, common: esCommon },
    },
  });
  const client = new QueryClient();
  client.setQueryData(["private"], "retained");
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <McpLoginPage lang={lang} search={search} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return client;
}
it.each([
  ["en-US", en, enCommon],
  ["es-MX", es, esCommon],
] as const)(
  "%s offers a session retry after a failed session check",
  async (lang, strings, common) => {
    fake.sessionError = true;
    await mount(lang);
    expect(screen.getByText(strings.login.sessionCheckFailed)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain(strings.login.sessionCheckFailed);
    expect(screen.queryByText(strings.consent.invalid)).toBeNull();
    const retry = screen.getByRole("button", { name: common.actions.tryAgain });
    expect(retry.className).toContain("min-h-[44px]");
    await userEvent.setup().click(retry);
    expect(fake.refetch).toHaveBeenCalledOnce();
    expect(fake.proceed).not.toHaveBeenCalled();
  },
);
it.each([
  ["en-US", en],
  ["es-MX", es],
] as const)(
  "%s retains invalid-request guidance for an unusable request",
  async (lang, strings) => {
    fake.sessionError = true;
    await mount(lang, { client_id: "client", scope: "sandboxes:read" });
    expect(screen.getByRole("alert").textContent).toBe(strings.consent.invalid);
    expect(screen.queryByText(strings.login.sessionCheckFailed)).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  },
);
it("keeps the signed raw query, including repeated ba_param values, across login", async () => {
  const raw =
    "?client_id=client&scope=sandboxes%3Aread&ba_param=client_id&ba_param=scope&sig=signed";
  window.history.replaceState(null, "", `/en-US/mcp-login${raw}`);
  await mount();
  expect(screen.getByRole("link", { name: en.login.signIn }).getAttribute("data-redirect")).toBe(
    `/en-US/mcp-login${raw}`,
  );
});
it("continues a signed-in person only after the explicit action", async () => {
  fake.authenticated = true;
  fake.proceed.mockResolvedValue({ error: { code: "invalid_signature" } });
  await mount();
  expect(fake.proceed).not.toHaveBeenCalled();
  await userEvent.setup().click(screen.getByRole("button", { name: en.login.continue }));
  expect(fake.proceed).toHaveBeenCalledWith({ postLogin: true });
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", en.consent.invalid);
});
it("offers fresh sign-in for revoked generations and retains private state when signout fails", async () => {
  fake.authenticated = true;
  fake.signOut.mockResolvedValue({ error: { code: "NETWORK_ERROR" } });
  const client = await mount();
  await userEvent.setup().click(screen.getByRole("button", { name: en.login.reauthenticate }));
  expect(fake.signOut).toHaveBeenCalledWith({ disableRedirect: true });
  expect(await screen.findByText(en.login.reauthFailed)).toBeTruthy();
  expect(fake.undo).toHaveBeenCalledOnce();
  expect(fake.leave).not.toHaveBeenCalled();
  expect(client.getQueryData(["private"])).toBe("retained");
});
it("re-authentication full-loads login through the quarantine, keeping the signed transaction", async () => {
  fake.authenticated = true;
  const raw = "?client_id=client&scope=sandboxes%3Aread&sig=signed";
  window.history.replaceState(null, "", `/en-US/mcp-login${raw}`);
  fake.signOut.mockResolvedValue({ data: { success: true }, error: null });
  await mount();
  await userEvent.setup().click(screen.getByRole("button", { name: en.login.reauthenticate }));
  await vi.waitFor(() =>
    expect(fake.leave).toHaveBeenCalledExactlyOnceWith(
      `/en-US/login?redirectTo=${encodeURIComponent(`/en-US/mcp-login${raw}`)}`,
    ),
  );
  expect(fake.undo).not.toHaveBeenCalled();
});
