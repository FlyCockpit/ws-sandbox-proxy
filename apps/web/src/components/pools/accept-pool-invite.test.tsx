// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import en from "@wssp/locales/src/en-US/hosts.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";
import { capturePoolInviteFragment, clearPoolInviteToken } from "@/lib/pool-invite";

vi.mock("@/components/settings/settings-back-link", () => ({ SettingsBackLink: () => null }));
const accept = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: { status: "authenticated", session: { user: { email: "accepting@example.test" } } },
  }),
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    to,
    search,
  }: {
    children: ReactNode;
    to: string;
    search?: Record<string, string>;
  }) => <a href={`${to}${search ? `?${new URLSearchParams(search)}` : ""}`}>{children}</a>,
}));
vi.mock("@/utils/orpc", () => ({
  orpc: { sandboxPools: { key: () => ["pools"], acceptInvite: { call: accept } } },
}));

import { AcceptPoolInvite } from "./accept-pool-invite";

afterEach(() => {
  cleanup();
  clearPoolInviteToken();
  accept.mockReset();
});
it("shows accepting account and forwarding semantics before explicit mode-bound acceptance; token never enters cache or redirect", async () => {
  const token = `wssp_inv_${"v".repeat(43)}`;
  window.history.replaceState(null, "", `/en-US/settings/pools/invite#${token}`);
  capturePoolInviteFragment();
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en } } });
  const client = new QueryClient();
  const user = userEvent.setup();
  accept.mockResolvedValue({ shareId: "opaque-share" });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <AcceptPoolInvite lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  expect(accept).not.toHaveBeenCalled();
  expect(screen.getByText(/accepting@example.test/)).toBeTruthy();
  expect(screen.getByText(en.sharing.forwarding)).toBeTruthy();
  await user.click(screen.getByRole("radio", { name: en.sharing.bearer }));
  await user.click(screen.getByRole("button", { name: en.sharing.accept }));
  await waitFor(() => expect(accept).toHaveBeenCalledWith({ token, mode: "bearer" }));
  await screen.findByText(en.sharing.accepted);
  // Success leads on: the shared tab and the sandboxes list, and the
  // "open the link again" status (the secret is now cleared) is not shown.
  expect(screen.getByRole("link", { name: en.sharing.openShared }).getAttribute("href")).toBe(
    "/$lang/settings/pools?tab=shared",
  );
  expect(screen.getByRole("link", { name: en.sharing.goSandboxes })).toBeTruthy();
  expect(screen.queryByText(en.sharing.reopen)).toBeNull();
  expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain(token);
  expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain(token);
  expect(document.body.textContent).not.toContain(token);
  expect(window.location.href).not.toContain(token);
});

it.each([
  ["TOO_MANY_REQUESTS", en.sharing.acceptRateLimited],
  ["UNAUTHORIZED", en.sharing.acceptSignedOut],
  ["FORBIDDEN", en.sharing.acceptForbidden],
  ["NOT_FOUND", en.sharing.acceptUnavailable],
  ["CONFLICT", en.sharing.acceptConflict],
  ["INTERNAL_SERVER_ERROR", en.sharing.failed],
])("maps %s acceptance refusals without displaying server details", async (code, message) => {
  window.history.replaceState(null, "", `/en-US/settings/pools/invite#wssp_inv_${"v".repeat(43)}`);
  capturePoolInviteFragment();
  accept.mockRejectedValue({ code, message: "private server detail" });
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en } } });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <AcceptPoolInvite lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await userEvent.setup().click(screen.getByRole("button", { name: en.sharing.accept }));
  expect((await screen.findByRole("alert")).textContent).toBe(message);
});

it("without the link's secret, says to open the invitation link and cannot accept", async () => {
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en } } });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <AcceptPoolInvite lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  expect(screen.getByRole("status").textContent).toBe(en.sharing.reopen);
  expect(
    (screen.getByRole("button", { name: en.sharing.accept }) as HTMLButtonElement).disabled,
  ).toBe(true);
  // Each acceptance method explains itself.
  expect(screen.getByText(en.sharing.emailModeHint)).toBeTruthy();
  expect(screen.getByText(en.sharing.bearerHint)).toBeTruthy();
});
